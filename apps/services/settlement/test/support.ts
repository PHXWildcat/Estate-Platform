import { randomUUID } from 'node:crypto';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { SettlementAuthz } from '../src/authz.service';
import type { CaseRow, CaseStatus, EvidenceEntry } from '../src/cases.repo';
import type { SettlementConfig } from '../src/config';
import type { ContactAttemptsRepo, ContactChannel } from '../src/contact-attempts.repo';
import type { CoreReadsRepo, ReportableEstate } from '../src/core-reads.repo';
import type { Db, Queryable } from '../src/db';
import { EventsService } from '../src/events.service';
import {
  IdentityLockError,
  OwnerAliveError,
  type IdentityLockPort,
  type LockState,
} from '../src/identity-lock';
import { StubNotifier } from '../src/notifications';
import type { OperatorsRepo } from '../src/operators.repo';
import { SettlementService } from '../src/settlement.service';

export const NOW = new Date('2026-07-27T12:00:00Z');

/** Mutable clock: tests advance time by assigning holder.value. */
export interface ClockHolder {
  value: Date;
}

const TERMINAL: readonly CaseStatus[] = ['closed', 'rejected_fraud'];

function uniqueViolation(): Error {
  return Object.assign(new Error('duplicate key'), { code: '23505' });
}

/** The repos are in-memory, so transactions are pass-through; any attempt to
 * run real SQL in a unit test fails loudly. */
export function fakeDb(): Db {
  const failingQuery = (): never => {
    throw new Error('unit tests use in-memory repos, not SQL');
  };
  const tx: Queryable = { query: failingQuery };
  return {
    query: failingQuery,
    withTransaction: <T>(_actor: string, fn: (t: Queryable) => Promise<T>): Promise<T> => fn(tx),
    onModuleDestroy: () => Promise.resolve(),
  } as unknown as Db;
}

export class InMemoryCases {
  readonly rows = new Map<string, CaseRow>();

  constructor(private readonly clock: () => Date) {}

  insert(
    _tx: Queryable,
    input: {
      decedentUserId: string;
      reportedBy: string;
      source: 'trusted_contact' | 'data_provider' | 'death_certificate_upload';
      evidence: EvidenceEntry[];
    },
  ): Promise<CaseRow> {
    for (const row of this.rows.values()) {
      if (row.decedent_user_id === input.decedentUserId && !TERMINAL.includes(row.status)) {
        throw uniqueViolation();
      }
    }
    const now = this.clock();
    const row: CaseRow = {
      id: randomUUID(),
      decedent_user_id: input.decedentUserId,
      status: 'reported',
      reported_by: input.reportedBy,
      report_source: input.source,
      verification_evidence: [...input.evidence],
      human_review_by: null,
      human_review_at: null,
      waiting_period_ends: null,
      verified_at: null,
      resolution: null,
      resolved_at: null,
      created_at: now,
      updated_at: now,
    };
    this.rows.set(row.id, row);
    return Promise.resolve(row);
  }

  findById(_q: unknown, caseId: string): Promise<CaseRow | null> {
    return Promise.resolve(this.rows.get(caseId) ?? null);
  }

  lockById(_tx: unknown, caseId: string): Promise<CaseRow | null> {
    return Promise.resolve(this.rows.get(caseId) ?? null);
  }

  listForUser(_q: unknown, userId: string): Promise<CaseRow[]> {
    return Promise.resolve(
      [...this.rows.values()].filter(
        (r) => r.decedent_user_id === userId || r.reported_by === userId,
      ),
    );
  }

  listOpenForReview(): Promise<CaseRow[]> {
    return Promise.resolve(
      [...this.rows.values()].filter((r) =>
        ['reported', 'verifying', 'waiting_period'].includes(r.status),
      ),
    );
  }

  listWaitingPeriod(): Promise<CaseRow[]> {
    return Promise.resolve([...this.rows.values()].filter((r) => r.status === 'waiting_period'));
  }

  findNonTerminalByDecedent(_q: unknown, decedentUserId: string): Promise<CaseRow | null> {
    return Promise.resolve(
      [...this.rows.values()].find(
        (r) => r.decedent_user_id === decedentUserId && !TERMINAL.includes(r.status),
      ) ?? null,
    );
  }

  findByDocumentEvidence(
    _q: unknown,
    documentId: string,
    version: number,
  ): Promise<CaseRow | null> {
    return Promise.resolve(
      [...this.rows.values()].find((r) =>
        r.verification_evidence.some(
          (e) => e.type === 'document' && e.documentId === documentId && e.version === version,
        ),
      ) ?? null,
    );
  }

  appendEvidence(_tx: unknown, caseId: string, entry: EvidenceEntry): Promise<void> {
    const row = this.rows.get(caseId);
    if (row) {
      row.verification_evidence.push(entry);
      row.updated_at = this.clock();
    }
    return Promise.resolve();
  }

  markReviewStarted(_tx: unknown, caseId: string): Promise<boolean> {
    const row = this.rows.get(caseId);
    if (!row || row.status !== 'reported') {
      return Promise.resolve(false);
    }
    row.status = 'verifying';
    row.updated_at = this.clock();
    return Promise.resolve(true);
  }

  markApproved(
    _tx: unknown,
    caseId: string,
    reviewerId: string,
    reviewedAt: Date,
    waitingPeriodEnds: Date,
  ): Promise<boolean> {
    const row = this.rows.get(caseId);
    if (!row || row.status !== 'verifying') {
      return Promise.resolve(false);
    }
    row.status = 'waiting_period';
    row.human_review_by = reviewerId;
    row.human_review_at = reviewedAt;
    row.waiting_period_ends = waitingPeriodEnds;
    row.updated_at = this.clock();
    return Promise.resolve(true);
  }

  markResolved(
    _tx: unknown,
    caseId: string,
    fromStatuses: readonly CaseStatus[],
    resolution: 'operator_rejected' | 'owner_voided',
    resolvedAt: Date,
    reviewer: { id: string; at: Date } | null,
  ): Promise<boolean> {
    const row = this.rows.get(caseId);
    if (!row || !fromStatuses.includes(row.status)) {
      return Promise.resolve(false);
    }
    row.status = 'rejected_fraud';
    row.resolution = resolution;
    row.resolved_at = resolvedAt;
    if (reviewer) {
      row.human_review_by = reviewer.id;
      row.human_review_at = reviewer.at;
    }
    row.waiting_period_ends = null;
    row.verified_at = null;
    row.updated_at = this.clock();
    return Promise.resolve(true);
  }

  markVerified(_tx: unknown, caseId: string, verifiedAt: Date): Promise<boolean> {
    const row = this.rows.get(caseId);
    if (!row || row.status !== 'waiting_period') {
      return Promise.resolve(false);
    }
    row.status = 'verified';
    row.verified_at = verifiedAt;
    row.updated_at = this.clock();
    return Promise.resolve(true);
  }
}

export class InMemoryAttempts {
  readonly rows: Array<{
    case_id: string;
    seq: number;
    channel: ContactChannel;
    attempted_at: Date;
  }> = [];

  insert(
    _tx: unknown,
    input: { caseId: string; seq: number; channel: ContactChannel; attemptedAt: Date },
  ): Promise<boolean> {
    if (this.rows.some((r) => r.case_id === input.caseId && r.seq === input.seq)) {
      return Promise.resolve(false);
    }
    this.rows.push({
      case_id: input.caseId,
      seq: input.seq,
      channel: input.channel,
      attempted_at: input.attemptedAt,
    });
    return Promise.resolve(true);
  }

  maxSeq(_q2: unknown, caseId: string): Promise<number | null> {
    const seqs = this.rows.filter((r) => r.case_id === caseId).map((r) => r.seq);
    return Promise.resolve(seqs.length > 0 ? Math.max(...seqs) : null);
  }

  listByCase(_q2: unknown, caseId: string): Promise<unknown[]> {
    return Promise.resolve(this.rows.filter((r) => r.case_id === caseId));
  }
}

export class InMemoryOperators {
  readonly active = new Set<string>();

  isOperator(_q2: unknown, userId: string): Promise<boolean> {
    return Promise.resolve(this.active.has(userId));
  }
}

export class InMemorySettings {
  readonly days = new Map<string, number>();

  waitingPeriodDays(_q2: unknown, userId: string): Promise<number> {
    return Promise.resolve(this.days.get(userId) ?? 5);
  }

  upsert(_tx: unknown, userId: string, waitingPeriodDays: number): Promise<void> {
    this.days.set(userId, waitingPeriodDays);
    return Promise.resolve();
  }
}

export class FakeCoreReads {
  /** decedent -> linked platform user ids */
  readonly links = new Map<string, Set<string>>();

  link(decedentUserId: string, userId: string): void {
    const set = this.links.get(decedentUserId) ?? new Set<string>();
    set.add(userId);
    this.links.set(decedentUserId, set);
  }

  isLinkedContact(decedentUserId: string, userId: string): Promise<boolean> {
    return Promise.resolve(this.links.get(decedentUserId)?.has(userId) ?? false);
  }

  reportableEstates(userId: string): Promise<ReportableEstate[]> {
    const estates: ReportableEstate[] = [];
    for (const [decedent, users] of this.links) {
      if (users.has(userId)) {
        estates.push({ decedentUserId: decedent, contactId: randomUUID(), roles: [] });
      }
    }
    return Promise.resolve(estates);
  }
}

export class FakeIdentityLock implements IdentityLockPort {
  readonly setStateCalls: Array<{
    userId: string;
    state: LockState;
    caseId: string;
    livenessNotAfter?: Date;
  }> = [];
  failSetState = false;
  failLiveness = false;
  /** Simulates a step-up landing AFTER settlement's liveness read: the
   * watermarked transition is refused the way identity's atomic interlock
   * refuses it. */
  raceStepUpAt: Date | null = null;
  livenessAnswer: { status: string; lastStepUpAt: Date | null } = {
    status: 'deceased_pending',
    lastStepUpAt: null,
  };

  setState(
    userId: string,
    state: LockState,
    caseId: string,
    livenessNotAfter?: Date,
  ): Promise<void> {
    if (this.failSetState) {
      return Promise.reject(new IdentityLockError());
    }
    if (
      livenessNotAfter &&
      this.raceStepUpAt &&
      this.raceStepUpAt.getTime() > livenessNotAfter.getTime()
    ) {
      return Promise.reject(new OwnerAliveError());
    }
    this.setStateCalls.push({
      userId,
      state,
      caseId,
      ...(livenessNotAfter ? { livenessNotAfter } : {}),
    });
    return Promise.resolve();
  }

  liveness(): Promise<{ status: string; lastStepUpAt: Date | null }> {
    if (this.failLiveness) {
      return Promise.reject(new IdentityLockError());
    }
    return Promise.resolve(this.livenessAnswer);
  }
}

export function testConfig(over: Partial<SettlementConfig> = {}): SettlementConfig {
  return {
    nodeEnv: 'test',
    port: 3007,
    databaseUrl: 'postgres://unused',
    kafkaBrokers: null,
    identityUrl: 'http://identity.internal',
    settlementInternalToken: 's'.repeat(32),
    notify: { mode: 'stub' },
    driverIntervalMs: 60_000,
    ...over,
  };
}

export interface Harness {
  service: SettlementService;
  cases: InMemoryCases;
  attempts: InMemoryAttempts;
  operators: InMemoryOperators;
  settings: InMemorySettings;
  coreReads: FakeCoreReads;
  identity: FakeIdentityLock;
  notifier: StubNotifier;
  producer: InMemoryAuditProducer;
  clock: ClockHolder;
}

export function buildHarness(over: { config?: Partial<SettlementConfig> } = {}): Harness {
  const clock: ClockHolder = { value: NOW };
  const clockFn = (): Date => clock.value;
  const cases = new InMemoryCases(clockFn);
  const attempts = new InMemoryAttempts();
  const operators = new InMemoryOperators();
  const settings = new InMemorySettings();
  const coreReads = new FakeCoreReads();
  const identity = new FakeIdentityLock();
  const notifier = new StubNotifier();
  const producer = new InMemoryAuditProducer();
  const events = new EventsService(producer, clockFn);
  const authz = new SettlementAuthz(new PolicyDecisionPoint(loadBundledPolicies()));
  const service = new SettlementService(
    fakeDb(),
    cases,
    attempts as unknown as ContactAttemptsRepo,
    operators as unknown as OperatorsRepo,
    settings,
    coreReads as unknown as CoreReadsRepo,
    authz,
    events,
    notifier,
    identity,
    testConfig(over.config),
    clockFn,
  );
  return {
    service,
    cases,
    attempts,
    operators,
    settings,
    coreReads,
    identity,
    notifier,
    producer,
    clock,
  };
}

/** Parsed audit actions captured so far. */
export function auditActions(producer: InMemoryAuditProducer): string[] {
  return producer.messages.map((m) => (JSON.parse(m.value) as { action: string }).action);
}

export function auditEvents(producer: InMemoryAuditProducer): Array<Record<string, unknown>> {
  return producer.messages.map((m) => JSON.parse(m.value) as Record<string, unknown>);
}
