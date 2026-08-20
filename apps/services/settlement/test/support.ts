import { randomUUID } from 'node:crypto';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import type { FieldCrypto } from '@estate/crypto';
import { SettlementAdminService } from '../src/admin.service';
import { InMemoryAuditProducer } from '@estate/kafka';
import type { DistributionRow } from '../src/distributions.repo';
import type { AccessStage, StageRow } from '../src/stages.repo';
import { SettlementAuthz } from '../src/authz.service';
import {
  ADMINISTRABLE_STATUSES,
  QUEUE_STATUSES,
  type CaseRow,
  type CaseStatus,
  type EvidenceEntry,
} from '../src/cases.repo';
import type { SettlementConfig } from '../src/config';
import type { ContactAttemptsRepo, ContactChannel } from '../src/contact-attempts.repo';
import type { CoreReadsRepo, ReportableEstate } from '../src/core-reads.repo';
import type { Db, Queryable } from '../src/db';
import { EventsService } from '../src/events.service';
import { DocumentsHoldError, type DocumentsHoldPort } from '../src/documents-hold';
import {
  IdentityLockError,
  OwnerAliveError,
  type IdentityLockPort,
  type LockState,
} from '../src/identity-lock';
import { StubNotifier } from '../src/notifications';
import { OperatorBreadthMonitor } from '../src/operator-breadth.monitor';
import { breadthExceeded } from '../src/operator-breadth';
import { OperatorGate } from '../src/operator-gate';
import type { OperatorsRepo } from '../src/operators.repo';
import type { TasksRepo } from '../src/tasks.repo';
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
      claimed_by: null,
      claimed_at: null,
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

  // Both worklists filter on the REAL status sets rather than a list retyped
  // here: a fixture that invents an enum tests the fixture (M15 PR3).
  listOpenForReview(): Promise<CaseRow[]> {
    return Promise.resolve(
      [...this.rows.values()].filter((r) => QUEUE_STATUSES.includes(r.status)),
    );
  }

  listAdministrable(): Promise<CaseRow[]> {
    return Promise.resolve(
      [...this.rows.values()].filter((r) => ADMINISTRABLE_STATUSES.includes(r.status)),
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

  markReviewStarted(
    _tx: unknown,
    caseId: string,
    claimedBy: string,
    claimedAt: Date,
  ): Promise<boolean> {
    const row = this.rows.get(caseId);
    if (!row || row.status !== 'reported') {
      return Promise.resolve(false);
    }
    row.status = 'verifying';
    row.claimed_by = claimedBy;
    row.claimed_at = claimedAt;
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

  advanceStatus(
    _tx: unknown,
    caseId: string,
    from: readonly CaseStatus[],
    to: CaseStatus,
  ): Promise<boolean> {
    const row = this.rows.get(caseId);
    if (!row || !from.includes(row.status)) {
      return Promise.resolve(false);
    }
    row.status = to;
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

  /**
   * RECORDS THE HANDLE, because discarding it made a security property
   * unobservable. `OperatorGate`'s whole contract is that a caller which owns a
   * transaction asks inside it; the first version of this double named the
   * parameter `_q2` and threw it away, so NO behavioural test — unit or
   * Postgres-backed — could tell `assertIn(tx, u)` from `assertIn(this.db, u)`,
   * and the source fence was the only thing in the repository that could. A
   * double more permissive than the real thing is this repo's recurring shape
   * one layer beneath the fixtures.
   */
  readonly asked: Array<{ handle: unknown; userId: string }> = [];

  isOperator(handle: unknown, userId: string): Promise<boolean> {
    this.asked.push({ handle, userId });
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

export class InMemoryTasks {
  readonly rows: Array<{
    id: string;
    case_id: string;
    title: string;
    category: string | null;
    assigned_role: string | null;
    due_at: Date | null;
    completed_at: Date | null;
    completed_by: string | null;
    court_doc_version_id: string | null;
    created_at: Date;
    updated_at: Date;
  }> = [];

  insertMany(
    _tx: unknown,
    caseId: string,
    tasks: ReadonlyArray<{
      title: string;
      category?: string | null;
      assignedRole?: string | null;
      dueAt?: Date | null;
    }>,
  ): Promise<number> {
    for (const t of tasks) {
      this.rows.push({
        id: randomUUID(),
        case_id: caseId,
        title: t.title,
        category: t.category ?? null,
        assigned_role: t.assignedRole ?? null,
        due_at: t.dueAt ?? null,
        completed_at: null,
        completed_by: null,
        court_doc_version_id: null,
        created_at: NOW,
        updated_at: NOW,
      });
    }
    return Promise.resolve(tasks.length);
  }

  listByCase(_q: unknown, caseId: string): Promise<unknown[]> {
    return Promise.resolve(this.rows.filter((r) => r.case_id === caseId));
  }

  lockById(_tx: unknown, taskId: string): Promise<unknown> {
    return Promise.resolve(this.rows.find((r) => r.id === taskId) ?? null);
  }

  setCompletion(
    _tx: unknown,
    taskId: string,
    completion: { at: Date; by: string } | null,
    courtDocVersionId: string | null,
  ): Promise<boolean> {
    const row = this.rows.find((r) => r.id === taskId);
    if (!row) {
      return Promise.resolve(false);
    }
    row.completed_at = completion?.at ?? null;
    row.completed_by = completion?.by ?? null;
    row.court_doc_version_id = courtDocVersionId ?? row.court_doc_version_id;
    return Promise.resolve(true);
  }
}

export class FakeCoreReads {
  /** decedent -> linked platform user ids */
  readonly links = new Map<string, Set<string>>();
  /** `${decedent}:${user}` pairs designated executor on_death_verified. */
  readonly executors = new Set<string>();

  link(decedentUserId: string, userId: string): void {
    const set = this.links.get(decedentUserId) ?? new Set<string>();
    set.add(userId);
    this.links.set(decedentUserId, set);
  }

  isLinkedContact(decedentUserId: string, userId: string): Promise<boolean> {
    return Promise.resolve(this.links.get(decedentUserId)?.has(userId) ?? false);
  }

  isExecutorOf(decedentUserId: string, userId: string): Promise<boolean> {
    return Promise.resolve(this.executors.has(`${decedentUserId}:${userId}`));
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

/** M9 PR2: the legal-hold side effect, recorded per call for assertions. */
export class FakeDocumentsHold implements DocumentsHoldPort {
  readonly setHoldCalls: Array<{ ownerUserId: string; hold: boolean; caseId: string }> = [];
  failSetHold = false;

  setHold(ownerUserId: string, hold: boolean, caseId: string): Promise<void> {
    if (this.failSetHold) {
      return Promise.reject(new DocumentsHoldError());
    }
    this.setHoldCalls.push({ ownerUserId, hold, caseId });
    return Promise.resolve();
  }
}

export function testConfig(over: Partial<SettlementConfig> = {}): SettlementConfig {
  return {
    nodeEnv: 'test',
    port: 3007,
    databaseUrl: 'postgres://unused',
    kafkaBrokers: null,
    identityUrl: 'http://identity.internal',
    internalApiToken: 's'.repeat(32),
    identityInternalToken: 'i'.repeat(32),
    notify: { mode: 'stub' },
    notificationsUrl: 'http://localhost:3008',
    notificationsInternalToken: '',
    documentsUrl: 'http://documents.internal',
    documentsInternalToken: 'd'.repeat(32),
    driverIntervalMs: 60_000,
    kms: { mode: 'local', masterKey: Buffer.alloc(32, 7) },
    kekAlias: 'settlement/kek',
    ...over,
  };
}

export interface Harness {
  service: SettlementService;
  /** The same Db the service was built with, so a test can ask WHICH handle a
   *  gate read was made on — `fakeDb()`'s transaction handle is a distinct
   *  object, which is what makes the question answerable at all. */
  db: Db;
  cases: InMemoryCases;
  attempts: InMemoryAttempts;
  operators: InMemoryOperators;
  settings: InMemorySettings;
  coreReads: FakeCoreReads;
  identity: FakeIdentityLock;
  documentsHold: FakeDocumentsHold;
  notifier: StubNotifier;
  producer: InMemoryAuditProducer;
  clock: ClockHolder;
}

export function buildHarness(over: { config?: Partial<SettlementConfig> } = {}): Harness {
  const clock: ClockHolder = { value: NOW };
  const clockFn = (): Date => clock.value;
  const db = fakeDb();
  const cases = new InMemoryCases(clockFn);
  const attempts = new InMemoryAttempts();
  const operators = new InMemoryOperators();
  const settings = new InMemorySettings();
  const tasks = new InMemoryTasks();
  const coreReads = new FakeCoreReads();
  const identity = new FakeIdentityLock();
  const documentsHold = new FakeDocumentsHold();
  const notifier = new StubNotifier();
  const producer = new InMemoryAuditProducer();
  const events = new EventsService(producer, clockFn);
  const authz = new SettlementAuthz(new PolicyDecisionPoint(loadBundledPolicies()));
  const service = new SettlementService(
    db,
    cases,
    attempts as unknown as ContactAttemptsRepo,
    new OperatorGate(operators as unknown as OperatorsRepo),
    breadthMonitor(),
    settings,
    tasks as unknown as TasksRepo,
    coreReads as unknown as CoreReadsRepo,
    authz,
    events,
    notifier,
    identity,
    documentsHold,
    testConfig(over.config),
    clockFn,
  );
  return {
    service,
    db,
    cases,
    attempts,
    operators,
    settings,
    coreReads,
    identity,
    documentsHold,
    notifier,
    producer,
    clock,
  };
}

// ------------------------------------------------------------- PR2 harness

export class InMemoryStages {
  readonly rows: StageRow[] = [];

  constructor(private readonly clock: () => Date) {}

  insertRequest(
    _tx: unknown,
    input: { caseId: string; stage: AccessStage; requestedBy: string; requestedAt: Date },
  ): Promise<StageRow> {
    const row: StageRow = {
      id: randomUUID(),
      case_id: input.caseId,
      stage: input.stage,
      status: 'requested',
      requested_by: input.requestedBy,
      requested_at: input.requestedAt,
      decided_by: null,
      decided_at: null,
      created_at: this.clock(),
      updated_at: this.clock(),
    };
    this.rows.push(row);
    return Promise.resolve(row);
  }

  listByCase(_q: unknown, caseId: string): Promise<StageRow[]> {
    return Promise.resolve(this.rows.filter((r) => r.case_id === caseId));
  }

  lockById(_tx: unknown, stageId: string): Promise<StageRow | null> {
    return Promise.resolve(this.rows.find((r) => r.id === stageId) ?? null);
  }

  findLive(_q: unknown, caseId: string, stage: AccessStage): Promise<StageRow | null> {
    return Promise.resolve(
      this.rows.find(
        (r) =>
          r.case_id === caseId &&
          r.stage === stage &&
          (r.status === 'requested' || r.status === 'approved'),
      ) ?? null,
    );
  }

  isApproved(_q: unknown, caseId: string, stage: AccessStage): Promise<boolean> {
    return Promise.resolve(
      this.rows.some((r) => r.case_id === caseId && r.stage === stage && r.status === 'approved'),
    );
  }

  decide(
    _tx: unknown,
    stageId: string,
    status: 'approved' | 'denied',
    decidedBy: string,
    decidedAt: Date,
  ): Promise<boolean> {
    const row = this.rows.find((r) => r.id === stageId);
    if (!row || row.status !== 'requested') {
      return Promise.resolve(false);
    }
    // The DDL CHECK, restated: the fake must not permit what Postgres forbids.
    if (decidedBy === row.requested_by) {
      return Promise.reject(Object.assign(new Error('check violation'), { code: '23514' }));
    }
    row.status = status;
    row.decided_by = decidedBy;
    row.decided_at = decidedAt;
    return Promise.resolve(true);
  }

  revoke(_tx: unknown, stageId: string, revokedBy: string, at: Date): Promise<boolean> {
    const row = this.rows.find((r) => r.id === stageId);
    if (!row || !['requested', 'approved'].includes(row.status)) {
      return Promise.resolve(false);
    }
    // Revocation writes decided_by, so it lands under the SAME CHECK as
    // approval. The fake used to omit this and permit what Postgres forbids,
    // which is how the unhandled 23514 in revokeStage stayed invisible.
    if (revokedBy === row.requested_by) {
      return Promise.reject(Object.assign(new Error('check violation'), { code: '23514' }));
    }
    row.status = 'revoked';
    row.decided_by = revokedBy;
    row.decided_at = at;
    return Promise.resolve(true);
  }
}

export class InMemoryDistributions {
  readonly rows: DistributionRow[] = [];

  constructor(private readonly clock: () => Date) {}

  insert(
    _tx: unknown,
    input: {
      caseId: string;
      assetId: string | null;
      beneficiaryContactId: string;
      amountCt: Buffer | null;
      dekId: string | null;
      createdBy: string;
    },
  ): Promise<DistributionRow> {
    const row: DistributionRow = {
      id: randomUUID(),
      case_id: input.caseId,
      asset_id: input.assetId,
      beneficiary_contact_id: input.beneficiaryContactId,
      amount_ct: input.amountCt,
      dek_id: input.dekId,
      status: 'planned',
      created_by: input.createdBy,
      approved_by: null,
      approved_at: null,
      created_at: this.clock(),
      updated_at: this.clock(),
    };
    this.rows.push(row);
    return Promise.resolve(row);
  }

  listByCase(_q: unknown, caseId: string): Promise<DistributionRow[]> {
    return Promise.resolve(this.rows.filter((r) => r.case_id === caseId));
  }

  lockById(_tx: unknown, id: string): Promise<DistributionRow | null> {
    return Promise.resolve(this.rows.find((r) => r.id === id) ?? null);
  }

  approve(_tx: unknown, id: string, approvedBy: string, approvedAt: Date): Promise<boolean> {
    const row = this.rows.find((r) => r.id === id);
    if (!row || row.status !== 'planned') {
      return Promise.resolve(false);
    }
    // The dual-control DDL CHECK, restated.
    if (approvedBy === row.created_by) {
      return Promise.reject(Object.assign(new Error('check violation'), { code: '23514' }));
    }
    row.status = 'approved';
    row.approved_by = approvedBy;
    row.approved_at = approvedAt;
    return Promise.resolve(true);
  }

  setStatus(
    _tx: unknown,
    id: string,
    from: readonly string[],
    to: DistributionRow['status'],
  ): Promise<boolean> {
    const row = this.rows.find((r) => r.id === id);
    if (!row || !from.includes(row.status)) {
      return Promise.resolve(false);
    }
    row.status = to;
    return Promise.resolve(true);
  }

  countOpen(_q: unknown, caseId: string): Promise<number> {
    return Promise.resolve(
      this.rows.filter((r) => r.case_id === caseId && !['completed', 'disputed'].includes(r.status))
        .length,
    );
  }
}

/** A FieldCrypto stand-in: records what was sealed, returns a marker buffer. */
export class FakeFieldCrypto {
  readonly sealed: Array<{ userId: string; field: string; plaintext: string }> = [];

  encryptField(
    userId: string,
    field: string,
    plaintext: string,
  ): Promise<{ ciphertext: Buffer; dekId: string }> {
    this.sealed.push({ userId, field, plaintext });
    return Promise.resolve({ ciphertext: Buffer.from(`sealed:${field}`), dekId: randomUUID() });
  }
}

export interface AdminHarness {
  admin: SettlementAdminService;
  cases: InMemoryCases;
  stages: InMemoryStages;
  tasks: InMemoryTasks;
  distributions: InMemoryDistributions;
  operators: InMemoryOperators;
  coreReads: FakeCoreReads;
  crypto: FakeFieldCrypto;
  producer: InMemoryAuditProducer;
  clock: ClockHolder;
}

export function buildAdminHarness(monitor?: OperatorBreadthMonitor): AdminHarness {
  const clock: ClockHolder = { value: NOW };
  const clockFn = (): Date => clock.value;
  const cases = new InMemoryCases(clockFn);
  const stages = new InMemoryStages(clockFn);
  const tasks = new InMemoryTasks();
  const distributions = new InMemoryDistributions(clockFn);
  const operators = new InMemoryOperators();
  const coreReads = new FakeCoreReads();
  const crypto = new FakeFieldCrypto();
  const producer = new InMemoryAuditProducer();
  const events = new EventsService(producer, clockFn);
  const admin = new SettlementAdminService(
    fakeDb(),
    cases,
    stages,
    tasks as unknown as TasksRepo,
    distributions,
    new OperatorGate(operators as unknown as OperatorsRepo),
    monitor ?? breadthMonitor(),
    coreReads as unknown as CoreReadsRepo,
    events,
    crypto as unknown as FieldCrypto,
    clockFn,
  );
  return {
    admin,
    cases,
    stages,
    tasks,
    distributions,
    operators,
    coreReads,
    crypto,
    producer,
    clock,
  };
}

/** Force a case into a post-verification status for administration tests. */
export function markCaseVerified(cases: InMemoryCases, caseId: string, at: Date): void {
  const row = cases.rows.get(caseId);
  if (row) {
    row.status = 'verified';
    row.verified_at = at;
    row.human_review_by = randomUUID();
    row.human_review_at = at;
  }
}

/** Parsed audit actions captured so far. */
export function auditActions(producer: InMemoryAuditProducer): string[] {
  return producer.messages.map((m) => (JSON.parse(m.value) as { action: string }).action);
}

export function auditEvents(producer: InMemoryAuditProducer): Array<Record<string, unknown>> {
  return producer.messages.map((m) => JSON.parse(m.value) as Record<string, unknown>);
}

/**
 * An in-memory breadth monitor for the unit harnesses.
 *
 * The double is FAITHFUL ABOUT WHAT IT REFUSES, not only about values: it keeps
 * a real per-operator set of case ids so `record` returns a real distinct
 * count, because a stub that always answered 0 would make every breadth
 * assertion in this package pass by construction. `operator-breadth.int.spec.ts`
 * runs the same logic against Postgres, which is where the SQL is proven.
 */
export function breadthMonitor(): OperatorBreadthMonitor {
  const seen = new Map<string, Set<string>>();
  return {
    record(_tx: unknown, operator: string, caseId: string): Promise<number> {
      const cases = seen.get(operator) ?? new Set<string>();
      cases.add(caseId);
      seen.set(operator, cases);
      return Promise.resolve(cases.size);
    },
    exceeded: (n: number) => breadthExceeded(n),
  } as unknown as OperatorBreadthMonitor;
}
