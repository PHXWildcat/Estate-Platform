import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import { AUDIT_ACTIONS } from '@estate/contracts';

import type { CaseStatus } from '../src/cases.repo';
import {
  CASE_ADVANCE_ACTIONS,
  DISTRIBUTION_STATUS_ACTIONS,
  type CaseStatusAdvanceTarget,
  type DistributionStatusTarget,
} from '../src/events.service';
import {
  auditEvents,
  buildAdminHarness,
  markCaseVerified,
  NOW,
  type AdminHarness,
} from './support';

const DECEDENT = randomUUID();
const EXECUTOR = randomUUID();
const OPERATOR = randomUUID();
const REPORTER = randomUUID();
const SESSION = randomUUID();

/** A verified case with an executor designated, ready for administration. */
async function verifiedCaseFor(h: AdminHarness): Promise<string> {
  const row = await h.cases.insert(undefined as never, {
    decedentUserId: DECEDENT,
    reportedBy: REPORTER,
    source: 'trusted_contact',
    evidence: [],
  });
  markCaseVerified(h.cases, row.id, NOW);
  h.coreReads.link(DECEDENT, REPORTER);
  h.coreReads.link(DECEDENT, EXECUTOR);
  h.coreReads.executors.add(`${DECEDENT}:${EXECUTOR}`);
  h.operators.active.add(OPERATOR);
  return row.id;
}

/**
 * A STATE MACHINE MUST NOT AUDIT FEWER TRANSITIONS THAN IT PERMITS (M49 PR1).
 *
 * The defect this fence exists for: `setDistributionStatus` accepted three
 * targets and emitted on exactly one, `if (to === 'completed')`. Nothing in the
 * repo related a transition's TARGET SET to its EMITTED ACTION SET. Two fences
 * come close and neither joins the halves: `settlement-distributions.spec.ts`
 * in the BFF reads this same DDL and asserts the SDL enum accounts for its
 * whole vocabulary — the STATUS side alone — and the `CaseReadSurface` fence
 * derives gated readers from source, which is the ACTION side for reads rather
 * than for transitions. So the gap was invisible for as long as nobody read the
 * method.
 *
 * WHAT IT IS ANCHORED ON, and why each alternative would go green while wrong:
 *
 *   - THE DDL CHECK, not `DistributionStatus`/`CaseStatus`. The database is
 *     what the runtime reads; a TypeScript type is a rename away from
 *     desynchronising, which the BFF's twin fence says in its own words.
 *   - THE MAPS, not the action-name prefix. `/^settlement\.distribution\./`
 *     would sweep in `recorded`, `approved` and `amount_viewed` — three actions
 *     written by other verbs — and is renamed into invisibility. The maps are
 *     what the emitter indexes at runtime.
 *   - BEHAVIOUR, not just the tables. A table can be total and the emit still
 *     never fire; the driven arm below compares the SET of actions the service
 *     actually emitted against the SET the map declares.
 *
 * AND THE FLOOR IS AT EVERY LEVEL. Targets are one level and EDGES are another:
 * `completed → disputed` (undoing a payout) and `approved → disputed` (a
 * dispute before money moved) are one target and two edges, and docs/03 §6dd
 * says against its own phrasing that counting targets hides that. A fence that
 * asserted target coverage alone would be green while the edge claim — the one
 * the residual is actually about — went unproven.
 */
describe('every status a settlement state machine permits is a status it audits', () => {
  const MIGRATIONS = join(__dirname, '..', 'migrations');
  const SERVICE = join(__dirname, '..', 'src', 'admin.service.ts');

  /**
   * The values a `status` CHECK admits, from one `CREATE TABLE` body or one
   * `ALTER TABLE`, keyed by table — read from the DDL, which is what the
   * runtime enforces.
   *
   * BOTH CONSTRAINT STYLES, AND BOTH STATEMENTS. The first version of this
   * scan required the column-level style (`status TEXT NOT NULL … CHECK (…)`)
   * inside a `CREATE TABLE`, and was blind to the two forms that matter:
   *
   *   - A NAMED TABLE CONSTRAINT (`CONSTRAINT x_status_check CHECK (…)`),
   *     which is the dominant style in these same migrations.
   *   - `ALTER TABLE … ADD CONSTRAINT … CHECK (…)`, which is the ONLY way this
   *     repo can add a status to a shipped table: migrations are append-only
   *     and checksummed, so editing the original `CREATE TABLE` raises
   *     `MigrationDriftError` and never reaches a database. A fence blind to
   *     the ALTER form is blind to the only edit it exists to catch — proven,
   *     by adding a sixth `distributions` status that way and watching every
   *     assertion here stay green.
   *
   * Later files win, because that is what running them in order does.
   *
   * The value regex is `[A-Za-z0-9_]+`, not `[a-z_]+`: a token carrying a
   * digit silently produced NO match and dropped out of the "derived"
   * vocabulary rather than failing.
   */
  function statusTablesIn(dir: string): Map<string, string[]> {
    const found = new Map<string, string[]>();
    const values = (list: string): string[] => {
      const tokens = [...list.matchAll(/'([A-Za-z0-9_]+)'/g)].map((m) => m[1] as string);
      expect(tokens.length).toBeGreaterThan(1);
      return tokens;
    };
    for (const file of readdirSync(dir)
      .filter((f) => f.endsWith('.sql'))
      .sort()) {
      const sql = readFileSync(join(dir, file), 'utf8');
      for (const m of sql.matchAll(/CREATE TABLE (?:IF NOT EXISTS )?(\w+) \(([\s\S]*?)\n\);/g)) {
        // `\)\)` and nothing but a value list between: the OTHER `status IN`
        // constraints in these files read `CHECK (status IN (…) OR x IS NOT
        // NULL)`, which is a precondition on a column rather than the column's
        // vocabulary, and must not be mistaken for it.
        const checks = [...(m[2] as string).matchAll(/CHECK \(status IN \(([^)]*)\)\)/g)];
        if (checks.length === 0) continue;
        // Exactly one vocabulary per table, or the ambiguity fails loudly
        // instead of being resolved by match order.
        expect({ table: m[1], vocabularies: checks.length }).toEqual({
          table: m[1],
          vocabularies: 1,
        });
        found.set(m[1] as string, values((checks[0] as RegExpMatchArray)[1] as string));
      }
      for (const m of sql.matchAll(
        /ALTER TABLE (\w+)\s+ADD CONSTRAINT \w+\s*CHECK \(status IN \(([^)]*)\)\)/g,
      )) {
        found.set(m[1] as string, values(m[2] as string));
      }
    }
    return found;
  }

  /** The settlement service's own migrations — the corpus this fence claims. */
  function statusTables(): Map<string, string[]> {
    return statusTablesIn(MIGRATIONS);
  }

  /** Every value a table's `status` CHECK constraint admits, read from the DDL. */
  function ddlStatuses(table: string): string[] {
    const listed = statusTables().get(table);
    expect({ table, found: listed !== undefined }).toEqual({ table, found: true });
    return listed as string[];
  }

  /**
   * The edges `setDistributionStatus` permits, read from the service.
   *
   * READ, NEVER RESHAPED. `apps/web/src/components/EstateDistributions.test.tsx`
   * parses this same expression as text and derives the UI's move map from it,
   * so hoisting the ternary into shared data would break a fence in another
   * package and silently delete the "Raise a dispute" button from a paid-out
   * row. Two readers of one expression is the cost of that. ONLY THIS ONE SAYS
   * SO: the web fence names `admin.service.ts` and not this file, and an
   * earlier draft of this comment claimed "both say so" — a sentence about a
   * file M49 PR1 does not touch, which is the class of claim this repo gets
   * wrong most often.
   */
  function serviceEdges(): Map<string, string[]> {
    const source = readFileSync(SERVICE, 'utf8');
    const block = /const from: DistributionStatus\[\] =([\s\S]*?);\n/.exec(source);
    expect(block?.[1]?.length ?? 0).toBeGreaterThan(50);
    const body = block?.[1] ?? '';
    const edges = new Map<string, string[]>();
    for (const m of body.matchAll(/to === '([a-z_]+)'\s*\n?\s*\?\s*\[([^\]]*)\]/g)) {
      edges.set(
        m[1] as string,
        [...(m[2] as string).matchAll(/'([a-z_]+)'/g)].map((x) => x[1] as string),
      );
    }
    const tail = /:\s*\[([^\]]*)\];?\s*$/.exec(body.trim());
    const tailFroms = [...(tail?.[1] ?? '').matchAll(/'([a-z_]+)'/g)].map((x) => x[1] as string);
    // The unguarded arm is the target the ternary never names; recover it as
    // the one map key the chain does not mention.
    const named = new Set(edges.keys());
    const remaining = Object.keys(DISTRIBUTION_STATUS_ACTIONS).filter((t) => !named.has(t));
    expect(remaining).toHaveLength(1);
    // A FLOOR PER TARGET, not just on the total. `block` needs its `;` to be
    // followed by a newline, so a trailing comment after the ternary makes it
    // run PAST the expression and `tail` match nothing — leaving the unguarded
    // arm with an empty from-list. Every assertion downstream compared totals,
    // so one extra edge elsewhere restored the count and that target dropped
    // out of the drive entirely: measured, with a real missing emit going
    // undetected behind it.
    edges.set(remaining[0] as string, tailFroms);
    // The floor itself, and it covers the recovered arm because the line above
    // put it in `edges` first. Reported per TARGET so the failure names the one
    // that emptied rather than reporting a total that some other edge restored.
    for (const [target, froms] of edges) {
      expect({ target, empty: froms.length === 0 }).toEqual({ target, empty: false });
    }
    return edges;
  }

  /**
   * The stage machine's status → action mapping, DRIVEN below rather than
   * trusted. It lives here and not in `events.service.ts` because stages need
   * no map at runtime: each transition already has its own verb and its own
   * emitter, which is the reason this machine was total before M49 PR1 and the
   * distribution machine was not. Declaring it here buys the fence a third
   * machine to be total over without adding an indirection the service would
   * not otherwise have.
   */
  const STAGE_STATUS_ACTIONS: Readonly<Record<string, string>> = {
    requested: 'settlement.stage.requested',
    approved: 'settlement.stage.approved',
    denied: 'settlement.stage.denied',
    revoked: 'settlement.stage.revoked',
  };

  it('the corpus is every settlement table with a status CHECK — declared, not chosen', () => {
    const derived = statusTables();
    // Anti-vacuity: a scan that stopped matching reports an empty map, which
    // would agree with any declaration written as a subset.
    expect(derived.size).toBeGreaterThanOrEqual(3);

    // WHY EACH ONE IS IN REACH, so that a fourth table forces a sentence rather
    // than a line. The values are the vocabularies asserted individually below.
    const covered: Readonly<Record<string, string>> = {
      distributions: 'DISTRIBUTION_STATUS_ACTIONS — the machine this PR made total.',
      settlement_cases: 'CASE_ADVANCE_ACTIONS plus the six rungs with verbs of their own.',
      settlement_access_stages:
        'STAGE_STATUS_ACTIONS — already total when this fence was written, ' +
        'and kept here as the POSITIVE CONTROL: a machine that passes proves ' +
        'the assertions can distinguish coverage from a matcher that fires on ' +
        'everything.',
    };
    expect([...derived.keys()].sort()).toEqual(Object.keys(covered).sort());
  });

  it('reads a status vocabulary REDEFINED by a later migration — the ALTER form', () => {
    /*
     * THE ANTI-VACUITY FOR A BRANCH SETTLEMENT DOES NOT YET EXERCISE.
     *
     * Migrations are append-only and checksummed, so a status can only be added
     * to a shipped table by `ALTER TABLE … DROP CONSTRAINT … ADD CONSTRAINT` in
     * a NEW file — editing the original `CREATE TABLE` raises
     * `MigrationDriftError` and never reaches a database. That makes the ALTER
     * form the ONLY edit this fence exists to catch, and settlement has none
     * today, so the branch that handles it would sit unproven and could rot to
     * a no-op while every assertion here stayed green.
     *
     * Identity has one, so it is the control: `014_erasure_requests.sql`
     * creates `erasure_requests` with two statuses and
     * `015_erasure_execution.sql` redefines the constraint with four. Reading
     * TWO is the failure this proves impossible — it would mean the scan sees
     * the `CREATE TABLE` and not the redefinition.
     */
    const identity = statusTablesIn(join(__dirname, '..', '..', 'identity', 'migrations'));
    expect(identity.get('erasure_requests')).toEqual([
      'pending',
      'cancelled',
      'executing',
      'completed',
    ]);
  });

  it('the stage machine was already total, and is driven to prove it', async () => {
    const stageStatuses = statusTables().get('settlement_access_stages');
    expect([...(stageStatuses ?? [])].sort()).toEqual(Object.keys(STAGE_STATUS_ACTIONS).sort());
    for (const action of Object.values(STAGE_STATUS_ACTIONS)) {
      expect(AUDIT_ACTIONS).toContain(action);
    }
    // DISTINCT, like its sibling map's assertion below. Both sides of the set
    // comparison at the end of this test collapse duplicates, so two statuses
    // sharing one action would let a suppressed emit pass — measured: with
    // `revoked` pointed at `settlement.stage.approved` and the revoke emit
    // removed, this test stayed green without this line.
    expect(new Set(Object.values(STAGE_STATUS_ACTIONS)).size).toBe(
      Object.keys(STAGE_STATUS_ACTIONS).length,
    );

    const h = buildAdminHarness();
    const caseId = await verifiedCaseFor(h);
    const approved = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, approved.stageId, 'approve');
    const denied = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'documents');
    await h.admin.decideStage(OPERATOR, SESSION, denied.stageId, 'deny');
    await h.admin.revokeStage(OPERATOR, SESSION, approved.stageId);

    const emitted = new Set(
      auditEvents(h.producer)
        .map((e) => e['action'])
        .filter((a) => (Object.values(STAGE_STATUS_ACTIONS) as unknown[]).includes(a)),
    );
    expect(emitted).toEqual(new Set(Object.values(STAGE_STATUS_ACTIONS)));
  });

  it('the distribution map is exactly the targets the verb accepts, and no more', () => {
    const ddl = ddlStatuses('distributions');
    expect(ddl).toEqual(['planned', 'approved', 'in_progress', 'completed', 'disputed']);

    const mapped = Object.keys(DISTRIBUTION_STATUS_ACTIONS).sort();
    const edges = serviceEdges();
    // The map and the service agree about which targets exist...
    expect(mapped).toEqual([...edges.keys()].sort());
    // ...and every DDL status is accounted for as either a target of this verb
    // or a status written by a different, separately audited one. A sixth
    // status added to the CHECK lands in neither list and reddens here.
    const elsewhere = ddl.filter((s) => !mapped.includes(s));
    expect(elsewhere).toEqual(['planned', 'approved']);
  });

  it('the case map is exactly the rungs that had no verb of their own', () => {
    const ddl = ddlStatuses('settlement_cases');
    expect(ddl).toEqual([
      'reported',
      'verifying',
      'waiting_period',
      'verified',
      'active',
      'distributing',
      'closed',
      'rejected_fraud',
    ]);
    expect(Object.keys(CASE_ADVANCE_ACTIONS).sort()).toEqual(['active', 'distributing']);
    // Every other case status is written by a verb with its own audited event.
    // Named here so that adding a ninth forces a decision rather than silence.
    const byOwnVerb = ddl.filter((s) => !(s in CASE_ADVANCE_ACTIONS));
    expect(byOwnVerb).toEqual([
      'reported',
      'verifying',
      'waiting_period',
      'verified',
      'closed',
      'rejected_fraud',
    ]);
  });

  it('every mapped action is a member of the closed audit vocabulary', () => {
    const mapped = [
      ...Object.values(DISTRIBUTION_STATUS_ACTIONS),
      ...Object.values(CASE_ADVANCE_ACTIONS),
    ];
    expect(mapped.length).toBe(5);
    for (const action of mapped) {
      expect(AUDIT_ACTIONS).toContain(action);
    }
    // Distinct: two targets sharing an action would make the trail unable to
    // say which move happened, and every assertion above would still pass.
    expect(new Set(mapped).size).toBe(mapped.length);
  });

  it('DRIVES every distribution edge, and each one lands under its mapped action', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCaseFor(h);
    const edges = serviceEdges();

    // One distribution per edge, each driven to the edge's `from` first.
    const seen: Array<{ action: unknown; from: unknown; to: unknown }> = [];
    for (const [to, froms] of edges) {
      for (const from of froms) {
        const dist = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
          beneficiaryContactId: randomUUID(),
          amount: '100.00',
        });
        await h.admin.approveDistribution(OPERATOR, SESSION, dist.distributionId);
        if (from === 'in_progress' || from === 'completed') {
          await h.admin.setDistributionStatus(
            EXECUTOR,
            SESSION,
            dist.distributionId,
            'in_progress',
          );
        }
        if (from === 'completed') {
          await h.admin.setDistributionStatus(EXECUTOR, SESSION, dist.distributionId, 'completed');
        }
        const before = auditEvents(h.producer).length;
        await h.admin.setDistributionStatus(
          EXECUTOR,
          SESSION,
          dist.distributionId,
          to as DistributionStatusTarget,
        );
        const emitted = auditEvents(h.producer).slice(before);
        const statusRows = emitted.filter((e) =>
          (Object.values(DISTRIBUTION_STATUS_ACTIONS) as unknown[]).includes(e['action']),
        );
        // EXACTLY ONE per movement: silence is the old defect and a duplicate
        // would be a second spelling of the same fact.
        expect(statusRows).toHaveLength(1);
        const row = statusRows[0] as Record<string, unknown>;
        const detail = row['detail'] as Record<string, unknown>;
        seen.push({ action: row['action'], from: detail['from'], to: detail['to'] });
      }
    }

    // The SET of edges the service recorded is the SET the service permits —
    // compared as edges, because two rows attributed to the same target would
    // satisfy any count while leaving completed→disputed unproven.
    const expected = [...edges].flatMap(([to, froms]) =>
      froms.map((from) => ({
        action: DISTRIBUTION_STATUS_ACTIONS[to as DistributionStatusTarget],
        from,
        to,
      })),
    );
    expect(expected.length).toBeGreaterThanOrEqual(5);
    // EVERY TARGET WAS ACTUALLY DRIVEN, asserted at the target level as well as
    // the edge level. The set comparison below draws both sides from the same
    // parse, so a target the parser loses is missing from both and agrees.
    expect(new Set(seen.map((x) => x.to))).toEqual(
      new Set(Object.keys(DISTRIBUTION_STATUS_ACTIONS)),
    );
    expect(new Set(seen.map((s) => JSON.stringify(s)))).toEqual(
      new Set(expected.map((s) => JSON.stringify(s))),
    );
    // The edge the residual is about, named so a reader can find it.
    expect(seen).toContainEqual({
      action: 'settlement.distribution.disputed',
      from: 'completed',
      to: 'disputed',
    });
  });

  it('DRIVES both case rungs, and each one lands under its mapped action', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCaseFor(h);

    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '100.00',
    });

    const rungs = auditEvents(h.producer)
      .filter((e) => (Object.values(CASE_ADVANCE_ACTIONS) as unknown[]).includes(e['action']))
      .map((e) => ({
        action: e['action'],
        from: (e['detail'] as Record<string, unknown>)['from'],
        to: (e['detail'] as Record<string, unknown>)['to'],
        onBehalfOf: e['onBehalfOf'],
        actorType: e['actorType'],
      }));

    expect(rungs).toEqual([
      {
        action: CASE_ADVANCE_ACTIONS['active' as CaseStatusAdvanceTarget],
        from: 'verified',
        to: 'active',
        onBehalfOf: DECEDENT,
        // THE CAPACITY, and it was unasserted until a mutation proved it: with
        // `recordDistribution`'s `asOperator` flipped from `false` to `true`
        // the whole package stayed green while an executor's own act landed on
        // a decedent's permanent trail as operator support. The two rungs take
        // opposite arms — an operator approves the stage, the executor records
        // the distribution — so asserting both is what discriminates.
        actorType: 'operator',
      },
      {
        action: CASE_ADVANCE_ACTIONS['distributing' as CaseStatusAdvanceTarget],
        from: 'active',
        to: 'distributing',
        onBehalfOf: DECEDENT,
        actorType: 'user',
      },
    ]);
  });

  it('a rung whose compare-and-set LOST is silent — only the boolean knows', async () => {
    /*
     * WRITTEN BECAUSE A MUTATION SURVIVED. Replacing
     * `caseAdvancedFrom = (await advanceStatus(…)) ? movedFrom : null` with an
     * unconditional `await advanceStatus(…); caseAdvancedFrom = movedFrom` left
     * this file and `admin.service.spec.ts` — the two that could have caught
     * it — entirely green.
     *
     * THE HONEST READING IS THE THIRD ONE, and it took two attempts to reach.
     * Not a weak test, and not an unfaithful mutation: the arm where the
     * boolean decides is UNREACHABLE. A first answer blamed the sequential
     * harness, and that was wrong about the reason. Both call sites read the
     * case status through `CasesRepo.lockById`, which is `SELECT … FOR UPDATE`
     * on the very row `advanceStatus` updates, so a second transaction blocks
     * on that lock and re-reads the committed status rather than interleaving
     * — and independently, the status is already narrowed to
     * `ADMINISTRABLE_STATUSES` with the destination excluded, so the
     * compare-and-set matches by construction.
     *
     * THE TEST IS KEPT AND PINS A SPECIFICATION, not a reproduction: the
     * emit's precondition is the WRITE rather than the read above it, so the
     * trail says what the DATABASE did and stays right if the locking ever
     * moves. To pin that it has to manufacture the interleaving the lock
     * forbids, which is what the racer below is.
     *
     * The racer is expressed through the repo the service already uses rather
     * than by stubbing a return value: every compare-and-set is preceded by an
     * identical one that WINS, so ours matches no `from` and answers false
     * through the real predicate. That is exactly the interleaving a second
     * transaction produces, and it is the shape a stub asserting `false` would
     * only be pretending to have.
     */
    const h = buildAdminHarness();
    const caseId = await verifiedCaseFor(h);

    const real = h.cases.advanceStatus.bind(h.cases);
    h.cases.advanceStatus = async (
      tx: Parameters<typeof real>[0],
      id: string,
      from: readonly CaseStatus[],
      to: CaseStatus,
    ): Promise<boolean> => {
      await real(tx, id, from, to);
      return real(tx, id, from, to);
    };

    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '100.00',
    });

    // The rungs were CLIMBED — by the racer, not by these calls. Without this
    // the test would pass on a run where nothing happened at all.
    expect((await h.cases.findById(undefined as never, caseId))?.status).toBe('distributing');
    // ...and this caller, which moved neither, claimed neither.
    expect(
      auditEvents(h.producer).filter((e) =>
        (Object.values(CASE_ADVANCE_ACTIONS) as unknown[]).includes(e['action']),
      ),
    ).toEqual([]);
  });

  it('a rung that did not move emits nothing — the second distribution is silent', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCaseFor(h);

    await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '100.00',
    });
    const before = auditEvents(h.producer).filter(
      (e) => e['action'] === CASE_ADVANCE_ACTIONS.distributing,
    ).length;
    await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '200.00',
    });
    const after = auditEvents(h.producer).filter(
      (e) => e['action'] === CASE_ADVANCE_ACTIONS.distributing,
    ).length;

    // The case reached `distributing` once and only once. Emitting per call
    // rather than per MOVEMENT would put one row on the trail per distribution
    // for a status that changed a single time.
    expect(before).toBe(1);
    expect(after).toBe(1);
  });
});
