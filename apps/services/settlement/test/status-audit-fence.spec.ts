import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import { AUDIT_ACTIONS, type AuditAction } from '@estate/contracts';

import { ADMINISTRABLE_STATUSES, type CaseStatus } from '../src/cases.repo';
import {
  CASE_ADVANCE_ACTIONS,
  DISTRIBUTION_STATUS_ACTIONS,
  type CaseStatusAdvanceTarget,
  type DistributionStatusTarget,
} from '../src/events.service';
import { LIVE_STAGE_STATUSES } from '../src/stages.repo';
import {
  auditEvents,
  buildAdminHarness,
  buildHarness,
  markCaseVerified,
  NOW,
  type AdminHarness,
  type Harness,
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

const MIGRATIONS = join(__dirname, '..', 'migrations');
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
      // WHITESPACE-TOLERANT, because the dominant style in these files puts
      // the constraint on its own lines and a CHECK body wrapped over three of
      // them was INVISIBLE to the first version — a probe migration adding a
      // fourth status table that way left this file's "a fourth table forces a
      // sentence rather than a line" assertion green. `\)\s*\)` and nothing but
      // a value list between still discriminates against the OTHER `status IN`
      // constraints here, which read `CHECK (status IN (…) OR x IS NOT NULL)`.
      const checks = [...(m[2] as string).matchAll(/CHECK \(\s*status IN \(([^)]*)\)\s*\)/g)];
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
      /ALTER TABLE (\w+)\s+ADD CONSTRAINT \w+\s*CHECK \(\s*status IN \(([^)]*)\)\s*\)/g,
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
  const SERVICE = join(__dirname, '..', 'src', 'admin.service.ts');

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

// ---------------------------------------------------------------------------
// M49 PR3 — the edge, where the target-level fence above stops.

const SRC = join(__dirname, '..', 'src');

interface StatusStatement {
  /**
   * `<table>:<what is assigned to status>` — the pair the RUNTIME writes, and
   * unique across this service's statements. NOT the method name: a fence
   * keyed on an identifier a caller chose gets renamed into invisibility and
   * stays green, and these nine statements are precisely the thing a rename
   * would hide.
   */
  key: string;
  file: string;
  /**
   * The one status this statement's from-predicate admits, or `null` when it
   * admits more than one.
   *
   * `null` IS THE UNRECOGNISED CASE TOO — a parameterised `= ANY($n)`, an
   * interpolated constant, or no `status` predicate at all. That is the
   * direction that fails closed: an unreadable predicate makes the fence
   * DEMAND the prior status be recorded rather than excuse it.
   */
  only: string | null;
}

/**
 * Every statement in this service that writes a `status` column, read from the
 * repo sources.
 *
 * WHY THE SCAN AND NOT A LIST. The rule this fence enforces is not "these four
 * events carry a `from`" — it is "a transition that could have started in more
 * than one place must say which". Those are the same sentence today and will
 * not be tomorrow: the next widened predicate, or the next status-writing
 * statement, is exactly the change that would leave a hand-written list still
 * true and still green. `StagesRepo.decide` is the derived POSITIVE CONTROL —
 * it writes a status from exactly one prior status, so it needs no `from`, and
 * it needs none for a reason the scan reads rather than a reason this file
 * asserts. Widen it to accept `approved` and this fence turns red demanding a
 * drive that does not exist.
 */
function statusWritingStatementsIn(source: string, file: string): StatusStatement[] {
  const found: StatusStatement[] = [];
  // Every SQL template literal in the file, then every UPDATE inside it. The
  // first draft matched `UPDATE (\w+)\n\s*SET status = …([\s\S]*?)RETURNING`
  // against the whole source, and its own review demonstrated TEN shapes that
  // produced no match at all — no `RETURNING` (a plain cascade has no reason to
  // have one), `status` not the first assignment, the statement on one line,
  // lowercase keywords, `SET "status" =`, a schema-qualified or aliased table.
  // Two of those already exist in this service on non-status columns, and a
  // live probe added a two-status `revokeAllForCase` with no `RETURNING`:
  // the scan stayed at nine and the whole package stayed green.
  for (const block of source.matchAll(/`([^`]*)`/g)) {
    // SQL line comments go first, and that is not tidiness: a `--` comment
    // reading "the normal case is status = 'requested'" made the classifier
    // below report single-valued for an `= ANY($n)` predicate, green.
    const sql = (block[1] as string).replace(/--[^\n]*/g, ' ');
    for (const stmt of sql.matchAll(/\bUPDATE\s+(?:ONLY\s+)?"?([A-Za-z_][\w.]*)"?\b([\s\S]*)/gi)) {
      const table = stmt[1] as string;
      const tail = stmt[2] as string;
      const setAt = /\bSET\b/i.exec(tail);
      if (!setAt) continue;
      const afterSet = tail.slice(setAt.index + setAt[0].length);
      // The SET clause ends at whichever of FROM / WHERE / RETURNING comes
      // first — `UPDATE … SET … FROM prior WHERE …` is the shape both CTE
      // statements use.
      const endOfSet = /\b(FROM|WHERE|RETURNING)\b/i.exec(afterSet);
      const setClause = endOfSet ? afterSet.slice(0, endOfSet.index) : afterSet;
      const assign = /(?:^|,)\s*"?status"?\s*=\s*([^,]+)/i.exec(setClause);
      if (!assign) continue;
      const whereAt = /\bWHERE\b/i.exec(afterSet);
      const predicate = whereAt
        ? (afterSet.slice(whereAt.index).split(/\bRETURNING\b/i)[0] ?? '')
        : '';
      found.push({
        key: `${table}:${(assign[1] as string).trim()}`,
        file,
        only: soleLiteralStatus(predicate),
      });
    }
  }
  return found;
}

/**
 * The one status a predicate admits, or `null` when it admits more — or when
 * this cannot tell.
 *
 * IT COUNTS MENTIONS BEFORE IT READS ONE. The first draft probed for the first
 * `status = '<literal>'` it could find, which is not a proof that the predicate
 * admits one value: `(status = 'requested' OR status = 'approved')` matched the
 * probe and classified as single-valued, and the whole package stayed green
 * while `settlement.stage.denied` gained a second prior status. `OR` in a WHERE
 * is idiomatic in these very repositories. So: exactly one `status` comparison,
 * and that one an equality on a literal, or the answer is `null` — which makes
 * the fence DEMAND the edge be recorded, the direction that fails closed.
 */
function soleLiteralStatus(predicate: string): string | null {
  const mentions = predicate.match(
    /\b(?:\w+\.)?"?status"?\s*(?:=|<>|!=|\bIS\b|\bIN\b|\bNOT\b|\bANY\b|\bALL\b)/gi,
  );
  if (!mentions || mentions.length !== 1) {
    return null;
  }
  const literal = /\b(?:\w+\.)?"?status"?\s*=\s*'([A-Za-z0-9_]+)'/.exec(predicate);
  return literal ? (literal[1] as string) : null;
}

/**
 * THE CORPUS IS EVERY SOURCE FILE IN THE SERVICE, not every file named
 * `*.repo.ts`.
 *
 * The first draft used that suffix, and settlement ALREADY holds a repository
 * that does not carry it: `dek.repository.ts`, which issues an UPDATE of its
 * own. It writes no `status` column, so the count was right — and it would
 * have gone on being right until someone added a status writer to a file whose
 * name this fence had quietly decided not to read, with every assertion green.
 * A scan keyed on a filename convention is the same defect as a fence keyed on
 * an identifier a caller chose.
 *
 * The file-set assertion below is what keeps the widening honest: the scan
 * reads everything and must still find status writes in exactly three files.
 */
function statusWritingStatements(): StatusStatement[] {
  const files = readdirSync(SRC, { recursive: true, encoding: 'utf8' })
    .filter((f) => f.endsWith('.ts'))
    .sort();
  // Anti-vacuity on the corpus rather than the result: a recursive read that
  // stopped matching returns nothing, and an empty scan agrees with any
  // declaration written as a subset.
  expect(files.length).toBeGreaterThanOrEqual(20);
  return files.flatMap((file) =>
    statusWritingStatementsIn(readFileSync(join(SRC, file), 'utf8'), file),
  );
}

/**
 * The statuses the partial unique index treats as LIVE, read from settlement's
 * migrations — `CREATE UNIQUE INDEX … ON settlement_access_stages (case_id,
 * stage) WHERE status IN (…)`.
 *
 * This is the constraint that makes one live stage row per (case, stage) true,
 * and therefore the constraint `StagesRepo.findLive` depends on when it returns
 * `rows[0]` without an ORDER BY. `LIVE_STAGE_STATUSES` serves both that role
 * and the revoke from-set, so the two must agree; the index is the side that
 * cannot be argued with.
 */
function liveStageIndexPredicate(): string[] {
  const found: string[][] = [];
  for (const file of readdirSync(MIGRATIONS)
    .filter((f) => f.endsWith('.sql'))
    .sort()) {
    const sql = readFileSync(join(MIGRATIONS, file), 'utf8');
    for (const m of sql.matchAll(
      /CREATE UNIQUE INDEX \w+\s+ON settlement_access_stages[^;]*?WHERE status IN \(([^)]*)\)/g,
    )) {
      found.push([...(m[1] as string).matchAll(/'([a-z_]+)'/g)].map((x) => x[1] as string));
    }
  }
  // Exactly one such index, and it names more than one status — two of them
  // would make "the live set" ambiguous, and zero would make this a scan that
  // cannot fail.
  expect(found).toHaveLength(1);
  expect((found[0] as string[]).length).toBeGreaterThan(1);
  return found[0] as string[];
}

/**
 * Every `CasesRepo.markResolved` call site, with the from-set it passes and the
 * resolution it writes — read from the service, because the predicate is a
 * PARAMETER and the sets therefore live at the call sites rather than in the
 * SQL.
 *
 * READ, NOT IMPORTED, and the BFF reads the same expression: `apps/bff`'s
 * `settlement.spec.ts` pins its own `VOIDABLE_STATUSES` to the void site's
 * array with a regex of the same shape, because it cannot import from a Nest
 * service package. Two readers of one expression, and hoisting these arrays
 * into a shared constant would blind both.
 */
function markResolvedSites(): Array<{ froms: string[]; resolution: string }> {
  const source = readFileSync(join(SRC, 'settlement.service.ts'), 'utf8');
  const sites = [
    ...source.matchAll(/markResolved\(\s*tx,\s*caseId,\s*\[([^\]]*)\],\s*'([a-z_]+)'/g),
  ].map((m) => ({
    froms: [...(m[1] as string).matchAll(/'([a-z_]+)'/g)].map((x) => x[1] as string),
    resolution: m[2] as string,
  }));
  // A FLOOR THE PARSE DID NOT PRODUCE. `expect(sites).toHaveLength(3)` counts
  // what this regex FOUND, so a fourth call site the regex cannot see is not
  // missing — it never existed. Measured: a fourth `markResolved(` spelled with
  // a different argument name carried a four-status from-set, undriven and
  // unrecorded, with the whole package green. Counting the bare occurrences is
  // the independent number, and it is cheap.
  const occurrences = (source.match(/markResolved\(/g) ?? []).length;
  expect({ parsed: sites.length, occurrences }).toEqual({
    parsed: occurrences,
    occurrences,
  });
  // A FLOOR PER SITE, not on the total: one site parsing to an empty array
  // while another gained a status would leave every downstream count intact.
  for (const site of sites) {
    expect({ resolution: site.resolution, empty: site.froms.length === 0 }).toEqual({
      resolution: site.resolution,
      empty: false,
    });
  }
  return sites;
}

/** The statuses an operator rejection can start from. */
function rejectFroms(): string[] {
  const sites = markResolvedSites().filter((s) => s.resolution === 'operator_rejected');
  expect(sites).toHaveLength(1);
  return (sites[0] as { froms: string[] }).froms;
}

/**
 * The statuses a void can start from — the UNION of the owner route's three
 * and the liveness re-check's two, which overlap on `waiting_period`. One
 * action, two call sites: a fence reading either one alone would be narrower
 * than its own claim and green for that reason.
 */
function voidFroms(): string[] {
  const sites = markResolvedSites().filter((s) => s.resolution === 'owner_voided');
  expect(sites).toHaveLength(2);
  return [...new Set(sites.flatMap((s) => s.froms))];
}

/**
 * The statements whose from-predicate admits exactly ONE prior status, and
 * that status. Nothing here needs to record an edge: the action names the
 * whole edge already.
 */
const SINGLE_FROM: Readonly<Record<string, string>> = {
  "settlement_cases:'verifying'": 'reported',
  "settlement_cases:'waiting_period'": 'verifying',
  "settlement_cases:'verified'": 'waiting_period',
  "distributions:'approved'": 'planned',
  'settlement_access_stages:$2': 'requested',
};

/**
 * The statements that can move a row from more than one prior status, and the
 * actions their movements land under — every one of which must therefore carry
 * the prior status. Driven below; the KEY SET is compared against the scan.
 *
 * Three of the four were made total by M49 PR1 at the TARGET level and are
 * driven at the EDGE level in the describe above; `settlement.case.closed`,
 * `settlement.case.rejected`, `settlement.case.voided` and
 * `settlement.stage.revoked` are M49 PR3's, and are driven here.
 */
const MULTI_FROM: Readonly<Record<string, readonly AuditAction[]>> = {
  "settlement_cases:'rejected_fraud'": ['settlement.case.rejected', 'settlement.case.voided'],
  'settlement_cases:$3': [
    'settlement.case.activated',
    'settlement.case.distributing',
    'settlement.case.closed',
  ],
  'distributions:$3': [
    'settlement.distribution.in_progress',
    'settlement.distribution.completed',
    'settlement.distribution.disputed',
  ],
  "settlement_access_stages:'revoked'": ['settlement.stage.revoked'],
};

/** The `from` values an action was actually recorded with, across a drive. */
function fromsFor(h: { producer: Parameters<typeof auditEvents>[0] }, action: string): string[] {
  return auditEvents(h.producer)
    .filter((e) => e['action'] === action)
    .map((e) => (e['detail'] as Record<string, unknown>)['from'] as string);
}

function caseHarness(): Harness {
  const h = buildHarness();
  h.coreReads.link(DECEDENT, REPORTER);
  h.operators.active.add(OPERATOR);
  return h;
}

async function reportedCase(h: Harness): Promise<string> {
  const dto = await h.service.report(REPORTER, SESSION, {
    decedentUserId: DECEDENT,
    source: 'trusted_contact',
    evidence: [],
  });
  return dto.caseId;
}

/** Move the clock past the waiting period this case actually got. */
function pastTheWait(h: Harness, caseId: string): void {
  const ends = h.cases.rows.get(caseId)?.waiting_period_ends;
  expect(ends).toBeInstanceOf(Date);
  h.clock.value = new Date((ends as Date).getTime() + 1000);
}

describe('a terminal state does not record what it ended — unless the event does', () => {
  it('DERIVES which statements owe a `from`: one prior status owes nothing, several owe one', () => {
    const scanned = statusWritingStatements();
    // Anti-vacuity at the level the scan operates on. A regex that stopped
    // matching returns an empty list, which agrees with any declaration
    // written as a subset — and the three repos below are the corpus claimed.
    expect(scanned.length).toBeGreaterThanOrEqual(8);
    expect(new Set(scanned.map((s) => s.file))).toEqual(
      new Set(['cases.repo.ts', 'distributions.repo.ts', 'stages.repo.ts']),
    );
    // Unique keys, or two statements collapse into one and one of them stops
    // being looked at while every count below still adds up.
    expect(new Set(scanned.map((s) => s.key)).size).toBe(scanned.length);

    const single = scanned.filter((s) => s.only !== null);
    const multi = scanned.filter((s) => s.only === null);
    expect(new Set(single.map((s) => s.key))).toEqual(new Set(Object.keys(SINGLE_FROM)));
    expect(new Set(multi.map((s) => s.key))).toEqual(new Set(Object.keys(MULTI_FROM)));
    // ...and the single-valued ones admit the status this file says they do,
    // so a predicate that changed which one still reddens.
    expect(Object.fromEntries(single.map((s) => [s.key, s.only]))).toEqual(SINGLE_FROM);

    for (const actions of Object.values(MULTI_FROM)) {
      for (const action of actions) {
        expect(AUDIT_ACTIONS).toContain(action);
      }
    }
  });

  it('classifies every predicate shape it cannot READ as owing a `from`', () => {
    /*
     * THE ANTI-VACUITY FOR THE FAIL-CLOSED DIRECTION, AND FOR THE SHAPES THIS
     * SCAN HAS ALREADY BEEN WRONG ABOUT.
     *
     * All nine statements in this service parse into forms the scan recognises,
     * so the branch deciding what happens to an UNRECOGNISED predicate is never
     * taken by the corpus above — and a branch no input reaches can rot into
     * the opposite answer while every assertion stays green. The opposite
     * answer is the dangerous one: classifying an unreadable predicate as
     * single-valued excuses it from recording an edge, silently.
     *
     * THE `OR` AND THE COMMENT CASES ARE NOT HYPOTHETICAL. The first version of
     * this classifier probed for the first `status = '<literal>'` it could
     * find. Its own review widened `StagesRepo.decide` to
     * `(status = 'requested' OR status = 'approved')` and to `= ANY($5)` under
     * a `--` comment mentioning `status = 'requested'`, and the whole package
     * stayed green both times — a machine gaining a second prior status behind
     * the assertion that exists to notice exactly that. `OR` in a WHERE and
     * `--` comments in SQL are both idiomatic in these repositories.
     *
     * Input is SOURCE, not bare SQL: the scan reads template literals out of a
     * TypeScript file, so a synthetic case that skipped the backticks would be
     * testing something the scan never sees.
     */
    const src = (sql: string): string => `const q = \`${sql}\`;`;
    const cases: Array<[string, string | null]> = [
      // ONE literal equality: the only shape that owes nothing.
      [`UPDATE t\n  SET status = 'x'\n WHERE id = $1 AND status = 'y'\n RETURNING id`, 'y'],
      // Two, spelled with OR. The shape that used to pass as single-valued.
      [
        `UPDATE t\n  SET status = 'x'\n WHERE id = $1 AND (status = 'y' OR status = 'z')\n RETURNING id`,
        null,
      ],
      // A parameterised set with a comment that names a single status.
      [
        `UPDATE t\n  SET status = $2\n  -- the normal case is status = 'y'\n WHERE id = $1 AND status = ANY($3)\n RETURNING id`,
        null,
      ],
      // Not an equality on a literal.
      [`UPDATE t\n  SET status = 'x'\n WHERE id = $1 AND status <> 'y'\n RETURNING id`, null],
      // No `status` predicate at all — the row can be in ANY status.
      [`UPDATE t\n  SET status = 'x'\n WHERE id = $1\n RETURNING id`, null],
    ];
    for (const [sql, expected] of cases) {
      const parsed = statusWritingStatementsIn(src(sql), 'synthetic.repo.ts');
      expect({ sql, count: parsed.length }).toEqual({ sql, count: 1 });
      expect({ sql, only: (parsed[0] as StatusStatement).only }).toEqual({ sql, only: expected });
    }
  });

  it('SEES every statement shape a status write could be written in', () => {
    /*
     * THE OTHER HALF, and the one a live probe broke: a statement the scan does
     * not SEE is not classified wrongly, it is absent — and absence is silent,
     * because the count floor and the key sets both agree with a statement that
     * was never read. A `revokeAllForCase` cascade with two prior statuses and
     * no `RETURNING` was added to `stages.repo.ts` during this file's review;
     * the scan stayed at nine and the package stayed green.
     *
     * Each shape below is one the old regex missed. Two of them already exist
     * in this service on non-status columns — `CasesRepo.appendEvidence` has no
     * `RETURNING`, and `dek.repository.ts` writes its UPDATE on one line.
     */
    const shapes: Record<string, string> = {
      'no RETURNING': `UPDATE t SET status = 'x' WHERE id = $1 AND status = 'y'`,
      'one line': `UPDATE t SET status = 'x' WHERE id = $1 AND status = 'y' RETURNING id`,
      'status not first': `UPDATE t\n  SET seen_at = $2, status = 'x'\n WHERE id = $1 AND status = 'y'`,
      'newline after SET': `UPDATE t\n  SET\n    status = 'x'\n WHERE id = $1 AND status = 'y'`,
      lowercase: `update t set status = 'x' where id = $1 and status = 'y'`,
      quoted: `UPDATE t\n  SET "status" = 'x'\n WHERE id = $1 AND "status" = 'y'`,
      'schema-qualified': `UPDATE app.t\n  SET status = 'x'\n WHERE id = $1 AND status = 'y'`,
      'no spaces': `UPDATE t\n  SET status='x'\n WHERE id = $1 AND status='y'`,
    };
    for (const [name, sql] of Object.entries(shapes)) {
      const parsed = statusWritingStatementsIn(`const q = \`${sql}\`;`, 'synthetic.repo.ts');
      // Reported per SHAPE, so the failure names the one that went invisible
      // rather than a total some other shape restored.
      expect({ name, seen: parsed.length }).toEqual({ name, seen: 1 });
      expect({ name, only: (parsed[0] as StatusStatement).only }).toEqual({ name, only: 'y' });
    }
    // The negative control: a template literal with no status write at all must
    // yield nothing, or "sees everything" would be satisfied by a scan that
    // reports a statement for any input.
    expect(
      statusWritingStatementsIn(
        'const q = `UPDATE t SET seen_at = $2 WHERE id = $1 RETURNING id`;',
        'synthetic.repo.ts',
      ),
    ).toEqual([]);
  });

  it('the from-sets are the predicates the runtime compares against, not a retyping', () => {
    // THE STAGE SET. One constant, interpolated into the statement, so the
    // type on the emitter's parameter and the SQL cannot disagree — it was two
    // identical literal lists in two statements before M49 PR3.
    const stages = readFileSync(join(SRC, 'stages.repo.ts'), 'utf8');
    expect(stages).toContain('const LIVE_LIST = LIVE_STAGE_STATUSES.map');
    const revoke = /SET status = 'revoked'[\s\S]*?RETURNING/.exec(stages);
    expect(revoke?.[0]).toContain('status IN (${LIVE_LIST})');
    expect(
      LIVE_STAGE_STATUSES.every((s) => ddlStatuses('settlement_access_stages').includes(s)),
    ).toBe(true);
    // AND ITS MEMBERS ARE THE DDL'S, not this file's. Writing
    // `toEqual(['requested','approved'])` here would be the hand-maintained
    // list beside a thing that grows — and it would be load-bearing beyond
    // this fence, because the constant has a SECOND role: `findLive` filters
    // on it and returns `rows[0]` with no ORDER BY, so its single-row-ness
    // comes entirely from the partial unique index below. Widen the constant
    // without widening the index and `findLive` starts choosing arbitrarily
    // between two rows, silently. Asserted as an equality against the index's
    // own predicate, which is the thing that makes the guarantee true.
    expect(new Set(LIVE_STAGE_STATUSES)).toEqual(new Set(liveStageIndexPredicate()));

    // THE CASE SETS, which are per CALL SITE because `markResolved` takes them
    // as a parameter. Exactly three, each admitting more than one status —
    // which is what makes the scan above classify the statement as owing a
    // `from` in the first place.
    const sites = markResolvedSites();
    expect(sites).toHaveLength(3);
    for (const site of sites) {
      expect(site.froms.length).toBeGreaterThan(1);
      for (const status of site.froms) {
        expect(ddlStatuses('settlement_cases')).toContain(status);
      }
    }

    // THE CLOSE SET, pinned to the identifier the call site passes rather than
    // to a copy of its members: `ADMINISTRABLE` is `ADMINISTRABLE_STATUSES`,
    // and if the call site is ever handed a literal instead this reddens.
    const admin = readFileSync(join(SRC, 'admin.service.ts'), 'utf8');
    expect(admin).toContain("advanceStatus(tx, caseId, ADMINISTRABLE, 'closed')");
    expect(admin).toContain('const ADMINISTRABLE: readonly CaseStatus[] = ADMINISTRABLE_STATUSES;');
    expect(ADMINISTRABLE_STATUSES.length).toBeGreaterThan(1);
  });

  it('DRIVES both live statuses a stage can be revoked from', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCaseFor(h);

    // A REQUEST WITHDRAWN BEFORE IT WAS ANSWERED. Every one of the eight
    // `revokeStage` call sites in this package revoked an APPROVED stage, so
    // this edge had no coverage anywhere in the repository — which is the
    // shape of the defect: the arm nobody drives is the arm the trail cannot
    // distinguish.
    const pending = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.revokeStage(OPERATOR, SESSION, pending.stageId);

    const granted = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, granted.stageId, 'approve');
    await h.admin.revokeStage(OPERATOR, SESSION, granted.stageId);

    const froms = fromsFor(h, 'settlement.stage.revoked');
    // The SET, and the LENGTH beside it: two rows both reading `approved`
    // would satisfy a set comparison on its own while the `requested` arm went
    // unrecorded.
    expect(froms).toHaveLength(2);
    expect(new Set(froms)).toEqual(new Set(LIVE_STAGE_STATUSES));
  });

  it('DRIVES both statuses an operator can reject a case from', async () => {
    const early = caseHarness();
    const underReview = await reportedCase(early);
    await early.service.startReview(OPERATOR, SESSION, underReview);
    await early.service.decideReview(OPERATOR, SESSION, underReview, {
      decision: 'reject',
      reason: 'insufficient_evidence',
    });

    // The one that costs the owner something: the account has been locked in
    // `deceased_pending` and the documents frozen since approval.
    const late = caseHarness();
    const waiting = await reportedCase(late);
    await late.service.startReview(OPERATOR, SESSION, waiting);
    await late.service.decideReview(OPERATOR, SESSION, waiting, { decision: 'approve' });
    await late.service.decideReview(OPERATOR, SESSION, waiting, {
      decision: 'reject',
      reason: 'fraud_suspected',
    });

    const froms = [
      ...fromsFor(early, 'settlement.case.rejected'),
      ...fromsFor(late, 'settlement.case.rejected'),
    ];
    expect(froms).toHaveLength(2);
    expect(new Set(froms)).toEqual(new Set(rejectFroms()));
  });

  it('DRIVES every status a case can be voided from, across BOTH routes', async () => {
    const froms: string[] = [];

    // The owner's kill switch: three statuses, and `via: 'owner_route'`.
    for (const stage of ['reported', 'verifying', 'waiting_period'] as const) {
      const h = caseHarness();
      const caseId = await reportedCase(h);
      if (stage !== 'reported') {
        await h.service.startReview(OPERATOR, SESSION, caseId);
      }
      if (stage === 'waiting_period') {
        await h.service.decideReview(OPERATOR, SESSION, caseId, { decision: 'approve' });
      }
      // Driven to the status this iteration claims, not assumed into it.
      expect(h.cases.rows.get(caseId)?.status).toBe(stage);
      await h.service.void(DECEDENT, SESSION, caseId);
      froms.push(...fromsFor(h, 'settlement.case.voided'));
    }

    // The liveness re-check, `via: 'liveness_check'`, from `waiting_period`:
    // the owner stepped up during the wait, so nothing was ever verified.
    const alive = caseHarness();
    const aliveCase = await reportedCase(alive);
    await alive.service.startReview(OPERATOR, SESSION, aliveCase);
    await alive.service.decideReview(OPERATOR, SESSION, aliveCase, { decision: 'approve' });
    pastTheWait(alive, aliveCase);
    alive.identity.livenessAnswer = {
      status: 'deceased_pending',
      lastStepUpAt: new Date(alive.clock.value.getTime() - 1000),
    };
    await expect(
      alive.service.confirmVerification(OPERATOR, SESSION, aliveCase),
    ).rejects.toMatchObject({ response: { error: 'owner_alive' } });
    froms.push(...fromsFor(alive, 'settlement.case.voided'));

    // ...and from `verified`, WHICH IS THE EDGE NO CALLER COULD HAVE REPORTED.
    // Liveness read no step-up, so `markVerified` moved the row to `verified`
    // inside this transaction; identity's watermarked interlock then refused
    // the lock and the verification unwound through the same `markResolved`.
    // The status the service READ before all of that is `waiting_period` — the
    // method admits nothing else — so a pre-read here records a `from` that
    // never happened, in the arm where a living owner came one commit from
    // being locked into their own estate settlement.
    const raced = caseHarness();
    const racedCase = await reportedCase(raced);
    await raced.service.startReview(OPERATOR, SESSION, racedCase);
    await raced.service.decideReview(OPERATOR, SESSION, racedCase, { decision: 'approve' });
    pastTheWait(raced, racedCase);
    raced.identity.livenessAnswer = { status: 'deceased_pending', lastStepUpAt: null };
    raced.identity.raceStepUpAt = new Date(raced.clock.value.getTime());
    await expect(
      raced.service.confirmVerification(OPERATOR, SESSION, racedCase),
    ).rejects.toMatchObject({ response: { error: 'owner_alive' } });
    // The unwind really happened — without this the assertion below would pass
    // on a run where the interlock never fired and nothing was voided.
    expect(raced.cases.rows.get(racedCase)?.verified_at).toBeNull();
    expect(raced.cases.rows.get(racedCase)?.resolution).toBe('owner_voided');
    froms.push(...fromsFor(raced, 'settlement.case.voided'));

    expect(froms).toHaveLength(5);
    expect(new Set(froms)).toEqual(new Set(voidFroms()));
    // Named, because it is the one the pre-read would have got wrong and the
    // one a reader should be able to find.
    expect(froms).toContain('verified');
  });

  it('DRIVES all three statuses a case can be closed from', async () => {
    const froms: string[] = [];

    // Closed having approved nothing and paid nothing.
    const bare = buildAdminHarness();
    const bareCase = await verifiedCaseFor(bare);
    await bare.admin.closeCase(OPERATOR, SESSION, bareCase);
    froms.push(...fromsFor(bare, 'settlement.case.closed'));

    // Closed after access was granted but no distribution recorded.
    const active = buildAdminHarness();
    const activeCase = await verifiedCaseFor(active);
    const stage = await active.admin.requestStage(EXECUTOR, SESSION, activeCase, 'inventory');
    await active.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    await active.admin.closeCase(OPERATOR, SESSION, activeCase);
    froms.push(...fromsFor(active, 'settlement.case.closed'));

    // Closed after paying out — `closeCase` refuses while any distribution is
    // still open, so this one has to be driven all the way to `completed`.
    const paid = buildAdminHarness();
    const paidCase = await verifiedCaseFor(paid);
    const dist = await paid.admin.recordDistribution(EXECUTOR, SESSION, paidCase, {
      beneficiaryContactId: randomUUID(),
      amount: '100.00',
    });
    await paid.admin.approveDistribution(OPERATOR, SESSION, dist.distributionId);
    await paid.admin.setDistributionStatus(EXECUTOR, SESSION, dist.distributionId, 'in_progress');
    await paid.admin.setDistributionStatus(EXECUTOR, SESSION, dist.distributionId, 'completed');
    await paid.admin.closeCase(OPERATOR, SESSION, paidCase);
    froms.push(...fromsFor(paid, 'settlement.case.closed'));

    expect(froms).toHaveLength(3);
    expect(new Set(froms)).toEqual(new Set(ADMINISTRABLE_STATUSES));
  });

  it('a terminal statement that LOST refuses, and puts nothing on the trail', async () => {
    /*
     * The M49 PR1 rung test's sibling, and the same honest reading applies:
     * this arm is unreachable today. `decideReview` holds the case row through
     * `lockById`'s `SELECT … FOR UPDATE` and has already narrowed the status to
     * the two `markResolved` compares against, so the compare-and-set matches
     * by construction and a second transaction blocks rather than interleaves.
     *
     * IT PINS A SPECIFICATION. The emit's precondition is the WRITE, not the
     * read above it — so the trail says a case was rejected exactly when this
     * statement rejected it, and stays right if the locking ever moves. To pin
     * that, the test has to manufacture the interleaving the lock forbids: the
     * racer runs an IDENTICAL compare-and-set that wins first, so ours answers
     * null through the real predicate rather than through a stub pretending to.
     */
    const h = caseHarness();
    const caseId = await reportedCase(h);
    await h.service.startReview(OPERATOR, SESSION, caseId);

    const real = h.cases.markResolved.bind(h.cases);
    h.cases.markResolved = async <S extends CaseStatus>(
      tx: Parameters<typeof real>[0],
      id: string,
      froms: readonly S[],
      resolution: 'operator_rejected' | 'owner_voided',
      at: Date,
      reviewer: { id: string; at: Date } | null,
    ): Promise<S | null> => {
      await real(tx, id, froms, resolution, at, reviewer);
      return real(tx, id, froms, resolution, at, reviewer);
    };

    await expect(
      h.service.decideReview(OPERATOR, SESSION, caseId, {
        decision: 'reject',
        reason: 'other',
      }),
    ).rejects.toMatchObject({ response: { error: 'invalid_transition' } });

    // The case WAS resolved — by the racer, not by this call. Without this the
    // test would pass on a run where nothing happened at all.
    expect(h.cases.rows.get(caseId)?.status).toBe('rejected_fraud');
    // ...and this caller, which resolved nothing, claimed nothing.
    expect(fromsFor(h, 'settlement.case.rejected')).toEqual([]);
  });

  it('every recorded `from` is a status the DDL admits — which a double answering `true` is not', async () => {
    /*
     * THE DOUBLE IS THE HOLE THIS CLOSES. `InMemoryCases` and `InMemoryStages`
     * reach the service through a structural check, so they are type-checked
     * — but `markResolved` and `revoke` used to answer a BOOLEAN, and a double
     * left answering one would satisfy every `=== null` guard in the service
     * and put `true` on the audit event. `AuditEventSchema.detail` accepts a
     * boolean as a scalar, so the emit would succeed, the trail would carry
     * `from: true` on a permanent record, and nothing else in this package
     * would notice.
     *
     * Asserting membership of the table's own vocabulary is what makes that
     * visible, and it is derived from the migration rather than from the union
     * type — for the reason the describe above gives: a type is a rename away
     * from agreeing with anything.
     *
     * ITS REACH IS MEMBERSHIP, AND ONLY MEMBERSHIP. A `from` reporting the
     * POST-update status passes here — `revoked` and `closed` are both in
     * their tables' vocabularies — and that is measured, not assumed. The
     * DRIVES tests are what catch that; this one catches a value from outside
     * the vocabulary entirely, which is the shape an unfaithful double emits.
     */
    const h = buildAdminHarness();
    const caseId = await verifiedCaseFor(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    await h.admin.revokeStage(OPERATOR, SESSION, stage.stageId);
    await h.admin.closeCase(OPERATOR, SESSION, caseId);

    const owner = caseHarness();
    const ownerCase = await reportedCase(owner);
    await owner.service.void(DECEDENT, SESSION, ownerCase);

    // THE FOURTH ACTION, and it is here because the sentence above says "every
    // recorded `from`". `settlement.case.rejected` takes its value from the
    // same `markResolved` as `caseVoided`, so nothing was unprotected — but a
    // corpus of three under a claim of four is the shape this repo goes green
    // on for exactly the reason it is wrong.
    const reject = caseHarness();
    const rejectCase = await reportedCase(reject);
    await reject.service.startReview(OPERATOR, SESSION, rejectCase);
    await reject.service.decideReview(OPERATOR, SESSION, rejectCase, {
      decision: 'reject',
      reason: 'other',
    });

    const recorded: Array<{ action: string; from: unknown; vocabulary: string[] }> = [
      ...fromsFor(h, 'settlement.stage.revoked').map((from) => ({
        action: 'settlement.stage.revoked',
        from,
        vocabulary: ddlStatuses('settlement_access_stages'),
      })),
      ...fromsFor(h, 'settlement.case.closed').map((from) => ({
        action: 'settlement.case.closed',
        from,
        vocabulary: ddlStatuses('settlement_cases'),
      })),
      ...fromsFor(owner, 'settlement.case.voided').map((from) => ({
        action: 'settlement.case.voided',
        from,
        vocabulary: ddlStatuses('settlement_cases'),
      })),
      ...fromsFor(reject, 'settlement.case.rejected').map((from) => ({
        action: 'settlement.case.rejected',
        from,
        vocabulary: ddlStatuses('settlement_cases'),
      })),
    ];
    // Anti-vacuity: an empty list would agree with the loop below. And the SET
    // of actions, not just the count — one action contributing two rows while
    // another contributed none preserves any total.
    expect(recorded).toHaveLength(4);
    expect(new Set(recorded.map((r) => r.action))).toEqual(
      new Set([
        'settlement.stage.revoked',
        'settlement.case.closed',
        'settlement.case.voided',
        'settlement.case.rejected',
      ]),
    );
    for (const row of recorded) {
      expect({ action: row.action, admitted: row.vocabulary.includes(row.from as string) }).toEqual(
        {
          action: row.action,
          admitted: true,
        },
      );
    }
  });
});
