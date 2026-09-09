import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { AUDIT_ACTIONS, type AuditAction } from '@estate/contracts';

/**
 * THE ERASURE LADDER'S TRANSITIONS, AGAINST THE EVENTS THAT RECORD THEM
 * (M49 PR5; docs/03 §6kkk -> §6ooo).
 *
 * The defect: `erasure_requests.status` has four transitions and audited ONE.
 * (The second pre-existing member records the INSERT that CREATES the row, not
 * a transition; an earlier draft of this header counted it and said "two".)
 * The claim that begins a destruction, the release that hands one back, and the
 * completion of a legal erasure all moved the row and said nothing. The
 * destructive steps between them are audited by CONSEQUENCE, which is why this
 * looked covered — but a RESUME TAKEN AFTER THE CLOSE AND THE SHRED skips every
 * one of them, so a driver picking up that half-finished erasure could run its
 * whole leg and leave no trace. A resume taken earlier re-runs the leg and
 * emits; how much depends on where the previous driver died.
 *
 * WHAT THIS IS ANCHORED ON, and why each alternative goes green while wrong:
 *
 *   - THE DDL CHECK, not `ErasureRequestStatus`. The database is what the
 *     runtime enforces, and the vocabulary here arrives in TWO files: 014
 *     creates the table admitting two statuses and 015 DROPs that constraint
 *     and re-ADDs it with four. A scan reading only `CREATE TABLE` sees two and
 *     is wrong about the machine it claims to describe — migrations are
 *     append-only and checksummed, so the ALTER form is the ONLY way a status
 *     can ever be added to this table, and therefore the only edit worth
 *     catching.
 *   - THE SQL PREDICATE, not the method name. M49 PR3's rule is that a
 *     statement whose `WHERE` pins ONE prior owes no `from`, and one admitting
 *     more owes one. A fence keyed on `claimDue` gets renamed into
 *     invisibility; a fence keyed on what the statement ASSIGNS does not.
 *   - AN UNREADABLE PREDICATE OWES A `from`. That is the direction that fails
 *     closed: the scan demanding a key it cannot justify is a red test somebody
 *     reads, where a scan excusing what it cannot parse is a green one nobody
 *     does.
 *
 * THE BOUND, STATED (M45's subject, docs/03 §6kkk's last residual). This is
 * keyed on the literal table `erasure_requests` and the literal column
 * `status`. Identity's OTHER lifecycle column, `erasure_domain_progress.state`,
 * is invisible to it — a different spelling of the same idea, in the same
 * migration. There is no repo-wide equivalent, and this file is the third
 * per-service copy of that absence rather than a fix for it.
 *
 * AND IT SCANS `UPDATE` ONLY. `insertIfPermitted` creates the row at the DDL
 * default, so it is not a transition and the four below are the whole ladder —
 * but that is an argument, not a mechanism, and it is why the vocabulary
 * comment says FIVE writing statements where this scan asserts FOUR. An
 * `INSERT ... VALUES ($1, 'executing')` would move the ladder with no
 * `TRANSITION_ACTIONS` entry and a green fence. docs/03 §6ooo records it.
 *
 * THE CLASSIFIER BELOW IS A SECOND SPELLING of settlement's
 * `status-audit-fence.spec.ts`, deliberately and with the debt recorded rather
 * than hidden (docs/03 §6ooo). There is no shared home for a test helper in
 * this workspace and no precedent for a spec importing another service's
 * source; making one is M45's job, not a refactor to smuggle into a PR whose
 * subject is the trail. What is NOT duplicated is the judgement: the rule, the
 * fail-closed direction and the positive-control construction are settlement's,
 * cited here rather than re-argued.
 */

const MIGRATIONS = join(__dirname, '..', 'migrations');
const SRC = join(__dirname, '..', 'src');

/**
 * The values a table's `status` CHECK admits, read from the DDL in file order
 * so that a later `ALTER` wins — which is what running the migrations does.
 *
 * Both constraint styles, because this table uses BOTH: 014 writes the
 * column-level form wrapped across two lines, 015 the `ALTER TABLE … ADD
 * CONSTRAINT` form wrapped across two more. A scan tolerant of only one of
 * them reads this machine as having two statuses.
 */
function ddlStatusesOf(table: string): string[] {
  let found: string[] | null = null;
  const values = (list: string): string[] => {
    const tokens = [...list.matchAll(/'([A-Za-z0-9_]+)'/g)].map((m) => m[1] as string);
    expect(tokens.length).toBeGreaterThan(1);
    return tokens;
  };
  for (const file of readdirSync(MIGRATIONS)
    .filter((f) => f.endsWith('.sql'))
    .sort()) {
    const sql = readFileSync(join(MIGRATIONS, file), 'utf8').replace(/--[^\n]*/g, ' ');
    for (const m of sql.matchAll(/CREATE TABLE (?:IF NOT EXISTS )?(\w+) \(([\s\S]*?)\n\);/g)) {
      if (m[1] !== table) continue;
      const checks = [...(m[2] as string).matchAll(/CHECK \(\s*status IN \(([^)]*)\)\s*\)/g)];
      if (checks.length === 0) continue;
      expect({ table, vocabularies: checks.length }).toEqual({ table, vocabularies: 1 });
      found = values((checks[0] as RegExpMatchArray)[1] as string);
    }
    for (const m of sql.matchAll(
      /ALTER TABLE (\w+)\s+ADD CONSTRAINT \w+\s*CHECK \(\s*status IN \(([^)]*)\)\s*\)/g,
    )) {
      if (m[1] !== table) continue;
      found = values(m[2] as string);
    }
  }
  expect({ table, read: found !== null }).toEqual({ table, read: true });
  return found as string[];
}

interface StatusStatement {
  /**
   * `<table>:<what is assigned to status>` — what the RUNTIME writes, and
   * unique across this ladder's statements. Not the method name, which a
   * rename would hide.
   */
  key: string;
  /** The literal this statement assigns to `status`. */
  target: string;
  /**
   * The one status this statement's from-predicate admits, or `null` when it
   * admits more than one — AND when the predicate cannot be read at all, which
   * is the same answer on purpose.
   */
  only: string | null;
}

/**
 * The one status a predicate admits, or `null` when it admits more, or when
 * this cannot tell.
 *
 * IT COUNTS MENTIONS BEFORE IT READS ONE. Probing for the first
 * `status = '<literal>'` is not a proof that the predicate admits one value: a
 * two-arm `WHERE` such as `(r.status = 'pending' … OR r.status = 'executing'
 * …)` would be classified single-valued by a first-match probe and go green.
 *
 * ON THIS CORPUS THAT BRANCH IS DEAD, AND SAYING SO IS THE POINT. Before this
 * PR the claim's own `WHERE` held exactly that two-arm predicate. This PR
 * moved it into a CTE, so the UPDATE's `WHERE` is now
 * `erasure_requests.id = claimed.claim_id` and mentions no status at all — the
 * claim reaches `null` by the UNREADABLE path below, never by counting two.
 * Same verdict, weaker route, and widening the CTE's arms does not move it.
 * The mention-counting stays for the three statements that DO carry their
 * from-set inline, and for the day the claim's does again. docs/03 §6ooo owns
 * the gap; this docblock used to describe the old SQL in the present tense.
 */
function soleLiteralStatus(predicate: string): string | null {
  const mentions = predicate.match(
    /\b(?:\w+\.)?"?status"?\s*(?:=|<>|!=|\bIS\b|\bIN\b|\bNOT\b|\bANY\b|\bALL\b)/gi,
  );
  if (!mentions || mentions.length !== 1) return null;
  const literal = /\b(?:\w+\.)?"?status"?\s*=\s*'([A-Za-z0-9_]+)'/.exec(predicate);
  return literal ? (literal[1] as string) : null;
}

/**
 * JS comments removed, so template-literal extraction stays in phase.
 *
 * NOT LOAD-BEARING, AND KEPT ANYWAY. This was written for a diagnosis that
 * turned out to be WRONG. The theory was that prose ABOUT SQL, written in
 * backticks, left an ODD number of them before the real literal and so sliced
 * every statement at the wrong boundary. Measured on this tree, every count is
 * EVEN — 10 backticks in the comment above the claim, 54 before the
 * `WITH claimed AS (` literal, 78 in the file — so the pairing was never out
 * of phase. Deleting the call leaves all four statements and all four
 * classifications identical. The real defect was `FOR UPDATE OF r` matching
 * the `UPDATE <table>` head regex; two changes landed in one edit and the
 * wrong one was credited. It is kept as defence in depth, and docs/03 §6ooo
 * records it as not load-bearing rather than as a fix.
 *
 * It is a stripper, not a tokenizer. A `//` inside a string literal, or a backtick inside a regex
 * literal, would still desynchronise it. No such case exists in this service's
 * sources today, and the assertions below are the tripwire if one arrives.
 */
function stripJsComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/**
 * Every statement in this service that writes `erasure_requests.status`.
 *
 * PER TEMPLATE LITERAL, then per UPDATE inside it — never one regex over the
 * whole file. A single scan over a source is how M49 PR4's tombstone check came
 * to report two locks while reading only one: its first match spanned 134 lines
 * and swallowed four `deleted_at IS NULL` clauses belonging to unrelated list
 * queries, so the count was two whether or not either lock filtered anything.
 * Measured here rather than carried over — PR4's own comment rounds it.
 *
 * `FOR UPDATE` IS NOT AN UPDATE, and this fence learned that from its own
 * subject. The claim's CTE takes its row lock with `FOR UPDATE OF r SKIP
 * LOCKED`, which appears BEFORE the statement's real `UPDATE erasure_requests`
 * — so a scan matching the first `UPDATE` in the block read the table name as
 * `OF`, found no `SET`, and dropped the one statement this entire PR is about.
 * It then reported three healthy-looking statements and a set missing a member.
 *
 * THE PARALLEL WITH PR4 IS NOT EXACT, and the difference is worth keeping: PR4's
 * defect PRESERVED a count while mis-attributing it, so only a set comparison
 * could see it. This one DROPS a statement, so the length assertion below would
 * have reddened too. Both are kept; only one of them was needed here.
 *
 * EACH MATCH IS SLICED FROM ITS OWN POSITION rather than captured with a
 * greedy tail, so a literal holding two UPDATEs yields two statements instead
 * of one.
 *
 * SQL LINE COMMENTS GO FIRST TOO: the claim's predicate is wrapped in prose
 * explaining the resume arm, and a comment naming `status = 'pending'` would
 * make the classifier count a mention the engine never evaluates.
 */
function statusWritingStatements(table: string): StatusStatement[] {
  const found: StatusStatement[] = [];
  for (const file of readdirSync(SRC).filter((f) => f.endsWith('.ts'))) {
    const source = stripJsComments(readFileSync(join(SRC, file), 'utf8'));
    for (const block of source.matchAll(/`([^`]*)`/g)) {
      const sql = (block[1] as string).replace(/--[^\n]*/g, ' ');
      const heads = /(?<!\bFOR\s+)\bUPDATE\s+(?:ONLY\s+)?"?([A-Za-z_][\w.]*)"?\b/gi;
      for (const head of sql.matchAll(heads)) {
        if (head[1] !== table) continue;
        const tail = sql.slice(head.index + head[0].length);
        const setAt = /\bSET\b/i.exec(tail);
        if (!setAt) continue;
        const afterSet = tail.slice(setAt.index + setAt[0].length);
        const endOfSet = /\b(FROM|WHERE|RETURNING)\b/i.exec(afterSet);
        const setClause = endOfSet ? afterSet.slice(0, endOfSet.index) : afterSet;
        const assign = /(?:^|,)\s*"?status"?\s*=\s*([^,]+)/i.exec(setClause);
        if (!assign) continue;
        const whereAt = /\bWHERE\b/i.exec(afterSet);
        const predicate = whereAt
          ? (afterSet.slice(whereAt.index).split(/\bRETURNING\b/i)[0] ?? '')
          : '';
        const target = (assign[1] as string).trim().replace(/^'|'$/g, '');
        found.push({ key: `${table}:${target}`, target, only: soleLiteralStatus(predicate) });
      }
    }
  }
  return found;
}

/**
 * The action each transition is recorded under, and whether that emitter
 * carries a prior status — read from the emitters, which is what the runtime
 * publishes.
 *
 * Anchored on the `action:` literal inside each emit object, not on the method
 * name: the method is an identifier a caller chose, the action id is the token
 * the closed vocabulary and every consumer key on.
 */
function erasureEmitters(): Map<string, { carriesFrom: boolean }> {
  const source = readFileSync(join(SRC, 'events.service.ts'), 'utf8');
  const out = new Map<string, { carriesFrom: boolean }>();
  for (const m of source.matchAll(
    /action:\s*'(auth\.account\.erasure_[a-z_]+)'([\s\S]*?)\n {4}\}\);/g,
  )) {
    const body = m[2] as string;
    const detail = /detail:\s*\{([^}]*)\}/.exec(body);
    out.set(m[1] as string, { carriesFrom: detail ? /\bfrom\b/.test(detail[1] as string) : false });
  }
  return out;
}

/**
 * WHICH ACTION RECORDS WHICH TRANSITION — pinned as data, and asserted TOTAL
 * over the derived statement set below.
 *
 * A map rather than a derivation because nothing relates `executing` to
 * `erasure_claimed` except editorial judgement: the action names the ACT and
 * the status names the RESTING PLACE, and TWO of these four disagree on
 * purpose — `claimed` writes `executing`, `released` writes `pending` — while
 * `cancelled` and `completed` use the token verbatim. Freezing that into a naming
 * rule would be a rule this family does not keep. What the fence does enforce
 * is that the map covers every statement the scan finds — so a fifth statement
 * cannot arrive without an entry, and an entry cannot outlive its statement.
 */
const TRANSITION_ACTIONS: Readonly<Record<string, AuditAction>> = {
  cancelled: 'auth.account.erasure_cancelled',
  executing: 'auth.account.erasure_claimed',
  pending: 'auth.account.erasure_released',
  completed: 'auth.account.erasure_completed',
};

describe('every transition the erasure ladder makes is a transition it records', () => {
  it('DERIVES the vocabulary from the DDL, and the later ALTER wins', () => {
    // ANTI-VACUITY AND THE CASE THAT MUST MATCH. 014 admits two statuses and
    // 015 redefines the constraint with four; reading TWO is the failure this
    // proves impossible, and it is the exact failure a CREATE-TABLE-only scan
    // produces. Settlement's fence reads this same table for the same reason,
    // from the other side of the repo.
    expect(ddlStatusesOf('erasure_requests')).toEqual([
      'pending',
      'cancelled',
      'executing',
      'completed',
    ]);
  });

  it('finds every statement that writes the ladder, keyed on what it ASSIGNS', () => {
    const statements = statusWritingStatements('erasure_requests');
    // A SET, not a count: four statements all writing 'completed' would satisfy
    // any count while meaning the ladder had collapsed to one rung.
    expect(new Set(statements.map((s) => s.key))).toEqual(
      new Set([
        'erasure_requests:cancelled',
        'erasure_requests:executing',
        'erasure_requests:pending',
        'erasure_requests:completed',
      ]),
    );
    // ...and no statement is found twice, which a set comparison cannot see.
    expect(statements).toHaveLength(4);
  });

  it('reads each statement’s from-predicate, and only the claim admits more than one prior', () => {
    const byKey = new Map(statusWritingStatements('erasure_requests').map((s) => [s.key, s.only]));
    // THE WHOLE RULE, DERIVED. Three of the four pin exactly one prior in SQL
    // and owe nothing; the claim admits 'pending' OR 'executing' and owes a
    // `from`. Widen any of the three — or make any predicate unreadable — and
    // this map changes and the pairing assertion below turns red.
    expect(Object.fromEntries(byKey)).toEqual({
      'erasure_requests:cancelled': 'pending',
      'erasure_requests:executing': null,
      'erasure_requests:pending': 'executing',
      'erasure_requests:completed': 'executing',
    });
  });

  it('records every transition under an action in the CLOSED vocabulary', () => {
    const targets = statusWritingStatements('erasure_requests').map((s) => s.target);
    // The map is TOTAL over the scan, both ways: a new statement with no entry
    // reddens here, and an entry whose statement was deleted reddens too.
    expect(new Set(Object.keys(TRANSITION_ACTIONS))).toEqual(new Set(targets));
    for (const action of Object.values(TRANSITION_ACTIONS)) {
      expect(AUDIT_ACTIONS).toContain(action);
    }
    // Every action the map names is actually EMITTED. A member of the closed
    // vocabulary with no emitter is the zero-caller surface this repo keeps
    // finding; a map naming one would assert coverage that does not exist.
    // NO EXEMPTIONS. A first draft skipped `erasure_cancelled` here "because it
    // is the owner's half", which was both unnecessary — the scan finds its
    // emitter like any other — and unsound: an exempted action can lose every
    // producer while this stays green. The PR's own review found it.
    const emitted = erasureEmitters();
    for (const action of Object.values(TRANSITION_ACTIONS)) {
      expect([...emitted.keys()]).toContain(action);
    }
  });

  it('carries `from` on EXACTLY the transitions whose predicate admits more than one', () => {
    const statements = statusWritingStatements('erasure_requests');
    const emitted = erasureEmitters();

    // THE TWO HALVES JOINED. Left: the statements the SQL says owe a prior.
    // Right: the emitters that actually carry one. Comparing SETS rather than
    // counts, because "one owes and one carries" is equally true of a fence
    // that paired them the wrong way round.
    const owes = new Set(
      statements
        .filter((s) => s.only === null)
        .map((s) => TRANSITION_ACTIONS[s.target] as AuditAction),
    );
    const carries = new Set(
      [...emitted.entries()].filter(([, v]) => v.carriesFrom).map(([action]) => action),
    );
    expect(carries).toEqual(owes);

    // THE DERIVED POSITIVE CONTROLS, and there are THREE of them. The
    // assertion below names all three but makes no COUNT — it is
    // `arrayContaining`, so a fourth single-prior statement would leave it
    // green; what pins the total is the length assertion on `statements`. `release` and `completion` each pin
    // 'executing' and `cancel` pins 'pending'; none carries a `from`, and each
    // does so for a reason the SCAN read rather than one this file asserts.
    // Widen any of the three predicates to admit a second prior and the sets
    // above disagree. An earlier draft said "two", counting only the driver's
    // own and quietly putting the owner's half outside the fence's reach.
    expect(
      statements.filter((s) => s.only !== null).map((s) => TRANSITION_ACTIONS[s.target]),
    ).toEqual(
      expect.arrayContaining([
        'auth.account.erasure_released',
        'auth.account.erasure_completed',
        'auth.account.erasure_cancelled',
      ]),
    );
    expect(owes).toEqual(new Set(['auth.account.erasure_claimed']));
  });

  it('emits nothing for a compare-and-set that lost — the boolean is READ', () => {
    // M49 PR1's rule, one service over: `advanceStatus` returned a boolean both
    // call sites discarded, so a CAS that lost a race changed nothing and said
    // nothing. Both statements here are compare-and-sets — they pin
    // `status = 'executing'` — so both emits must be conditional.
    //
    // ANCHORED ON THE CALL SITE'S SHAPE, not on a method name: what makes the
    // emit safe is that the repo's answer reaches an `if`, and a refactor that
    // dropped the branch while keeping the name is exactly the regression.
    const service = readFileSync(join(SRC, 'erasure.service.ts'), 'utf8');
    for (const [repoCall, guard, emit] of [
      ['releaseClaim', 'if (released)', 'erasureReleased'],
      ['completeIfAllDone', 'if (completed)', 'erasureCompleted'],
    ] as const) {
      expect(service).toContain(repoCall);
      expect(service).toContain(guard);
      // The emit sits INSIDE that guard's block, not merely somewhere after it.
      const at = service.indexOf(guard);
      const block = service.slice(at, service.indexOf('}', at));
      expect(block).toContain(emit);
    }
  });

  it('states its own reach — the columns this fence cannot see', () => {
    // A fence whose input is narrower than its claim goes green for the same
    // reason it is wrong, so the reach is asserted rather than described. This
    // reads `status`; identity's other lifecycle column is spelled `state`, in
    // the same migration, and is deliberately outside the corpus (M45).
    const sql = readFileSync(join(MIGRATIONS, '015_erasure_execution.sql'), 'utf8');
    expect(sql).toMatch(/state\s+TEXT[\s\S]*?CHECK \(\s*state IN \(/);
    expect(statusWritingStatements('erasure_domain_progress')).toEqual([]);
  });
});
