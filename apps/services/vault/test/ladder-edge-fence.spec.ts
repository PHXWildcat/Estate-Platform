import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * M49 PR4 — WHICH LADDER EVENTS OWE A PRIOR STATUS, DERIVED.
 *
 * M49 PR3 built the same rule for settlement and derived it from the SQL: a
 * statement whose `WHERE` pins one literal prior status owes nothing, one that
 * admits more owes a `from`, and a predicate the scan cannot READ owes one too,
 * which fails closed. That derivation does not transfer here, and the reason is
 * the finding rather than an inconvenience: EVERY status write in this service
 * is `WHERE id = $1`. There is no predicate to read. Applied unchanged, PR3's
 * scan would say all five statements owe a `from` — fail-closed and wrong,
 * because `markRequested` genuinely admits one prior.
 *
 * SO THIS FENCE DERIVES FROM THE GUARD CHAIN INSTEAD. The vault narrows its
 * priors in TypeScript, above the write, and it does so in exactly three shapes
 * (below). A fourth shape is unreadable and OWES A `from`, which is the same
 * fail-closed direction PR3 chose for the same reason.
 *
 * WHAT IS DERIVED AND WHAT IS NOT, stated because an earlier draft of this
 * paragraph claimed more than the file delivers. Derived: the status
 * vocabulary (from the `CREATE TABLE` body), the writers and their targets
 * (from the runtime SQL), the dead statuses (as a difference), the locks and
 * whether they filter tombstones, the guard shapes, and the writer/emitter
 * pairing. Hand-named: the two FILES this scan reads by name —
 * `emergency.repo.ts` and `emergency.service.ts` — which is a real bound, since
 * a ladder statement moved to a third file would be invisible to the guard-chain
 * half while `statusWriters()` (which reads every `.ts` under `src`) would still
 * see it. The expectations are compared as sets or as keyed objects, never as
 * ordered arrays, so that mis-attribution cannot preserve a passing count.
 */

const SRC = join(__dirname, '..', 'src');
const MIGRATIONS = join(__dirname, '..', 'migrations');

const sourceFiles = (dir: string, ext: string): string[] =>
  readdirSync(dir, { recursive: true, encoding: 'utf8' }).filter((f) => f.endsWith(ext));

const read = (dir: string, file: string): string => readFileSync(join(dir, file), 'utf8');

// --------------------------------------------------------------------------
// 1. THE VOCABULARY, FROM THE DDL
// --------------------------------------------------------------------------

/**
 * The `CREATE TABLE emergency_access_policies (...)` body, and nothing else.
 *
 * Anchored on the TABLE because this fence's claim is about one table: an
 * earlier spelling scanned every migration table-agnostically, which would have
 * silently absorbed a `status` CHECK belonging to some other table into a
 * vocabulary it then reported as this one's. Its own review caught that.
 */
function policyTableBody(): string {
  const bodies: string[] = [];
  for (const file of sourceFiles(MIGRATIONS, '.sql')) {
    for (const m of read(MIGRATIONS, file).matchAll(
      /CREATE TABLE\s+emergency_access_policies\s*\(([\s\S]*?)\n\);/gi,
    )) {
      bodies.push(m[1] as string);
    }
  }
  // Exactly one CREATE TABLE for it, ever. Two would mean the scan is reading a
  // rebuild it does not understand; zero means the anchor has rotted.
  expect(bodies).toHaveLength(1);
  return bodies[0] as string;
}

/** Every literal the `status` CHECK on `emergency_access_policies` admits. */
function ddlStatuses(): string[] {
  const found = new Set<string>();
  // Whitespace-tolerant: M49 PR3's review broke the settlement equivalent with
  // a CHECK body wrapped over three lines, which its regex could not read and
  // which therefore went green.
  const checks = [
    ...policyTableBody().matchAll(
      /status\s+TEXT[^,]*?CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)\s*\)/gis,
    ),
  ];
  expect(checks).toHaveLength(1);
  for (const lit of (checks[0]![1] as string).matchAll(/'([a-z_]+)'/g)) found.add(lit[1] as string);
  return [...found].sort();
}

/** The column DEFAULT, which is a status no UPDATE has to write. */
function ddlDefaultStatus(): string | null {
  const m = /status\s+TEXT\s+NOT\s+NULL\s+DEFAULT\s+'([a-z_]+)'/i.exec(policyTableBody());
  return m ? (m[1] as string) : null;
}

// --------------------------------------------------------------------------
// 2. THE WRITERS, FROM THE RUNTIME SQL
// --------------------------------------------------------------------------

interface Writer {
  /** The repository method the service calls. */
  method: string;
  /** The literal it assigns to `status`. */
  target: string;
  /** Everything between WHERE and RETURNING — the from-predicate, if any. */
  predicate: string;
  /** Whether the same statement also tombstones the row. */
  tombstones: boolean;
}

function statusWriters(): Writer[] {
  const found: Writer[] = [];
  for (const file of sourceFiles(SRC, '.ts')) {
    const source = read(SRC, file);
    // Anchor on the METHOD the service calls, because that is the name the
    // pairing below reads — not on a comment or a variable a rename could hide.
    for (const decl of source.matchAll(/async\s+(\w+)\s*\([\s\S]{0,400}?`([^`]*)`/g)) {
      const method = decl[1] as string;
      const sql = (decl[2] as string).replace(/--[^\n]*/g, ' ');
      const assign =
        /UPDATE\s+emergency_access_policies[\s\S]*?SET\s+([\s\S]*?)(?:\bWHERE\b|\bRETURNING\b|$)/i.exec(
          sql,
        );
      if (!assign) continue;
      const setClause = assign[1] as string;
      const status = /(?:^|,)\s*status\s*=\s*'([a-z_]+)'/i.exec(setClause);
      if (!status) continue;
      const where = /\bWHERE\b([\s\S]*?)(?:\bRETURNING\b|$)/i.exec(sql);
      found.push({
        method,
        target: status[1] as string,
        predicate: (where?.[1] ?? '').trim(),
        tombstones: /\bdeleted_at\s*=/i.test(setClause),
      });
    }
  }
  return found;
}

/**
 * A prior status no ladder method can ever observe, and therefore never report.
 *
 * Derived from two facts in the tree: a writer that also sets `deleted_at`, and
 * locking reads that filter `deleted_at IS NULL`.
 *
 * THE FIRST SPELLING OF THIS DID NOT READ THE LOCKS AT ALL, and five of this
 * PR's review lenses found it independently. It ran
 * `/SELECT[\s\S]*?FROM emergency_access_policies[\s\S]*?FOR UPDATE/` over the
 * whole file, whose first match spanned a hundred and thirty lines and borrowed
 * a `deleted_at IS NULL` from unrelated list queries — so the count was two
 * whether or not either lock filtered anything, and the grantee lock could stop
 * filtering with the fence still green. Statements are extracted ONE AT A TIME
 * now, the shape `revoked-is-unobservable.spec.ts` already uses, and the
 * assertion is a SET of the locks that fail to filter rather than a count of
 * the ones that do — mis-attribution preserves a count.
 */
function policyLocks(): { sql: string; filtersDeleted: boolean }[] {
  const repo = read(SRC, 'emergency.repo.ts');
  return [...repo.matchAll(/`([^`]*)`/g)]
    .map((m) =>
      (m[1] as string)
        .replace(/--[^\n]*/g, ' ')
        .replace(/\s+/g, ' ')
        .trim(),
    )
    .filter(
      (sql) => /\bFOR UPDATE\b/i.test(sql) && /\bFROM\s+emergency_access_policies\b/i.test(sql),
    )
    .map((sql) => ({ sql, filtersDeleted: /\bdeleted_at\s+IS\s+NULL\b/i.test(sql) }));
}

function tombstonedTargets(): string[] {
  return statusWriters()
    .filter((w) => w.tombstones)
    .map((w) => w.target);
}

// --------------------------------------------------------------------------
// 3. THE GUARD CHAIN, FROM THE SERVICE
// --------------------------------------------------------------------------

const SERVICE = read(SRC, 'emergency.service.ts');

/** Split the service into `name -> body`, methods and private helpers alike. */
function serviceMethods(): Map<string, string> {
  const out = new Map<string, string>();
  // SCOPED TO THE SERVICE CLASS. The file declares two classes, and splitting
  // the whole file put `SettlementGateError`'s constructor and the service's
  // own under one key — the collision guard below found that the moment it was
  // added, where the previous spelling silently overwrote one with the other.
  const classAt = SERVICE.indexOf('export class EmergencyAccessService {');
  expect(classAt).toBeGreaterThan(0);
  const body = SERVICE.slice(classAt);
  // The type-parameter list is not optional decoration either:
  // `withSettlementGate<T>(` was invisible to the first spelling, so its body —
  // which contains the release path's refusal emitter — was merged into the
  // PRECEDING method and silently reattributed. A collision throws rather than
  // overwriting, because a member quietly replacing another has no symptom.
  const starts = [
    ...body.matchAll(/^ {2}(?:private\s+)?(?:async\s+)?(\w+)\s*(?:<[^>(]*>)?\s*\(/gm),
  ];
  starts.forEach((m, i) => {
    const from = m.index;
    const to = i + 1 < starts.length ? starts[i + 1]!.index : body.length;
    const name = m[1] as string;
    if (out.has(name)) throw new Error(`two members named ${name} — the splitter is mis-reading`);
    out.set(name, body.slice(from, to));
  });
  return out;
}

type Narrowing =
  | { shape: 'allow'; statuses: string[] }
  | { shape: 'refuse'; statuses: string[] }
  | { shape: 'none' }
  | { shape: 'unreadable' };

/**
 * How a method narrows the prior statuses that reach its write.
 *
 * THE THREE SHAPES THIS TREE CONTAINS, and nothing else is guessed at:
 *
 *   allow  — `const collectable = policy.status === 'a' || policy.status === 'b'`
 *            guarding a throw. The listed statuses are the ONLY ones admitted.
 *   refuse — `if (policy.status === 'x') throw ...` or a helper returning a
 *            refusal token. Everything NOT listed is admitted.
 *   none   — no comparison at all: every live status is admitted.
 *
 * A `policy.status` comparison that is neither guarding a throw nor returning a
 * refusal token is UNREADABLE, and an unreadable guard owes a `from`.
 */
/**
 * The consequent of the first `if` matching `head`, delimited by ITS OWN braces
 * (or by the statement's `;` when it has none) — never by a character count.
 * A fixed window is how both arms of this scan borrowed the NEXT guard's
 * refusal, which is the defect that cost this fence two mutations.
 */
function consequentOf(text: string, head: RegExp): string | null {
  const m = head.exec(text);
  if (!m) return null;
  // Walk the condition's parentheses to their close, so `if (!a || !b)` ends
  // where the condition ends rather than at its first `)`.
  let i = text.indexOf('(', m.index);
  if (i < 0) return null;
  let depth = 0;
  for (; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) break;
  }
  const rest = text.slice(i + 1);
  const brace = /^\s*\{/.exec(rest);
  if (!brace) return rest.slice(0, rest.indexOf(';') + 1 || rest.length);
  const j = rest.indexOf('{');
  depth = 0;
  for (let k = j; k < rest.length; k++) {
    if (rest[k] === '{') depth++;
    else if (rest[k] === '}' && --depth === 0) return rest.slice(j, k + 1);
  }
  return null;
}

function narrowingOf(body: string, helpers: Map<string, string>): Narrowing {
  // Inline one level of private-helper calls, so a guard factored out of the
  // method (`blockReason`) is still read. A guard TWO levels deep is not seen
  // at all and the method reads as `none`, which over-demands a `from` for a
  // different reason than `unreadable` does — the bound is asserted below and
  // recorded as a residual.
  let text = body;
  for (const call of body.matchAll(/this\.(\w+)\(policy\)/g)) {
    const helper = helpers.get(call[1] as string);
    if (helper) text += '\n' + helper;
  }

  const comparisons = [...text.matchAll(/policy\.status\s*===\s*'([a-z_]+)'/g)];

  // The separator is spelled `\s*\|\|\s*` between two REQUIRED comparisons
  // rather than as an optional tail on a repeated group. The first spelling —
  // `(?:CMP\s*(?:\|\|)?\s*)+` — lets a single space between two comparisons be
  // consumed by either `\s*`, which is two parses per repetition and 2^n over
  // the whole list; the trailing `;` then forces the engine to walk all of
  // them. CodeQL's `js/redos` caught it on this PR's own CI. The rewrite is
  // also the TIGHTER read: an allow-list is comparisons joined by `||`, and
  // the old shape matched them juxtaposed with no operator at all.
  const allow =
    /const\s+(\w+)\s*=\s*(policy\.status\s*===\s*'[a-z_]+'(?:\s*\|\|\s*policy\.status\s*===\s*'[a-z_]+')*)\s*;/.exec(
      text,
    );
  if (allow) {
    // The docstring says this shape GUARDS A THROW, so check that rather than
    // trusting it: an allow-list whose negation is not a refusal admits
    // everything, and reading it as a narrowing fails OPEN. Its own review
    // found this arm asserting the negation existed and never the throw.
    //
    // The throw must be inside THAT `if`'s own consequent. A character window
    // was tried and is wrong for the same reason it was wrong on the refuse
    // arm: `release`'s next guard throws `waiting_period_active` a few lines
    // below, so a 200-character lookahead borrowed it and a mutation replacing
    // the real refusal with a `return` stayed green. Found by that mutation.
    const neg = consequentOf(text, new RegExp(`if\\s*\\(\\s*!\\s*${allow[1] as string}\\b`));
    if (neg !== null && /\bthrow\b/.test(neg)) {
      return {
        shape: 'allow',
        statuses: [...(allow[2] as string).matchAll(/'([a-z_]+)'/g)].map((m) => m[1] as string),
      };
    }
    return { shape: 'unreadable' };
  }

  if (comparisons.length === 0) return { shape: 'none' };

  // THE WINDOW ENDS AT THE NEXT COMPARISON, not after a fixed number of
  // characters. A 140-character lookahead was this fence's worst defect and its
  // own review caught it: `blockReason`'s three guards are consecutive
  // one-liners, so each window spilled into the NEXT guard's `return '...'` and
  // a guard that STOPPED refusing was still counted as one. Two faithful
  // spellings of that mutation — `return null` and a bare side effect — went
  // green, and `request` kept an exemption the scan had not actually read.
  const refused: string[] = [];
  for (let i = 0; i < comparisons.length; i++) {
    const c = comparisons[i]!;
    const start = c.index + c[0].length;
    const stop = i + 1 < comparisons.length ? comparisons[i + 1]!.index : text.length;
    if (/\bthrow\b|\breturn\s+'/.test(text.slice(start, stop))) refused.push(c[1] as string);
    else return { shape: 'unreadable' };
  }
  return { shape: 'refuse', statuses: refused };
}

/** Each service method that writes a status: its writer, emitter, and guard. */
interface Site {
  method: string;
  writer: string;
  /** The emitter on the path that does NOT throw — the transition. */
  emitter: string | null;
  /** Emitters on a refusal path, kept visible rather than silently dropped. */
  refusalEmitters: string[];
  passesFrom: boolean;
  narrowing: Narrowing;
}

/**
 * A method may emit more than one action, and taking the FIRST is how a scan
 * gets this wrong: `request` emits `request_blocked` above `requested`, so a
 * first-match pairing reports the refusal as the transition. (It did, on this
 * fence's first run.)
 *
 * The discriminator is in the tree, not in a list: an emitter followed by a
 * `throw` before any other emit is on a REFUSAL path. The transition is the
 * one whose forward span reaches the end of the method without throwing.
 */
function classifyEmitters(body: string): { transition: string | null; refusals: string[] } {
  const emits = [...body.matchAll(/this\.events\.(emergency\w+)\(([\s\S]*?)\);/g)];
  const refusals: string[] = [];
  let transition: string | null = null;
  emits.forEach((e, i) => {
    const start = e.index + e[0].length;
    const end = i + 1 < emits.length ? emits[i + 1]!.index : body.length;
    if (/\bthrow\b/.test(body.slice(start, end))) refusals.push(e[1] as string);
    else if (transition === null) transition = e[1] as string;
  });
  return { transition, refusals };
}

function ladderSites(): Site[] {
  const helpers = serviceMethods();
  const writers = new Set(statusWriters().map((w) => w.method));
  const sites: Site[] = [];
  for (const [method, body] of helpers) {
    const write = [...body.matchAll(/this\.emergency\.(\w+)\(/g)].find((m) =>
      writers.has(m[1] as string),
    );
    if (!write) continue;
    const { transition, refusals } = classifyEmitters(body);
    const emitArgs = transition
      ? (new RegExp(`this\\.events\\.${transition}\\(([\\s\\S]*?)\\);`).exec(body)?.[1] ?? '')
      : '';
    sites.push({
      method,
      writer: write[1] as string,
      emitter: transition,
      refusalEmitters: refusals,
      // `from` is the captured local, not a property read at the top of the
      // method: anchor on the argument the emitter actually receives.
      passesFrom: /\bfrom\b/.test(emitArgs),
      narrowing: narrowingOf(body, helpers),
    });
  }
  return sites;
}

// --------------------------------------------------------------------------

const DDL = ddlStatuses();
const WRITERS = statusWriters();
const SITES = ladderSites();

describe('the vault ladder vocabulary, derived from the DDL and the writers', () => {
  it('reads a corpus big enough to be believed', () => {
    // Anti-vacuity at every LEVEL, not just the total: an empty migrations
    // directory and a clean scan look identical otherwise.
    expect({
      migrations: sourceFiles(MIGRATIONS, '.sql').length >= 8,
      srcFiles: sourceFiles(SRC, '.ts').length >= 15,
      ddlStatuses: DDL.length,
      writers: WRITERS.length,
    }).toEqual({ migrations: true, srcFiles: true, ddlStatuses: 6, writers: 5 });
  });

  it('DERIVES the statuses no statement can produce', () => {
    const written = new Set(WRITERS.map((w) => w.target));
    const dflt = ddlDefaultStatus();
    expect(dflt).toBe('configured');
    const dead = DDL.filter((s) => !written.has(s) && s !== dflt);

    // `requested` is in the CHECK and in `PolicyStatus`, and nothing assigns
    // it. It is dead vocabulary — which matters because a fixture that drove
    // an edge "from requested" would be testing the fixture.
    expect(dead).toEqual(['requested']);
  });

  it('DERIVES the status that is written but can never be a PRIOR', () => {
    const locks = policyLocks();
    // Asserted as a SET of the locks that FAIL to filter, not as a count of the
    // ones that do: a count is what mis-attribution preserves, and the first
    // spelling of this scan reported two while reading neither lock.
    expect({
      tombstoned: tombstonedTargets(),
      lockCount: locks.length,
      notFilteringTombstones: locks.filter((l) => !l.filtersDeleted).map((l) => l.sql),
    }).toEqual({
      tombstoned: ['revoked'],
      lockCount: 2,
      notFilteringTombstones: [],
    });
    // POSITIVE CONTROL on the extractor: it must be able to SAY a lock does not
    // filter. Without this, an extractor that returns `filtersDeleted: true`
    // unconditionally passes the assertion above exactly as a working one does.
    expect(
      /\bdeleted_at\s+IS\s+NULL\b/i.test(
        'SELECT x FROM emergency_access_policies WHERE id = $1 FOR UPDATE',
      ),
    ).toBe(false);
  });

  it('states the prior vocabulary as the difference, not as a list', () => {
    const written = new Set(WRITERS.map((w) => w.target));
    const dead = DDL.filter((s) => !written.has(s) && s !== ddlDefaultStatus());
    const tombstoned = new Set(tombstonedTargets());
    const prior = DDL.filter((s) => !dead.includes(s) && !tombstoned.has(s));
    expect(new Set(prior)).toEqual(
      new Set(['configured', 'waiting', 'denied_by_owner', 'released']),
    );
  });
});

describe('every ladder statement is `WHERE id`, which is why the derivation moved', () => {
  it('finds NO from-predicate in any status write', () => {
    // The load-bearing observation of this PR, asserted rather than described:
    // if a statement ever gains a status predicate, this reddens and the
    // derivation above should move back to the SQL where PR3 put it.
    expect(Object.fromEntries(WRITERS.map((w) => [w.method, w.predicate]))).toEqual({
      markRequested: 'id = $1',
      markDenied: 'id = $1',
      markRearmed: 'id = $1',
      markReleased: 'id = $1',
      markRevoked: 'id = $1',
    });
  });
});

describe('which emitters owe a prior status', () => {
  it('pairs every status writer with exactly one emitter', () => {
    expect(
      Object.fromEntries(
        SITES.map((s) => [
          s.method,
          { writer: s.writer, emitter: s.emitter, refusals: s.refusalEmitters },
        ]),
      ),
    ).toEqual({
      request: {
        writer: 'markRequested',
        emitter: 'emergencyRequested',
        // The refusal that a first-match pairing reported as the transition.
        refusals: ['emergencyRequestBlocked'],
      },
      deny: { writer: 'markDenied', emitter: 'emergencyDenied', refusals: [] },
      rearm: { writer: 'markRearmed', emitter: 'emergencyRearmed', refusals: [] },
      revoke: { writer: 'markRevoked', emitter: 'emergencyRevoked', refusals: [] },
      release: { writer: 'markReleased', emitter: 'emergencyReleased', refusals: [] },
    });
  });

  it('READS each guard chain, and says which shape it read', () => {
    // The exemption is DERIVED: `request` owes nothing because the scan read
    // `blockReason` refusing the other three live statuses, not because this
    // file says so. That is the same construction as `StagesRepo.decide` in
    // settlement's fence — a positive control the scan itself produces.
    expect(Object.fromEntries(SITES.map((s) => [s.method, s.narrowing]))).toEqual({
      request: { shape: 'refuse', statuses: ['released', 'waiting', 'denied_by_owner'] },
      deny: { shape: 'none' },
      rearm: { shape: 'refuse', statuses: ['released'] },
      revoke: { shape: 'none' },
      release: { shape: 'allow', statuses: ['waiting', 'released'] },
    });
  });

  it('DERIVES the obligation, and every site that owes a `from` passes one', () => {
    const written = new Set(WRITERS.map((w) => w.target));
    const dead = DDL.filter((s) => !written.has(s) && s !== ddlDefaultStatus());
    const tombstoned = new Set(tombstonedTargets());
    const prior = DDL.filter((s) => !dead.includes(s) && !tombstoned.has(s));

    const admitted = (n: Narrowing): number => {
      if (n.shape === 'allow') return n.statuses.length;
      if (n.shape === 'refuse') return prior.filter((s) => !n.statuses.includes(s)).length;
      if (n.shape === 'none') return prior.length;
      return Number.POSITIVE_INFINITY; // unreadable owes a `from`
    };

    // Compared as SETS. Mis-attribution preserves a count: a fence that swapped
    // `owes` and `exempt` wholesale would keep both totals.
    expect({
      owes: new Set(SITES.filter((s) => admitted(s.narrowing) > 1).map((s) => s.method)),
      exempt: new Set(SITES.filter((s) => admitted(s.narrowing) === 1).map((s) => s.method)),
      owesButDoesNotPass: SITES.filter((s) => admitted(s.narrowing) > 1 && !s.passesFrom).map(
        (s) => s.method,
      ),
    }).toEqual({
      owes: new Set(['deny', 'rearm', 'revoke', 'release']),
      exempt: new Set(['request']),
      owesButDoesNotPass: [],
    });
  });

  it('classifies a guard shape it cannot READ as owing a `from`', () => {
    // The fail-closed direction, driven. A comparison that neither guards a
    // throw nor returns a refusal token is not evidence of a narrowing, and
    // must not be read as one.
    const helpers = new Map<string, string>();
    expect(narrowingOf(`if (policy.status === 'waiting') { proceed(); }`, helpers)).toEqual({
      shape: 'unreadable',
    });
    expect(narrowingOf(`if (policy.status === 'waiting') throw new Error();`, helpers)).toEqual({
      shape: 'refuse',
      statuses: ['waiting'],
    });
    // POSITIVE CONTROL: the scan is not simply answering `unreadable`.
    expect(narrowingOf(`const x = 1;`, helpers)).toEqual({ shape: 'none' });

    // TWO CONSECUTIVE GUARDS — the case a fixed-width lookahead gets wrong, and
    // the one every single-guard input above is structurally unable to show. A
    // 140-character window let the first guard borrow the second's `return '`,
    // so a guard that STOPPED refusing still read as a refusal. The window ends
    // at the next comparison now.
    expect(
      narrowingOf(
        `if (policy.status === 'a') { record(); }\n    if (policy.status === 'b') return 'nope';`,
        helpers,
      ),
    ).toEqual({ shape: 'unreadable' });
    // ...and its twin, so the boundary is a measurement rather than a matcher
    // that answers `unreadable` whenever it sees two guards.
    expect(
      narrowingOf(
        `if (policy.status === 'a') return 'no';\n    if (policy.status === 'b') return 'nope';`,
        helpers,
      ),
    ).toEqual({ shape: 'refuse', statuses: ['a', 'b'] });

    // The `allow` arm must see the THROW its docstring requires, not merely the
    // negation — an allow-list whose negation refuses nothing admits everything.
    expect(
      narrowingOf(
        `const ok = policy.status === 'a' || policy.status === 'b';\n    if (!ok) log();`,
        helpers,
      ),
    ).toEqual({ shape: 'unreadable' });
    expect(
      narrowingOf(
        `const ok = policy.status === 'a' || policy.status === 'b';\n    if (!ok) throw new Error();`,
        helpers,
      ),
    ).toEqual({ shape: 'allow', statuses: ['a', 'b'] });
  });
});

describe('the verb each action names, against the status its write produces', () => {
  it('PINS the map, including the two that disagree', () => {
    // There is deliberately no `to` key on the wire: five statements, five
    // literal targets, one emitter each, so a `to` would be a second copy of
    // what the action id already determines. The disagreements are recorded
    // HERE instead, as data — `requested` writes `waiting` and `rearmed`
    // writes `configured`. Both are honest names for the ACT; neither names
    // the status. A third disagreement would redden this.
    const byMethod = new Map(WRITERS.map((w) => [w.method, w.target]));
    expect(
      Object.fromEntries(
        SITES.map((s) => [
          s.emitter?.replace(/^emergency/, '').toLowerCase(),
          byMethod.get(s.writer),
        ]),
      ),
    ).toEqual({
      requested: 'waiting',
      denied: 'denied_by_owner',
      rearmed: 'configured',
      revoked: 'revoked',
      released: 'released',
    });
  });
});
