/**
 * THREE WAYS THE OPERATOR GATE CAN DRIFT BACK, all closed by scanning source.
 *
 * 1. A FIFTH ADMISSION PATH. Before M21 PR2 this service asked "is this caller
 *    an operator?" at SEVEN call sites in four distinct shapes — two
 *    byte-identical private methods, a bare branch inside `assertCaseVisible`,
 *    an inline disjunction in `setDistributionStatus`, and three more direct
 *    reads feeding a value (`addEvidence`, `getCase`, `evidenceReadAuthority`)
 *    — and they had already drifted about WHICH DATABASE HANDLE to ask on. One
 *    behaviour with several spellings is the M8 PR2 shape. `OperatorGate` is
 *    the one spelling now, and this fence is what keeps it one.
 *
 * 2. THE HANDLE DRIFTING BACK TO THE POOL. Six of those seven asked the pool
 *    and one asked its own transaction, so the convention (a caller that owns a
 *    transaction asks inside it) is declared as data here rather than left as a
 *    habit. The five pool reads are the ones with no transaction to be
 *    consistent with, each named with its reason.
 *
 * 3. A BOOLEAN LITERAL REACHING CEDAR. `assertCan`'s second argument is the
 *    `isSettlementOperator` attribute the policy matches on. Three call sites
 *    passed a hardcoded `true`, which was correct only because an assertion had
 *    run a few lines above — delete that line and the route opened to anyone
 *    while the policy went on evaluating happily against a constant asserting
 *    the very thing nobody had checked. A measured value cannot do that.
 *
 * WHY A SOURCE SCAN. All three are facts about WHERE something is written:
 * there is no runtime seam that distinguishes a sanctioned read of the
 * allowlist from an unsanctioned one, because they call the same method on the
 * same class. The vault-crypto zero-dependency-fence precedent — reading files
 * creates no package edge.
 *
 * WHAT THE FIRST VERSION OF THIS FILE GOT WRONG, kept as the reason the
 * mechanics below look the way they do. Its header claimed the corpus was
 * recursive; only the FIRST of its three blocks used the recursive walk, while
 * the other two read a single hardcoded filename and a hardcoded two-file list.
 * It anchored the reader check on the PROPERTY NAME a caller had chosen
 * (`operators.isOperator`), which a rename evades. And its Cedar check asserted
 * the argument was SPELLED `isOperator` rather than that it was MEASURED, so
 * `const isOperator = true` — or a brand-new route with no gate call at all —
 * passed green. Every one of those is a rule this repository had already
 * written down (docs/03 §6y; the 2026-07-28 and 2026-08-12 entries on anchoring
 * a fence on what the RUNTIME reads, never on the identifier a caller chose),
 * and the file that cited them broke all three. So: ONE recursive corpus, split
 * into methods ONCE, and every assertion below runs over that.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, sep } from 'node:path';

const SRC = join(__dirname, '..', 'src');

/** The one module allowed to consult the allowlist. */
const GATE = 'operator-gate.ts';

/** The repo that owns the SQL. The gate is its only caller. */
const REPO = 'operators.repo.ts';

/** The table itself, for the raw-SQL half of "exactly one reader". */
const TABLE = 'settlement_operators';

/**
 * Sites where a boolean LITERAL is deliberately handed to Cedar, each with the
 * reason. Declared as data rather than argued in a comment, so adding one is a
 * visible decision — the credential-graph habit.
 *
 * Only `false` is ever declarable. There is no legitimate reason to ASSERT
 * operator-ness to a policy without having measured it, which is precisely the
 * defect this fence exists to prevent.
 */
const DECLARED_FALSE: ReadonlyArray<{ readonly action: string; readonly why: string }> = [
  {
    action: 'void',
    why: "The owner's kill switch. The owner is evaluated purely as the decedent; measuring the allowlist would WIDEN the decision for an owner who is also an operator.",
  },
  {
    action: 'manage',
    why: "The owner's own settings. Same reasoning as `void`.",
  },
];

/**
 * The ONLY methods that may consult the gate on the connection pool.
 *
 * Everything else passes its own `tx`, so the allowlist answer and the row it
 * authorizes come from one handle. These own no transaction — all but one are
 * reads, and `reportProviderSignal`'s write happens inside `insertCase`, a
 * helper shared with the trusted-contact path whose gate is the linked-contact
 * check rather than the allowlist.
 *
 * No count in this sentence, deliberately: the assertion below derives one and
 * a number in the prose beside it is a second copy free to drift (M21 PR2.5).
 *
 * Declared with a reason each, because "which handle" is exactly what the seven
 * replaced call sites had already drifted about, and a convention nobody checks
 * is how it drifts again.
 */
const DECLARED_POOL_READS: ReadonlyArray<{ readonly method: string; readonly why: string }> = [
  {
    method: 'reportProviderSignal',
    why: 'Owns no transaction; insertCase opens its own, shared with the trusted-contact path.',
  },
  {
    method: 'getCase',
    why: 'A read. The case row was already fetched on the pool above it.',
  },
  {
    method: 'queue',
    why: 'A read with no transaction: it lists open cases and writes nothing, so there is no row for the answer to be consistent with.',
  },
  {
    method: 'administrable',
    why: 'The post-verification worklist (M21 PR3b) — the queue argument verbatim: a listing owns no transaction, so there is no row for the allowlist answer to be consistent with.',
  },
  {
    method: 'evidenceReadAuthority',
    why: 'A read; answers a peer service a question rather than authorizing a write.',
  },
  {
    method: 'assertCaseVisible',
    why: 'A read helper; the case row was already fetched on the pool above it.',
  },
];

function walk(dir: string, prefix = ''): Array<{ file: string; text: string }> {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) return walk(join(dir, entry.name), rel);
    return entry.name.endsWith('.ts')
      ? [{ file: rel, text: readFileSync(join(dir, entry.name), 'utf8') }]
      : [];
  });
}

/**
 * Both masks are LENGTH-PRESERVING, and that is load-bearing rather than
 * tidy: this file slices two views of the same file at ONE set of offsets (a
 * method's calls come from the masked view, its Cedar action from the view
 * that still has string literals). The first version shortened one view and
 * not the other, so every offset past the first string literal was wrong —
 * which silently lost an `assertCan` call and credited another to the wrong
 * method. It was caught by this file's own count assertion, which is the
 * argument for having one.
 */
function blank(s: string): string {
  return s.replace(/[^\n]/g, ' ');
}

/** Comments masked, string literals KEPT (Cedar actions are string literals). */
function stripComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/(^|[^:])\/\/[^\n]*/g, (m, lead: string) => lead + blank(m.slice(lead.length)));
}

/** Comments AND string literals masked, so a mention is a call. */
function code(text: string): string {
  return stripComments(text)
    .replace(/`(?:\\[\s\S]|[^\\`])*`/g, (m) => '`' + blank(m.slice(2)) + '`')
    .replace(/'(?:\\.|[^\\'])*'/g, (m) => "'" + blank(m.slice(2)) + "'")
    .replace(/"(?:\\.|[^\\"])*"/g, (m) => '"' + blank(m.slice(2)) + '"');
}

/**
 * Class members at two-space indent, in every form TypeScript admits here:
 * modifiers in any order, `async`, generics, getters, and arrow properties.
 *
 * The first version matched only `[private ][async ]name(`, so a `public`,
 * `static`, `override` or generic method was INVISIBLE and its calls were
 * credited to whichever method happened to be declared above it. A fence that
 * mis-attributes is worse than one that finds nothing, because it still goes
 * green — so anything this cannot attribute is a hard failure below, never a
 * skip.
 */
const MEMBER =
  /^ {2}(?:(?:public|private|protected|readonly|static|override|abstract|declare)\s+)*(?:(?:async|get|set)\s+)?([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*[(=]/gm;

type Method = { file: string; method: string; body: string; raw: string };

/**
 * Every source file, split into its class members ONCE. Both views are carried
 * per method: `body` has strings blanked (a mention is a call) and `raw` keeps
 * them (the Cedar action is a string literal).
 */
function methodsOf(file: string, text: string): Method[] {
  const stripped = stripComments(text);
  const blanked = code(text);
  const marks: Array<{ at: number; name: string }> = [];
  MEMBER.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MEMBER.exec(blanked)) !== null) marks.push({ at: m.index, name: m[1] as string });
  return marks.map((mark, i) => {
    const end = i + 1 < marks.length ? (marks[i + 1] as { at: number }).at : blanked.length;
    return {
      file,
      method: mark.name,
      body: blanked.slice(mark.at, end),
      raw: stripped.slice(mark.at, end),
    };
  });
}

const files = walk(SRC).map(({ file, text }) => ({ file, text, blanked: code(text) }));
const methods = files.flatMap((f) => methodsOf(f.file, f.text));

/** A call this fence could not attribute to a method is a hard failure. */
function unattributed(pattern: RegExp): string[] {
  const out: string[] = [];
  for (const f of files) {
    const inFile = (f.blanked.match(pattern) ?? []).length;
    const inMethods = methods
      .filter((mm) => mm.file === f.file)
      .reduce((n, mm) => n + (mm.body.match(pattern) ?? []).length, 0);
    if (inFile !== inMethods) out.push(`${f.file}: ${inFile} in file, ${inMethods} attributed`);
  }
  return out;
}

describe('the operator allowlist has exactly one reader', () => {
  it('scans a real corpus, and the whole of it (anti-vacuity)', () => {
    expect(files.length).toBeGreaterThanOrEqual(20);
    expect(files.map((f) => f.file)).toEqual(
      expect.arrayContaining([GATE, REPO, 'settlement.service.ts', 'admin.service.ts']),
    );
    const truth = readdirSync(SRC, { recursive: true, encoding: 'utf8' })
      .filter((f) => f.endsWith('.ts'))
      .map((f) => f.split(sep).join('/'))
      .sort();
    expect(files.map((f) => f.file).sort()).toEqual(truth);
  });

  it('splits that corpus into methods, and attributes every gate call', () => {
    // The whole file rests on this: every assertion below reasons per method,
    // so a call the splitter cannot see is a call no rule applies to.
    expect(methods.length).toBeGreaterThanOrEqual(80);
    expect(unattributed(/this\.gate\.(?:is|assertIn)\(/g)).toEqual([]);
    expect(unattributed(/this\.authz\.assertCan(?:OrNotFound)?\(/g)).toEqual([]);
  });

  it('only the gate calls OperatorsRepo.isOperator — anchored on the TYPE', () => {
    // NOT on the property name. A field is a caller's choice and can be renamed
    // into invisibility, which is how the credential graph went blind twice
    // (2026-07-28, 2026-08-07) and how the route-audience fence did (2026-08-12).
    // Every field DECLARED as an OperatorsRepo is found first, and then no file
    // but the gate may call `.isOperator(` on any of their names — so a rename
    // is followed rather than evaded.
    //
    // HOLDING the repo is legitimate elsewhere: operator-cli.ts constructs one
    // to grant/revoke/list (PR1's write path). What is fenced is the READ.
    const holders = files.flatMap((f) =>
      [...f.blanked.matchAll(/([A-Za-z_$][\w$]*)\s*:\s*OperatorsRepo\b/g)].map((mm) => ({
        file: f.file,
        field: mm[1] as string,
      })),
    );
    expect(holders.length).toBeGreaterThanOrEqual(1);
    expect(holders.map((h) => h.file)).toEqual(expect.arrayContaining([GATE]));

    for (const h of holders) {
      const call = new RegExp(`\\b${h.field}\\s*\\.\\s*isOperator\\s*\\(`);
      expect({
        field: h.field,
        callers: files.filter((f) => call.test(f.blanked)).map((f) => f.file),
      }).toEqual({ field: h.field, callers: [GATE] });
    }
  });

  it('the gate really does call it (the fence is not vacuous)', () => {
    // Without this, the assertion above is satisfied by a gate that calls
    // NOTHING — and every caller would be admitting on a hardcoded answer.
    const gate = files.find((f) => f.file === GATE) as { blanked: string };
    expect(/\.\s*isOperator\s*\(/.test(gate.blanked)).toBe(true);
  });

  it('nobody reads the table in raw SQL either', () => {
    // The type-anchored scan above sees calls through the repo. It cannot see a
    // method that skips the repo entirely — which is exactly what the CLI used
    // to do before PR1 (see operator-write-path.spec.ts, whose SQL scan covers
    // INSERT/UPDATE/DELETE only, writes having been PR1's subject).
    const read = new RegExp(`\\bFROM\\s+${TABLE}\\b`, 'i');
    const raw = walk(SRC).map(({ file, text }) => ({ file, text: stripComments(text) }));
    expect(raw.filter((f) => read.test(f.text)).map((f) => f.file)).toEqual([REPO]);
  });

  it('no service declares its own assertOperator any more', () => {
    // The two byte-identical private copies M21 PR2 deleted. A third would be
    // invisible to the scans above, because it would call the gate — so the
    // NAME is fenced as well as the read.
    const declared = methods
      .filter((mm) => mm.file !== GATE && mm.method === 'assertOperator')
      .map((mm) => mm.file);
    expect(declared).toEqual([]);
  });
});

describe('Cedar is handed a MEASURED operator value, never a literal', () => {
  /**
   * Every `assertCan(subject, <operatorArg>, '<action>', …)`, per method —
   * INCLUDING `assertCanOrNotFound`, the variant whose deny answers the
   * uniform 404. Both are PEP entry points taking the same operator attribute,
   * so a rule that covered only one would be evaded by choosing the other.
   */
  function calls(): Array<{ file: string; method: string; arg: string; action: string }> {
    const out: Array<{ file: string; method: string; arg: string; action: string }> = [];
    for (const mm of methods) {
      const re = /assertCan(?:OrNotFound)?\(\s*[^,]+?\s*,\s*([^,]+?)\s*,\s*'([a-z_]+)'\s*,/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(mm.raw)) !== null) {
        out.push({
          file: mm.file,
          method: mm.method,
          arg: (m[1] as string).trim(),
          action: m[2] as string,
        });
      }
    }
    return out;
  }

  it('finds every assertCan call, in every file (anti-vacuity)', () => {
    // A scan that silently matched none would agree with every assertion below.
    const found = calls();
    expect(found.length).toBeGreaterThanOrEqual(7);
    const declaredTotal = files.reduce(
      (n, f) => n + (f.blanked.match(/this\.authz\.assertCan(?:OrNotFound)?\(/g) ?? []).length,
      0,
    );
    expect(found.length).toBe(declaredTotal);
  });

  it('NEVER passes `true` — the defect M21 PR2 removed', () => {
    expect(calls().filter((c) => c.arg === 'true')).toEqual([]);
  });

  it('passes `false` ONLY at declared owner-path sites, each with a reason', () => {
    const actual = calls()
      .filter((c) => c.arg === 'false')
      .map((c) => c.action)
      .sort();
    expect(actual).toEqual(DECLARED_FALSE.map((d) => d.action).sort());
    for (const d of DECLARED_FALSE) {
      expect(d.why.length).toBeGreaterThan(40);
    }
  });

  it('every other argument is BOUND BY A GATE CALL IN THE SAME METHOD', () => {
    // The property, at last. The first version of this fence asserted the
    // argument was SPELLED `isOperator`, which is a claim about a name and not
    // about where the value came from — so `const isOperator = true` beside a
    // discarded gate call passed, and so did a brand-new route with no gate
    // call at all. Provenance is what makes removing the check remove the
    // argument, which is the whole reason `assertIn` returns a value.
    const literals = new Set(['true', 'false']);
    const measured = calls().filter((c) => !literals.has(c.arg));
    expect(measured.length).toBeGreaterThanOrEqual(4);
    for (const c of measured) {
      expect(c.arg).toMatch(/^[A-Za-z_$][\w$]*$/);
      const owner = methods.find((mm) => mm.file === c.file && mm.method === c.method) as Method;
      const bound = new RegExp(`\\b${c.arg}\\s*=\\s*await\\s+this\\.gate\\.(?:is|assertIn)\\s*\\(`);
      expect({ method: c.method, arg: c.arg, boundByGate: bound.test(owner.body) }).toEqual({
        method: c.method,
        arg: c.arg,
        boundByGate: true,
      });
    }
  });
});

describe('the handle is a decision, and pool reads are declared', () => {
  /** Every `this.gate.<method>(<handle>, …)` across the WHOLE corpus. */
  function gateCalls(): Array<{ file: string; method: string; handle: string }> {
    const out: Array<{ file: string; method: string; handle: string }> = [];
    for (const mm of methods) {
      const re = /this\.gate\.(?:is|assertIn)\(\s*([A-Za-z_$][\w$.]*)\s*,/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(mm.body)) !== null) {
        out.push({ file: mm.file, method: mm.method, handle: m[1] as string });
      }
    }
    return out;
  }

  it('finds every call (anti-vacuity), and attributes each to a method', () => {
    const found = gateCalls();
    expect(found.length).toBeGreaterThanOrEqual(14);
    const declaredTotal = files.reduce(
      (n, f) => n + (f.blanked.match(/this\.gate\.(?:is|assertIn)\(/g) ?? []).length,
      0,
    );
    expect(found.length).toBe(declaredTotal);
    for (const c of found) expect(c.method).not.toEqual('constructor');
  });

  it('passes `tx` everywhere except the declared pool reads', () => {
    const pool = gateCalls().filter((c) => c.handle !== 'tx');
    expect(pool.map((c) => c.method).sort()).toEqual(
      DECLARED_POOL_READS.map((d) => d.method).sort(),
    );
    for (const c of pool) expect(c.handle).toEqual('this.db');
    for (const d of DECLARED_POOL_READS) expect(d.why.length).toBeGreaterThan(40);
  });

  it('`tx` is the transaction callback parameter, never an alias for the pool', () => {
    // `const tx = this.db` would satisfy the assertion above while asking the
    // pool — the identifier is not the property, so the binding is checked too.
    for (const mm of methods) {
      expect({
        method: mm.method,
        aliasesTx: /\btx\s*(?::[^=]+)?=\s*this\.db\b/.test(mm.body),
      }).toEqual({ method: mm.method, aliasesTx: false });
    }
  });

  it('the transactional callers are the majority, and really do pass tx', () => {
    // Without this, the assertion above is satisfied by a service that has
    // stopped calling the gate transactionally at all.
    expect(gateCalls().filter((c) => c.handle === 'tx').length).toBeGreaterThanOrEqual(9);
  });
});
