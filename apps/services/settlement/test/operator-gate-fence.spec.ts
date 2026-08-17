/**
 * TWO WAYS THE OPERATOR GATE CAN DRIFT BACK, both closed by scanning source.
 *
 * 1. A FIFTH ADMISSION PATH. Before M21 PR2 this service asked "is this caller
 *    an operator?" in four separate places — two byte-identical private
 *    methods, a bare branch inside `assertCaseVisible`, and an inline
 *    disjunction in `setDistributionStatus` — and they had already drifted
 *    about WHICH DATABASE HANDLE to ask on. Four spellings of one question is
 *    the M8 PR2 shape. `OperatorGate` is the one spelling now, and this fence
 *    is what keeps it one.
 *
 * 2. THE HANDLE DRIFTING BACK TO THE POOL. The four paths this replaced had
 *    already disagreed about it — three asked the pool and one asked its own
 *    transaction — so the convention (a caller that owns a transaction asks
 *    inside it) is declared as data here rather than left as a habit. The five
 *    pool reads are the ones with no transaction to be consistent with, each
 *    named with its reason.
 *
 * 3. A BOOLEAN LITERAL REACHING CEDAR. `assertCan`'s second argument is the
 *    `isSettlementOperator` attribute the policy matches on. Three call sites
 *    passed a hardcoded `true`, which was correct only because an assertion had
 *    run a few lines above — delete that line and the route opened to anyone
 *    while the policy went on evaluating happily against a constant asserting
 *    the very thing nobody had checked. A measured value cannot do that.
 *
 * WHY A SOURCE SCAN. Both are facts about WHERE something is written: there is
 * no runtime seam that distinguishes a sanctioned read of the allowlist from an
 * unsanctioned one, because they call the same method on the same class. The
 * vault-crypto zero-dependency-fence precedent — reading files creates no
 * package edge.
 *
 * The corpus is RECURSIVE and asserted equal to the platform's own recursive
 * read: `src/` is flat today, so a non-recursive walk would satisfy every other
 * assertion here and quietly stop covering the service the day somebody adds a
 * subdirectory. docs/03 §6y assigns M21 that lesson — a fence whose input is
 * narrower than its claim goes green for the same reason it is wrong.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, sep } from 'node:path';

const SRC = join(__dirname, '..', 'src');

/** The one module allowed to consult the allowlist. */
const GATE = 'operator-gate.ts';

/** The repo that owns the SQL. The gate is its only caller. */
const REPO = 'operators.repo.ts';

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
 * authorizes come from one handle. These five own no transaction — four are
 * reads, and `reportProviderSignal`'s write happens inside `insertCase`, a
 * helper shared with the trusted-contact path whose gate is the linked-contact
 * check rather than the allowlist.
 *
 * Declared with a reason each, because "which handle" is exactly what the four
 * replaced paths had already drifted about, and a convention nobody checks is
 * how it drifts again.
 */
const DECLARED_POOL_READS: ReadonlyArray<{ readonly method: string; readonly why: string }> = [
  {
    method: 'reportProviderSignal',
    why: 'Owns no transaction; insertCase opens its own, shared with the trusted-contact path.',
  },
  { method: 'getCase', why: 'A read. The case row was already fetched on the pool above it.' },
  {
    method: 'queue',
    why: 'A read with no transaction: it lists open cases and writes nothing, so there is no row for the answer to be consistent with.',
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

/** Comments and string literals removed, so a mention is a call. */
function code(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1 ')
    .replace(/`(?:\\[\s\S]|[^\\`])*`/g, '``')
    .replace(/'(?:\\.|[^\\'])*'/g, "''")
    .replace(/"(?:\\.|[^\\"])*"/g, '""');
}

const files = walk(SRC).map(({ file, text }) => ({ file, text: code(text) }));

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

  it('only the gate calls OperatorsRepo.isOperator', () => {
    // `this.operators.isOperator(` on the property name both services used to
    // bind the repo to. The declaration in operators.repo.ts is `async
    // isOperator(` and does not match.
    const call = /\boperators\s*\.\s*isOperator\s*\(/;
    expect(files.filter((f) => call.test(f.text)).map((f) => f.file)).toEqual([GATE]);
  });

  it('the gate really does call it (the fence is not vacuous)', () => {
    // Without this, the assertion above is satisfied by a gate that calls
    // NOTHING — and every caller would be admitting on a hardcoded answer.
    const gate = files.find((f) => f.file === GATE);
    expect(gate).toBeDefined();
    expect(/\boperators\s*\.\s*isOperator\s*\(/.test((gate as { text: string }).text)).toBe(true);
  });

  it('no service declares its own assertOperator any more', () => {
    // The two byte-identical private copies M21 PR2 deleted. A third would be
    // invisible to the scan above, because it would call the gate — so the
    // NAME is fenced as well as the read.
    const declared = files
      .filter((f) => f.file !== GATE && /\bassertOperator\s*\(/.test(f.text))
      .map((f) => f.file);
    expect(declared).toEqual([]);
  });
});

describe('Cedar is handed a measured operator value, never a literal', () => {
  const service = files.find((f) => f.file === 'settlement.service.ts') as { text: string };

  /**
   * Every `assertCan(subject, <operatorArg>, 'action', …)` in the service.
   *
   * Read RAW rather than through `code()`, which blanks string literals — the
   * ACTION is a string literal and is how each call is identified, so a
   * comment-stripped scan would see `''` everywhere and the declared-`false`
   * check would have nothing to key on.
   */
  const RAW = readFileSync(join(SRC, 'settlement.service.ts'), 'utf8');

  function calls(): Array<{ arg: string; action: string }> {
    const out: Array<{ arg: string; action: string }> = [];
    const re = /assertCan\(\s*[^,]+?\s*,\s*([^,]+?)\s*,\s*'([a-z_]+)'\s*,/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(RAW)) !== null) {
      out.push({ arg: (m[1] as string).trim(), action: m[2] as string });
    }
    return out;
  }

  it('finds every assertCan call (anti-vacuity)', () => {
    // Seven today. A scan that silently matched none would agree with any
    // assertion below.
    expect(calls().length).toBeGreaterThanOrEqual(7);
    expect(service.text.split('assertCan(').length - 1).toBe(calls().length);
  });

  it('NEVER passes `true` — the defect M21 PR2 removed', () => {
    // Three sites did: review/start, review and verify. Each was sound only
    // because `assertOperator` had run above it, so deleting one line opened
    // the route while Cedar kept saying yes.
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

  it('every other call passes a resolved variable', () => {
    const literals = new Set(['true', 'false']);
    const variable = calls().filter((c) => !literals.has(c.arg));
    expect(variable.length).toBeGreaterThanOrEqual(4);
    for (const c of variable) {
      expect(c.arg).toMatch(/^isOperator$/);
    }
  });
});

describe('the handle is a decision, and pool reads are declared', () => {
  /**
   * Every `this.gate.<method>(<handle>, …)` in the two services, with the
   * enclosing method resolved from the nearest declaration above it.
   *
   * REFUSES a shape it cannot resolve rather than skipping it: an unattributed
   * call would silently satisfy every assertion below, which is the way a fence
   * goes green for the same reason it is wrong.
   */
  function gateCalls(): Array<{ file: string; method: string; handle: string }> {
    const out: Array<{ file: string; method: string; handle: string }> = [];
    for (const name of ['settlement.service.ts', 'admin.service.ts']) {
      const text = (files.find((f) => f.file === name) as { text: string }).text;
      const re = /this\.gate\.(?:is|assertIn)\(\s*([A-Za-z.]+)\s*,/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const before = text.slice(0, m.index);
        const decl = [
          ...before.matchAll(/^ {2}(?:private\s+)?(?:async\s+)?([A-Za-z_]\w*)\s*\(/gm),
        ].pop();
        if (!decl) throw new Error(`unattributed gate call in ${name} at ${m.index}`);
        out.push({ file: name, method: decl[1] as string, handle: m[1] as string });
      }
    }
    return out;
  }

  it('finds every call (anti-vacuity), and attributes each to a method', () => {
    const calls = gateCalls();
    expect(calls.length).toBeGreaterThanOrEqual(14);
    for (const c of calls) expect(c.method).not.toEqual('constructor');
  });

  it('passes `tx` everywhere except the declared pool reads', () => {
    const pool = gateCalls().filter((c) => c.handle !== 'tx');
    expect(pool.map((c) => c.method).sort()).toEqual(
      DECLARED_POOL_READS.map((d) => d.method).sort(),
    );
    for (const c of pool) expect(c.handle).toEqual('this.db');
    for (const d of DECLARED_POOL_READS) expect(d.why.length).toBeGreaterThan(40);
  });

  it('the transactional callers are the majority, and really do pass tx', () => {
    // Without this, the assertion above is satisfied by a service that has
    // stopped calling the gate transactionally at all.
    expect(gateCalls().filter((c) => c.handle === 'tx').length).toBeGreaterThanOrEqual(9);
  });
});
