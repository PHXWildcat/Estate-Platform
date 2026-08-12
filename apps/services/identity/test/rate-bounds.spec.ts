/**
 * EVERY GUESSING BOUND'S COVERAGE, AS A FENCE.
 *
 * This is `second-factor-kinds.spec.ts` (M16) generalized to two bounds, and
 * every assertion that file carried has a successor here — the rename is
 * because the old name would have been a test named for a property it no longer
 * measures, which is the shape this repo keeps finding.
 *
 * The defect the original was written to close is what happens when a LIST goes
 * stale: the cap counted `stepup.denied` alone while `POST /v1/auth/totp/verify`
 * checked the same `mfa_methods` row with no cap at all, so forty wrong codes
 * there produced forty 401s, never a 429, and left the counter at zero. Nothing
 * related the SET to the routes that write into it.
 *
 * M17 adds the failure mode a second bound makes possible, and it is worse
 * because it is silent in the permissive direction: the "since the last
 * success" watermark is ONE SHARED SUBQUERY, so a success kind belonging to one
 * bound clears the window of every bound that shares the set. Measured against
 * real Postgres before this file existed — four `stepup.denied` rows plus one
 * `login.succeeded` row counts as four denials under the shipped sets and ZERO
 * if login's kinds are folded in. `it('no two bounds share a kind')` is that
 * measurement turned into a gate.
 *
 * SOURCE SCAN, because there is nowhere else for it to live: `kind` is a plain
 * string at the repo boundary (`auth_events.kind` has no CHECK), so there is no
 * union to exhaust, and a runtime test could only observe the kinds the cases it
 * happens to drive produce. The vault-crypto zero-dependency fence is the
 * precedent — read the file, do not import the service.
 *
 * ANTI-VACUITY IS THE FIRST CASE, because a scan that stops matching goes green.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  LEDGER_RATE_BOUNDS,
  LOGIN_BOUND,
  REGISTER_REFUSAL_KIND,
  STEP_UP_BOUND,
} from '../src/rate-bounds';

const SERVICE = join(__dirname, '..', 'src', 'auth.service.ts');

function source(): string {
  return readFileSync(SERVICE, 'utf8');
}

/** Every `kind: '…'` literal the service hands the ledger. */
function kindsWritten(): string[] {
  return [...source().matchAll(/kind:\s*'([a-z0-9._]+)'/g)].map((m) => m[1] as string);
}

/**
 * A wrong secret is submitted at exactly the routes that READ one, and each
 * records its own kind. Naming them here rather than deriving them is
 * deliberate: the derivation is the thing under test, so the expectation has to
 * come from somewhere a regex cannot also get wrong. Adding a route means
 * adding a line here AND to the bound's `failures`, and the pair is the review.
 */
const MEANS_A_WRONG_SUBMISSION: Record<string, readonly string[]> = {
  stepup: ['stepup.denied', 'totp.verify_failed'],
  login: ['login.failed'],
};

/** A refusal BY a bound. Counting one would let a counter feed itself. */
const REFUSALS = [STEP_UP_BOUND.refusalKind, LOGIN_BOUND.refusalKind, REGISTER_REFUSAL_KIND];

/**
 * How each refusal kind reaches the ledger. These are NOT literals in the
 * service — they are read off the declaration, which is the point: one source
 * of truth for the string, so a bound's kind cannot be renamed in the table and
 * left stale at the call site.
 *
 * The consequence for this fence is that a scan for `kind: '…'` cannot see
 * them, so it looks for the EXPRESSION instead. Anchored on what the runtime
 * reads (the exported constant) rather than on a copy of the value — the rule
 * the credential-graph fence had to learn twice.
 */
const REFUSAL_EMITTERS: ReadonlyArray<readonly [string, string]> = [
  [STEP_UP_BOUND.refusalKind, 'kind: STEP_UP_BOUND.refusalKind'],
  [LOGIN_BOUND.refusalKind, 'kind: LOGIN_BOUND.refusalKind'],
  [REGISTER_REFUSAL_KIND, 'kind: REGISTER_REFUSAL_KIND'],
];

describe('every guessing bound covers the routes that check its secret', () => {
  it('finds the kinds it is meant to be checking', () => {
    const written = kindsWritten();
    // The floor: the scan has found a real ledger surface, not an empty match.
    expect(written.length).toBeGreaterThanOrEqual(10);
    // …and the bound table itself is not empty, which every loop below assumes.
    expect(LEDGER_RATE_BOUNDS.length).toBeGreaterThanOrEqual(2);
    for (const kind of Object.values(MEANS_A_WRONG_SUBMISSION).flat()) {
      expect(written).toContain(kind);
    }
  });

  it('every refusal kind is actually emitted, through its own declaration', () => {
    // The counterpart to the literal scan above. A bound whose refusal kind is
    // declared and never written is a control with no trace: the wire already
    // says nothing (login answers a plain 401 either way), so the ledger row IS
    // the only evidence the bound fired.
    const text = source();
    for (const [kind, expression] of REFUSAL_EMITTERS) {
      expect({ kind, emitted: text.includes(expression) }).toEqual({ kind, emitted: true });
    }
    // …and no refusal kind is ALSO written as a literal, which would be the
    // second copy this indirection exists to prevent.
    for (const kind of REFUSALS) {
      expect(kindsWritten()).not.toContain(kind);
    }
  });

  it('every declared bound is one this file knows the expected kinds for', () => {
    // Otherwise a third bound could be added and every loop below would skip
    // it in silence — the vacuity this suite exists to refuse.
    expect(LEDGER_RATE_BOUNDS.map((b) => b.name).sort()).toEqual(
      Object.keys(MEANS_A_WRONG_SUBMISSION).sort(),
    );
  });

  it('COUNTS every kind that means a wrong submission was made', () => {
    for (const bound of LEDGER_RATE_BOUNDS) {
      const expected = MEANS_A_WRONG_SUBMISSION[bound.name] as readonly string[];
      expect({ bound: bound.name, failures: [...bound.failures].sort() }).toEqual({
        bound: bound.name,
        failures: [...expected].sort(),
      });
    }
  });

  it('counts NOTHING ELSE — no bound counts any refusal, its own or another’s', () => {
    // The counter must not be able to feed itself: if a refusal were counted,
    // every refused attempt would extend the window it was refused by and a
    // retrying client would lock its own user out permanently. Checked against
    // EVERY bound's refusal rather than only its own, because a shared kind
    // would make one bound's refusals feed another's counter.
    for (const bound of LEDGER_RATE_BOUNDS) {
      for (const refusal of REFUSALS) {
        expect({ bound: bound.name, refusal, counted: bound.failures.includes(refusal) }).toEqual({
          bound: bound.name,
          refusal,
          counted: false,
        });
        expect(bound.successes).not.toContain(refusal);
      }
    }
  });

  it('NO TWO BOUNDS SHARE A KIND — the watermark is one shared subquery', () => {
    // THE M17 MEASUREMENT, as a gate. `failedAttempts` counts failures since the
    // most recent SUCCESS, and that subquery filters on one set. So a kind
    // appearing in two bounds means one bound's success is another bound's
    // amnesty: measured at four denials → zero when `login.succeeded` was folded
    // into the step-up set, i.e. a plain password login silently resetting the
    // second-factor cap. Disjointness is what makes the shared predicate safe.
    for (const a of LEDGER_RATE_BOUNDS) {
      for (const b of LEDGER_RATE_BOUNDS) {
        if (a.name === b.name) continue;
        const aKinds = new Set([...a.failures, ...a.successes]);
        const shared = [...b.failures, ...b.successes].filter((kind) => aKinds.has(kind));
        expect({ a: a.name, b: b.name, shared }).toEqual({ a: a.name, b: b.name, shared: [] });
      }
    }
  });

  it('every counted kind is one the service actually writes', () => {
    // The other direction: a kind left in a set after its route is deleted is
    // dead weight that reads as coverage.
    const written = new Set(kindsWritten());
    for (const bound of LEDGER_RATE_BOUNDS) {
      for (const kind of [...bound.failures, ...bound.successes]) {
        expect({ bound: bound.name, kind, written: written.has(kind) }).toEqual({
          bound: bound.name,
          kind,
          written: true,
        });
      }
    }
  });

  it('every route that reads the second factor passes its gate first', () => {
    // The set being right buys nothing if a route skips the check. Both callers
    // of `checkTotp` must be preceded by the gate — asserted on the source
    // because the alternative is trusting that a test happened to drive both.
    const text = source();
    const readers = [...text.matchAll(/await this\.checkTotp\(/g)];
    expect(readers.length).toBe(2);
    const gates = [...text.matchAll(/await this\.assertStepUpAttemptsAvailable\(/g)];
    expect(gates.length).toBe(2);
    // …and each gate precedes a reader, rather than both sitting in one method.
    for (const reader of readers) {
      const before = text.slice(0, reader.index);
      const lastGate = before.lastIndexOf('assertStepUpAttemptsAvailable(');
      const lastMethodStart = before.lastIndexOf('\n  async ');
      expect(lastGate).toBeGreaterThan(lastMethodStart);
    }
  });
});

/**
 * THE TWO ORDERING DECISIONS ON LOGIN, which are controls rather than
 * arrangement, and which no runtime assertion catches: both placements produce
 * a working rate limiter, and the wrong ones produce an account-existence
 * oracle instead of closing one.
 */
describe('login checks its bounds in the order that keeps the timing channel closed', () => {
  it('checks the ADDRESS bound BEFORE resolving the user', () => {
    // Existence-independent, so short-circuiting here cannot correlate with
    // whether the account is real — and it is the only thing standing between
    // an unauthenticated caller and a 64 MiB Argon2 verification.
    const text = source();
    const login = text.slice(text.indexOf('  async login('), text.indexOf('  async refresh('));
    expect(login.length).toBeGreaterThan(200);

    const addressCheck = login.indexOf('this.loginAddresses.exhausted(');
    const lookup = login.indexOf('this.users.findByEmailBidx(');
    expect(addressCheck).toBeGreaterThan(-1);
    expect(lookup).toBeGreaterThan(-1);
    expect(addressCheck).toBeLessThan(lookup);
  });

  it('checks the ACCOUNT bound AFTER the password verification', () => {
    // The inverse of the case above, and the placement that looks wasteful. The
    // account bound can only be evaluated once the user is resolved, so
    // checking it BEFORE `verifyPassword` would let an over-cap account answer
    // fast while an unknown address still paid a full Argon2 — the
    // account-existence timing oracle this route burns `dummyVerify` to close,
    // re-opened by the control added to protect it.
    const text = source();
    const login = text.slice(text.indexOf('  async login('), text.indexOf('  async refresh('));

    const verify = login.indexOf('this.hasher.verifyPassword(');
    const accountCheck = login.indexOf('this.boundExceeded(LOGIN_BOUND');
    expect(verify).toBeGreaterThan(-1);
    expect(accountCheck).toBeGreaterThan(-1);
    expect(accountCheck).toBeGreaterThan(verify);
  });

  it('refuses with the SAME token a wrong password gets, never a distinct status', () => {
    // A 429 on login is an account-existence oracle however the counter is
    // keyed: past the threshold a live address would answer differently from
    // one that was never counted at all. The step-up bound's 429 is correct on
    // ITS routes, which already require a resolved authenticated caller.
    const text = source();
    const refusal = text.slice(
      text.indexOf('private async refuseLoginForRate('),
      text.indexOf('  private async recordLoginFailure('),
    );
    expect(refusal.length).toBeGreaterThan(200);
    expect(refusal).toContain('throw invalidCredentials()');
    expect(refusal).not.toContain('TOO_MANY_REQUESTS');
  });
});
