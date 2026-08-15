/**
 * EVERY LEDGER-DERIVED GUESSING BOUND IN THE PRODUCT, DECLARED AS DATA (M17).
 *
 * M16 shipped one bound, on the second factor, and wrote its kind sets as two
 * module-level constants that `AuthEventsRepo.failedFactorAttempts` imported
 * directly. That was right for one bound and is wrong for two, for a reason
 * that was MEASURED rather than reasoned about before this file existed.
 *
 * ═══ WHY LOGIN DOES NOT JOIN THE STEP-UP SETS ═══
 *
 * The obvious way to bound login is to add `login.failed` / `login.succeeded`
 * to `SECOND_FACTOR_FAILURES` / `SECOND_FACTOR_SUCCESSES` and change nothing
 * else. It is one line and it DESTROYS the step-up cap.
 *
 * The count is "failures since the last success", and the watermark is a single
 * shared subquery (`auth-events.repo.ts`). So a success of ANY kind in the set
 * clears the window for EVERY kind in it. Measured against real Postgres: a
 * user with four `stepup.denied` rows followed by one `login.succeeded` row
 * counts as
 *
 *     shipped sets                     → denials = 4
 *     merged (login kinds folded in)   → denials = 0
 *
 * — i.e. a plain password login, which proves no second factor at all, would
 * reset the step-up counter. That hands the exact adversary docs/03 §6j records
 * as the surviving residual ("an attacker who can MINT sessions, i.e. who holds
 * the password, can still walk the account total to its ceiling") an unlimited
 * reset, turning 20-per-15-minutes into no bound whatsoever.
 *
 * Hence: bounds are SEPARATE, their kind sets are PAIRWISE DISJOINT, and
 * `test/rate-bounds.spec.ts` asserts that rather than trusting this paragraph.
 * The repo predicate takes the sets as PARAMETERS now; it no longer imports
 * them, because a shared import is what made one bound's success another
 * bound's amnesty.
 *
 * ═══ WHY THE REFUSAL SHAPE DIFFERS PER BOUND ═══
 *
 * `stepup` and `totp/verify` answer 429 `too_many_attempts`. They require a
 * resolved, authenticated user, so a distinct status tells the caller something
 * they already know about themselves.
 *
 * LOGIN MUST NOT. A 429 there is an account-existence oracle however the
 * counter is keyed, because it is a state an attacker reaches only by naming
 * something real: past the threshold a live address would answer 429 while an
 * address with no account answers 401 forever, since nothing was ever counted
 * for it. That is perfectly reliable and timing-independent, and it would
 * defeat the `dummyVerify` equalization `password.ts` calls mandatory — the
 * control manufacturing the very oracle it was added to bound. So login's
 * refusal is the SAME 401 `invalid_credentials` as a wrong password, and the
 * bound's visibility is the audit trail rather than the status code.
 *
 * Register is the other way round and 429 is safe there: its bound is keyed on
 * the submitted ADDRESS alone, counted whether or not an account exists, so the
 * refusal depends on nothing the caller does not already know.
 */
import {
  SECOND_FACTOR_FAILURES,
  SECOND_FACTOR_SUCCESSES,
  STEPUP_DENIAL_WINDOW_MS,
  STEPUP_MAX_ACCOUNT_DENIALS,
  STEPUP_MAX_DENIALS,
} from './stepup';

/**
 * One bound: which ledger kinds it counts, over what window, to what ceilings,
 * and what it writes when it refuses.
 */
export interface LedgerRateBound {
  /** Stable identifier. Appears in fences and in nothing user-facing. */
  readonly name: string;
  /**
   * Kinds meaning "this principal submitted something wrong". Counted.
   * Disjoint from every other bound's failures AND successes.
   */
  readonly failures: readonly string[];
  /**
   * Kinds meaning "this principal proved it". The window is measured since the
   * most recent of these, so a user who fumbles twice and then succeeds does
   * not carry the failures forward.
   */
  readonly successes: readonly string[];
  readonly windowMs: number;
  /**
   * Cap on ONE credential's own failures, or null when the route has no
   * credential to scope to. See `LOGIN_BOUND` for what null costs.
   */
  readonly maxPerScope: number | null;
  /** Cap on the account's total across every scope. The real bound. */
  readonly maxPerAccount: number;
  /**
   * The kind written when THIS bound refuses. MUST NOT appear in `failures` —
   * a counter that counts its own refusals extends the window it was refused
   * by, and a client retrying in a loop locks its own user out permanently.
   */
  readonly refusalKind: string;
}

/**
 * The M16 second-factor bound, unchanged in every observable respect. Its
 * constants and kind sets still live in `stepup.ts`, which carries the full
 * reasoning and the measurement that forced the two scopes; this is the same
 * bound expressed in the shape the second one needs.
 */
export const STEP_UP_BOUND: LedgerRateBound = {
  name: 'stepup',
  failures: SECOND_FACTOR_FAILURES,
  successes: SECOND_FACTOR_SUCCESSES,
  windowMs: STEPUP_DENIAL_WINDOW_MS,
  maxPerScope: STEPUP_MAX_DENIALS,
  maxPerAccount: STEPUP_MAX_ACCOUNT_DENIALS,
  refusalKind: 'stepup.rate_limited',
};

/**
 * TWENTY FAILED LOGINS PER ACCOUNT PER FIFTEEN MINUTES — the durable backstop,
 * not the primary bound.
 *
 * `maxPerScope` IS NULL, AND THAT IS THE HONEST PART. M16's escape from the
 * owner-lockout trap was a per-CREDENTIAL scope: a stolen session exhausts
 * itself and the owner's other sessions keep their own budget. Login has no
 * credential at the point of failure — `recordLoginFailure` runs before any
 * session exists — so that escape does not port, and no amount of restructuring
 * invents one. Anyone who knows an address can submit wrong passwords for it.
 *
 * WHAT REPLACES IT is that this bound touches ONLY the login route. It is not
 * the step-up cap's situation, where the refusal blocked the one action that
 * could clear the window and simultaneously blocked vault open, document
 * generation, export, beneficiary changes, deletion and docs/03 §5.1's liveness
 * proof. Here a live session keeps working: `findLiveByAccessHash` and
 * `findLiveByRefreshHash` consult no counter, so an owner who is already signed
 * in stays signed in, keeps refreshing, and reaches every route in the product.
 * `test/login-bound.int.spec.ts` proves exactly that rather than asserting it.
 *
 * The cost that remains is real and is written down in docs/03 §6k rather than
 * softened: an attacker sustaining twenty wrong passwords per quarter-hour
 * denies NEW logins for that account for as long as they keep it up. They
 * cannot touch a live session, cannot escalate, and cannot learn whether the
 * address names an account. Twenty is chosen so that no legitimate user meets
 * it — it is four times the step-up per-credential cap, against a secret with
 * far more entropy than six digits — which makes reaching it a burst signal
 * rather than a support ticket.
 *
 * The tighter, faster bound is `AddressAttemptBound`, which is keyed on the
 * submitted address, refuses before Argon2 runs, and sees the attempts this one
 * structurally cannot (below).
 */
export const LOGIN_BOUND: LedgerRateBound = {
  name: 'login',
  // Every `login.failed` row regardless of `decision`: a bad password, a locked
  // account and a decedent-credential replay against a settled one are all
  // somebody submitting a credential that did not work, and the predicate does
  // not read `decision`.
  failures: ['login.failed'],
  successes: ['login.succeeded'],
  windowMs: 15 * 60 * 1000,
  maxPerScope: null,
  maxPerAccount: 20,
  refusalKind: 'login.rate_limited',
};

/**
 * FIVE WRONG CURRENT-PASSWORD GUESSES PER SESSION, TWENTY PER ACCOUNT — added
 * by the M17 PR6 review, which found `POST /v1/auth/password` verifying a
 * password with no bound of any kind.
 *
 * MEASURED BEFORE IT WAS WRITTEN, on the running stack: twenty-five wrong
 * guesses from one stolen session all answered 401, no refusal ever fired, and
 * the twenty-sixth — with the right password — took the account over. The same
 * volume against `POST /v1/auth/login` produced ten `login.failed` and four
 * `login.rate_limited`. One credential-guessing action, two routes, and only
 * one of them bounded.
 *
 * WHY THE GAP EXISTED: M17 PR1 bounded the routes that take a password from an
 * UNAUTHENTICATED caller, and PR2's change route reads as authenticated —
 * except that the whole reason it asks for the current password is the
 * stolen-session threat, so its caller is exactly the party the bound is for.
 *
 * ═══ WIDENED BY THE M20 PR5 REVIEW, WHICH FOUND A SECOND SUCH ROUTE ═══
 *
 * `POST /v1/auth/email/change/request` takes the current password too, for the
 * identical reason, and shipped in M20 PR2 with the identical gap — the fix one
 * milestone earlier had been applied to the one INSTANCE rather than to the
 * category. Measured on a factorless account, which `SecondFactorGate`
 * deliberately admits: unlimited 400s at a full Argon2id verification each,
 * while the bounded route sat one hop away.
 *
 * BOTH ROUTES SHARE THIS ONE BUDGET rather than getting one each, which is the
 * M16 chokepoint rule: the thing to bound is the SET of routes that read a
 * secret, because two bounds of five are a bound of ten to anyone willing to
 * alternate between them. Hence the rename — a constant called
 * `PASSWORD_CHANGE_BOUND` is exactly the name that lets the next person add a
 * third route without noticing it should be here.
 *
 * `email_change.denied` IS WRITTEN IN ONE PLACE AND MEANS ONE THING (a wrong
 * current password at the request leg), so counting the kind wholesale counts
 * nothing else. `email_change.refused`, `.failed` and `.cancelled` are separate
 * kinds and stay out of the set.
 *
 * NO EMAIL-CHANGE SUCCESS KIND CLEARS THE WINDOW, and that is the same call the
 * reset paragraph below makes. `email_change.requested` is written DETACHED,
 * after the response, and is skipped entirely when the destination turns out to
 * be taken — so it is an unreliable signal of "this caller proved the
 * password", and a success kind that can be missing is a window that clears
 * unpredictably. The cost is bounded by `windowMs`: a legitimate user who
 * mistyped their way to the cap waits it out instead of clearing it with a
 * correct guess.
 *
 * `maxPerScope` IS SET HERE, unlike `LOGIN_BOUND`, and the difference is the
 * one M16 identified: there IS a credential at the point of failure. A stolen
 * session exhausts its own budget and stops, while the owner's other sessions
 * keep theirs — so the cap cannot become the owner-lockout that a purely
 * account-keyed bound would be on a route the owner needs. The account ceiling
 * stays as the real bound against somebody holding several stolen sessions.
 *
 * A RESET DELIBERATELY DOES NOT CLEAR THE WINDOW (`successes` is
 * `password.changed` alone). It does not need to: completing a reset revokes
 * every session, so the attacker's stolen credential is dead and its budget is
 * moot — and adding a kind here that a caller can reach WITHOUT proving the
 * current password would let the reset path launder the guessing window.
 */
export const ACCOUNT_PASSWORD_BOUND: LedgerRateBound = {
  name: 'account-password',
  failures: ['password.change_failed', 'email_change.denied'],
  successes: ['password.changed'],
  windowMs: 15 * 60 * 1000,
  maxPerScope: 5,
  maxPerAccount: 20,
  // Unchanged across the rename, on purpose: see `AccountPasswordGate.refuse`.
  // The ledger kind is free to rename; the audit action beside it is not.
  refusalKind: 'password.change_rate_limited',
};

/** Every declared bound, for the fence to iterate. */
export const LEDGER_RATE_BOUNDS: readonly LedgerRateBound[] = [
  STEP_UP_BOUND,
  LOGIN_BOUND,
  ACCOUNT_PASSWORD_BOUND,
];

/**
 * THE ADDRESS-KEYED BOUND — the primary one, and deliberately NOT on the
 * ledger.
 *
 * ═══ WHY IT CANNOT RIDE `auth_events` ═══
 *
 * The account-keyed bound above is blind to most of the surface it looks like
 * it covers. `recordLoginFailure(null, …)` writes `user_id = NULL` whenever the
 * identifier does not resolve, so a per-account count sees only failures
 * against accounts that EXIST — measured on the live stack, every
 * `login.failed` row there is unattributed — and register's duplicate path
 * returns having written no row at all, in either direction. An attacker
 * spraying one password across many addresses, and every register probe,
 * produce nothing a user-keyed predicate can count.
 *
 * The selector that would work is the email blind index, already computed
 * before any expensive work on both routes. It is NOT added to `auth_events`,
 * for three reasons and the first is decisive: that table is append-only
 * (REVOKE UPDATE, DELETE) and carries no `dek_id`, so an `email_bidx` column
 * would permanently and unshreddably record a correlatable identifier for
 * addresses belonging to NO ACCOUNT — third parties merely typed at a login
 * box, who never registered and cannot be erased. It would also invert M9's own
 * "no blind index, lookup by user id only" decision for the delivery store; and
 * the index it needs is a plain `CREATE INDEX` inside the migrator's
 * BEGIN/COMMIT, which `005_auth_events_index.sql` already records as taking a
 * SHARE lock that blocks INSERT on the authentication write path.
 *
 * ═══ SO IT IS IN MEMORY, AND ITS LIMITS ARE STATED ═══
 *
 * Per process, holding a truncated digest of the blind index and a count. It
 * survives no restart, is not shared between replicas, and is bounded in size —
 * which means an attacker can evict their own counter by spraying unrelated
 * addresses until the map turns over. That is what "best effort" means here and
 * it is why this is one of two bounds rather than the only one: the ledger half
 * is the durable ceiling precisely because this half is evadable.
 *
 * What it buys that the ledger half cannot: it refuses BEFORE the Argon2id
 * verification, so it is also the only thing standing between an unauthenticated
 * caller and 64 MiB of memory-hard work per request; and it counts attempts
 * against addresses with no account, which is most of them.
 */
export interface AddressBoundOptions {
  /** Failures tolerated per address per window. */
  readonly max: number;
  readonly windowMs: number;
  /**
   * How many addresses are tracked at once. A bound on the bound: without it a
   * caller submitting unique addresses is a memory-exhaustion primitive, which
   * would make the rate limiter the denial-of-service vector.
   */
  readonly capacity: number;
}

/**
 * TEN PER ADDRESS PER FIFTEEN MINUTES. Tighter than the account ceiling, so in
 * a single-process deployment this is what a caller meets first; the account
 * ceiling is what they meet after spreading across replicas.
 *
 * CAPACITY 50,000 is a memory budget, not a security parameter — roughly a few
 * megabytes of digests and counters. Reaching it evicts the least recently
 * seen address, which fails OPEN by construction (an evicted counter starts
 * again at zero). Failing closed on eviction would be worse in the only way
 * that matters: it would let a caller who fills the map deny logins to every
 * user in the product.
 */
export const LOGIN_ADDRESS_BOUND: AddressBoundOptions = {
  max: 10,
  windowMs: 15 * 60 * 1000,
  capacity: 50_000,
};

/**
 * Register is bounded more loosely than login and for a different reason. It is
 * not a guessing route — there is no secret to get right — so the bound exists
 * to cap Argon2id cost and to blunt address probing, not to stop an attacker
 * converging on an answer. Twenty is comfortably above any human retry and
 * still bounds one address to twenty memory-hard hashes a quarter-hour.
 */
export const REGISTER_ADDRESS_BOUND: AddressBoundOptions = {
  max: 20,
  windowMs: 15 * 60 * 1000,
  capacity: 50_000,
};

/**
 * THE RESET-REQUEST BOUND (M17 PR3). Ten per address per fifteen minutes.
 *
 * The tightest of the three, and the only one whose refusal is SILENT. The
 * route it guards answers the same 202 for every input by design, so a 429
 * would be the one observable that varies — and although the count is
 * existence-independent (making a 429 safe by register's argument), a route
 * that tells the caller nothing is better served by continuing to tell them
 * nothing. A dropped request is indistinguishable from a delivered one, which
 * is what the whole route is arranged around.
 *
 * It is the PRIMARY defence on that route, because the per-account floor behind
 * it can only be evaluated after an address resolves to a user — so the floor
 * sees nothing at all for an address with no account, which is most of what an
 * abuser sends. Ten is below register's twenty because the cost here is a real
 * email to somebody who did not ask for it, not just CPU.
 */
export const RESET_ADDRESS_BOUND: AddressBoundOptions = {
  max: 10,
  windowMs: 15 * 60 * 1000,
  capacity: 50_000,
};

/**
 * Per-DESTINATION bound on the email-change challenge (M17 PR4): the mint is
 * gated on the caller's password and a fresh factor, but every request may
 * name a DIFFERENT target address, so the per-account floor cannot bound how
 * much mail lands at any one mailbox. Same numbers as the reset bound and for
 * its reason — the cost is a real email to somebody who may not have asked.
 */
export const CHANGE_ADDRESS_BOUND: AddressBoundOptions = {
  max: 10,
  windowMs: 15 * 60 * 1000,
  capacity: 50_000,
};

/**
 * The ledger kind register's refusal writes. It has no `LedgerRateBound`
 * because it counts nothing on the ledger — the row exists so that a control
 * firing leaves a trace, and the kind is declared here rather than inline so
 * the fence can assert no bound counts it.
 */
export const REGISTER_REFUSAL_KIND = 'register.rate_limited';
