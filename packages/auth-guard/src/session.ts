import {
  DEFAULT_SESSION_AUDIENCE,
  SESSION_AUDIENCES,
  type MfaLevel,
  type SessionAudience,
} from '@estate/contracts';

/**
 * WHAT A SESSION IS FOR, not just who it belongs to (M15).
 *
 * Until the vault surface there was one kind of session and every service
 * accepted it, which was correct while every surface lived on one origin. M15
 * puts Zone A on an ISOLATED ORIGIN (docs/03 TB6) reached by a single-use
 * handoff, and a handoff code that leaks must not become authority over the
 * rest of the estate — so the session it redeems for is minted for the vault
 * and is refused everywhere else.
 *
 * THE VOCABULARY MOVED TO @estate/contracts IN M16, and only the vocabulary —
 * everything below this line, which is the enforcement, stays here. The reason
 * is a consumer that cannot follow it: the BFF labels sessions with the
 * audience and deliberately does not depend on this package, since a NestJS
 * guard package has no business inside the edge. Leaving the list here would
 * have meant the BFF hand-copying three string literals, which is the drift
 * class this repo has recorded four times. `MfaLevel` travelled the same way
 * for the same reason and is imported on the line above.
 *
 * Re-exported rather than re-declared, so every existing importer of
 * `@estate/auth-guard` is unchanged and there is still exactly one definition.
 *
 * The enforcement is DENY BY DEFAULT and lives in `CallerGuard`: a service
 * admits `account` and nothing else unless it is explicitly constructed with a
 * wider set. Adding an audience is therefore a decision a reviewer sees, and
 * the nine services that never opt in reject a vault session without any of
 * them changing a line.
 */
export { DEFAULT_SESSION_AUDIENCE, SESSION_AUDIENCES };
export type { SessionAudience };

/**
 * WHO MAY ADMIT A NON-DEFAULT AUDIENCE, declared as data.
 *
 * The same reasoning as `credential-graph.ts`: `CallerGuard` can enforce "this
 * service admits these audiences", but it cannot say which services SHOULD, and
 * that question is the security property. The M7 collapse survived two reviews
 * because the trust graph existed only as prose, so this one is a table a test
 * fails the build over — `packages/auth-guard/test/session-audience.spec.ts`
 * scans `apps/services/*` for bindings of `ALLOWED_SESSION_AUDIENCES` and
 * requires them to match this exactly, in both directions.
 *
 * `account` is deliberately absent from the keys: every service admits it, so
 * listing it would invite the table to be read as an allowlist of who may serve
 * ordinary users.
 *
 * Vault admits BOTH `account` and `vault`, and the asymmetry is the point.
 * Refusing `account` at the vault service would buy nothing — an account
 * session is strictly MORE powerful, since it already opens every other service
 * — while making the vault service untestable except through the handoff. The
 * property that matters runs the other way: a `vault` session reaches the vault
 * service and nothing else.
 */
export const AUDIENCE_ADMITTERS: Readonly<
  Record<Exclude<SessionAudience, 'account'>, readonly string[]>
> = {
  vault: ['vault'],
  /**
   * EMPTY ON PURPOSE, and it is the most important entry in this file (M16).
   *
   * The obvious way to let a browser extension reach the vault is to add
   * `extension` to that service's `ALLOWED_SESSION_AUDIENCES`. It is one word
   * and it is wrong: `CallerGuard.audiencesFor` UNIONS the service-wide grant
   * with any route-level one and can never subtract, so a service-wide grant
   * here would open all 23 vault routes at once — including `reset`
   * (crypto-shreds the vault on step-up alone), both keyset routes, `deleteItem`,
   * `request` (starts a §5.2 waiting period) and `release` (the single moment
   * the platform half of a recovery key leaves the service). None of those needs
   * an open vault, so a long-lived extension credential would reach them with no
   * SRP unlock at all.
   *
   * The extension is therefore admitted PER HANDLER, below. An empty array here
   * is a deliberate subtraction rather than an oversight — the M8 zero-holder
   * rule — and the suite asserts separately that every declared audience is
   * admitted SOMEWHERE, so this cannot silently become an audience nothing
   * accepts.
   */
  extension: [],
  /**
   * STILL EMPTY AFTER PR3b, and now for the reason PR3a predicted rather than
   * because nothing admits the audience.
   *
   * `extension` is empty because a service-wide grant at the vault would be
   * too WIDE. `operator` is empty for the same shape of reason, one service
   * over: settlement is where the operator routes live, and binding `operator`
   * there service-wide would union with every route it has — including the
   * reporter- and owner-facing ones: the decedent's own `void`, the owner's
   * waiting-period settings, a reporter's `cases` listing. The operator
   * surface is a SUBSET of settlement rather than the whole of it, so the
   * grant is per handler, in `AUDIENCE_ROUTE_ADMITTERS` below.
   *
   * `CallerGuard.audiencesFor` returns the UNION of this list and the
   * per-route one, so a service-wide grant here could never be narrowed by a
   * decorator. That is why the console's thirteen routes are decorated
   * individually and this stays `[]`: the widening has to be spelled out one
   * handler at a time, and everything not spelled out is refused by default.
   */
  operator: [],
};

/**
 * WHO MAY ADMIT A NON-DEFAULT AUDIENCE ON ONE ROUTE ONLY (M15 PR3).
 *
 * The table above is the service-wide grant, and for the vault service that is
 * the right unit — every route it has is a Zone A route. Emergency access broke
 * that symmetry: choosing a grantee needs contact NAMES, which live in profile,
 * and a service-wide grant there would hand a leaked vault session the owner's
 * PII, every contact's decrypted detail, the family tree and the role
 * assignments. So profile admits a `vault` session on ONE route, whose whole
 * response is the three fields the design already decided may cross into
 * Zone A — a contact id, an account id and a name.
 *
 * DENY BY DEFAULT still holds and is what makes this narrow: an undecorated
 * route falls back to the service-wide list, which is `account` alone until a
 * service says otherwise, so this table is the COMPLETE list of exceptions
 * rather than a summary of them.
 *
 * Keyed `service:handler` and checked against the real decorated handlers in
 * both directions by `test/session-audience.spec.ts` — a route that quietly
 * acquires the decorator fails the build, and so does an entry here whose
 * handler no longer carries it. It also refuses an entry whose service already
 * holds the audience service-wide, because a route-level grant that changes
 * nothing reads as a narrower one than is actually in force.
 */
export const AUDIENCE_ROUTE_ADMITTERS: Readonly<
  Record<Exclude<SessionAudience, 'account'>, readonly string[]>
> = {
  vault: [
    // Identity's three, and why each is safe rather than merely convenient:
    // `session` is introspection and MUST admit every audience or the audience
    // is unusable; `stepUp` STRENGTHENS the session presenting it and confers
    // nothing else, so a vault session that steps up is still a vault session;
    // `logout` revokes the credential you presented, which can only reduce
    // authority (the M6 rule that the protective action must never be harder).
    // Absent, and load-bearing: `mintHandoff`. A vault session cannot mint
    // another, so a leaked one cannot chain itself forward.
    'identity:session',
    'identity:stepUp',
    'identity:logout',
    // Profile's one, added by M15 PR3. Its whole response is a contact id, an
    // account id and a name — see the route's own comment.
    'profile:granteeCandidates',
  ],
  /**
   * THE BROWSER EXTENSION'S ENTIRE REACH (M16).
   *
   * Ten handlers, chosen by what each one DOES rather than by its guard shape
   * — because guard shape cannot discriminate here. Eight vault routes are gated
   * on step-up ALONE, and that set contains both the destructive routes and the
   * two SRP legs an extension cannot function without, so "refuse everything
   * step-up-alone" would make the extension unable to open a vault while
   * "admit everything step-up-alone" would hand it `reset`.
   *
   * WHAT AN EXTENSION SESSION CAN DO, exhaustively: discover whether a vault
   * exists, run the two SRP legs, list items, CREATE and UPDATE an item, and
   * lock.
   *
   * THAT SENTENCE USED TO END AT "list items", and PR4a is the change that
   * made the old one false — it read "everything it can read is CIPHERTEXT …
   * and nothing else", which stopped being true the moment a write was
   * admitted. Restated rather than left standing (the M14 rule):
   *
   *   · EVERY ADMITTED ITEM ROUTE SITS BEHIND `VaultSessionGuard`, which only a
   *     completed SRP unlock satisfies — and that unlock needs the vault
   *     password and the device Secret Key, neither of which this platform has
   *     ever held, plus a fresh step-up. So a STOLEN EXTENSION CREDENTIAL still
   *     yields the ability to attempt a handshake and nothing more. The write
   *     capability belongs to an UNLOCKED vault, not to the credential.
   *   · `deleteItem` IS ABSENT AND STAYS ABSENT. It is the one item route gated
   *     on `StepUpGuard` as well, it is the destructive verb, and docs/04 fixes
   *     its exclusion. An overwrite is not equivalent: `vault_items_versions`
   *     captures BEFORE UPDATE OR DELETE (`001_vault_schema.sql`), so a write
   *     through this audience is recoverable and a delete would not be.
   *   · `updateItem` CARRIES `If-Match`, so an overwrite is conditional on the
   *     version the caller read rather than blind.
   *
   * RESIDUAL, STATED: with the vault unlocked, this audience can overwrite every
   * item the user has. The rows survive in `vault_items_versions`, but NO
   * RESTORE SURFACE EXISTS anywhere in the product, so recovery today means an
   * operator reading that table. That is a real gap and it is recorded in
   * docs/03 §6j rather than implied by the word "recoverable".
   *
   * `vault:getItem` is deliberately absent: `listItems` already returns each
   * item's full ciphertext blob, so it buys an autofill client nothing, and
   * every handler left out is authority not granted.
   *
   * Identity's three are the same three the vault origin gets, for the same
   * reasons — introspection must admit every audience or the audience is
   * unusable; step-up STRENGTHENS the session presenting it and confers nothing
   * else; logout can only reduce authority. `mintHandoff` is absent here as it
   * is for `vault`: no non-account session may mint a credential.
   *
   * NOT LISTED AND NOT AN OMISSION: `POST /v1/auth/refresh`. It carries no guard
   * at all — it is unauthenticated by construction, since the refresh token is
   * the authority — so there is no decorator to declare and this table, which is
   * about guarded routes, has nothing to say about it. Its audience safety comes
   * from a different property: refresh ROTATES IN PLACE (`UPDATE … WHERE id`),
   * so a refreshed session is the same row and cannot change what it is for.
   * That property is pinned by its own test rather than left as an accident of
   * the SET list.
   */
  extension: [
    'vault:keysetStatus',
    'vault:startUnlock',
    'vault:finishUnlock',
    'vault:listItems',
    // PR4a, and admitted in the same change as their callers — the rule the
    // graph's own comment sets for a new capability.
    'vault:createItem',
    'vault:updateItem',
    'vault:lock',
    'identity:session',
    'identity:stepUp',
    'identity:logout',
  ],
  /**
   * THE OPERATOR ORIGIN'S ENTIRE REACH. PR3a shipped identity's three and
   * nothing else in the product, deliberately — an audience is worth what the
   * services refusing it make it worth, and there was no surface yet. PR3b
   * added the settlement console's thirteen.
   *
   * IDENTITY'S THREE, the same three as `vault`, admitted for the same three reasons, which are
   * worth restating rather than cross-referencing because each is a different
   * argument: `session` is introspection and MUST admit every audience or the
   * audience cannot be used at all; `stepUp` STRENGTHENS the session presenting
   * it and confers nothing else, so an operator session that steps up is still
   * an operator session; `logout` revokes the credential you presented, which
   * can only reduce authority (the M6 rule that the protective action must
   * never be harder than the permissive one).
   *
   * ABSENT AND LOAD-BEARING, exactly as for `vault`: `mintHandoff`. An operator
   * session cannot mint another, so a leaked one cannot chain itself forward —
   * and since the operator handoff is minted by the same ceremony, this is what
   * stops an operator credential from re-minting itself past its 15 minutes.
   * `session-audience.spec.ts` names that absence in a test of its own.
   *
   * THE SETTLEMENT CONSOLE (PR3b), added in the same change as the client that
   * calls each one — the rule the credential graph's own comment sets for a
   * new capability. Three groups, and the shape of the split is the argument:
   *
   *   · TWO WORKLISTS and the reads that open a case. `getCase`, `timeline`,
   *     `listStages` and `listDistributions` authorize through the Cedar
   *     `read` permit and `assertCaseVisible`, which admit the decedent, the
   *     reporter and the estate's executor as well as an operator — so an
   *     operator credential reaches those people's own cases too. That is a
   *     real widening, it is the reason `AUDIENCE_COPY.OPERATOR` no longer
   *     claims the credential "reaches none of your estate", and it is
   *     recorded as an accepted residual in docs/03 §6cc rather than papered
   *     over. The alternative — four operator-only read projections — is a
   *     second copy of an authorization decision, which is how two copies
   *     drift apart.
   *   · THE REVIEW VERBS: claim, decide, verify. The §5.1 chain.
   *   · THE POST-VERIFICATION VERBS: close, stage decisions, distribution
   *     approval.
   *
   * ABSENT AND DELIBERATE — every one of the other settlement handlers, each
   * for its own reason rather than by omission. The enumeration is TOTAL and
   * `apps/services/settlement/test/session-audience.spec.ts` asserts it is,
   * against the refused set it derives from the real decorators: an
   * enumeration that silently stops covering its subject is how a name here
   * rots into a reason nobody re-reads.
   *
   *   · `reportableEstates`, `report`, `listMine`, `addEvidence` — the
   *     REPORTER's surface (M22). Filing and tracking a death report is a
   *     linked contact's act, not an operator's.
   *   · `void`, `getSettings`, `updateSettings` — the OWNER's controls. An
   *     operator credential must never reach the decedent's own kill switch
   *     or their waiting-period setting.
   *   · `reportProvider` — operator intake, but the console files no provider
   *     signals, and a capability with no caller is exactly what this table
   *     exists to prevent.
   *   · `evidenceRead`, `stageAccess`, `vaultRelease` — peer-service
   *     authority questions, asked by documents, assets and vault on somebody
   *     else's forwarded bearer or their own service credential. A human
   *     session has no business answering them.
   *   · `requestStage`, `completeTask`, `recordDistribution` — EXECUTOR-ONLY
   *     at the service: each refuses an operator outright (M23).
   *     `recordDistribution` is also the recording half of the distribution
   *     dual control, whose approving half IS admitted here — the row-local
   *     CHECK refuses the same actor either way, and a console offering both
   *     halves is not a shape to build and then rely on a constraint to save.
   *   · `listTasks`, `setDistributionStatus` — the service DOES admit an
   *     operator on both (`listTasks` through `assertCaseVisible`,
   *     `setDistributionStatus` through the gate), and they are absent because
   *     the CONSOLE does not offer them: the executor's checklist and the
   *     payment-progress ladder are M23's surface. This is the one group whose
   *     absence is a product decision rather than an authorization one, which
   *     is worth saying rather than letting the list imply otherwise.
   */
  operator: [
    'identity:session',
    'identity:stepUp',
    'identity:logout',
    'settlement:queue',
    'settlement:administrable',
    'settlement:getCase',
    'settlement:timeline',
    'settlement:listStages',
    'settlement:listDistributions',
    'settlement:startReview',
    'settlement:decideReview',
    'settlement:verify',
    'settlement:closeCase',
    'settlement:decideStage',
    'settlement:revokeStage',
    'settlement:approveDistribution',
  ],
};

/** Metadata key carrying a route's admitted audiences. See AllowSessionAudiences. */
export const SESSION_AUDIENCE_METADATA = 'estate:session-audiences';

/**
 * The verified session context a downstream service acts on. Mirrors the shape
 * identity's own SessionGuard attaches and its `GET /v1/auth/session`
 * introspection route returns — the single source of truth for "who is calling
 * and how strongly are they authenticated".
 */
export interface SessionContext {
  userId: string;
  sessionId: string;
  mfaLevel: MfaLevel;
  /** Non-null ⇒ a step-up is active until this instant (docs/01 §5, ≤5 min). */
  stepupExpiresAt: Date | null;
  /** What this session may be spent on. See SESSION_AUDIENCES. */
  audience: SessionAudience;
}

/** Injectable clock so step-up freshness is testable without real time. */
export type Clock = () => Date;

/** Step-up freshness window: docs/01 §5 mandates "fresh, ≤5 min". */
export const STEPUP_WINDOW_MS = 5 * 60 * 1000;

/**
 * The step-up gate: a session may perform a sensitive action only while its
 * mfa_level is 'stepup' AND the freshness window has not lapsed. Shared by
 * identity (which grants step-up) and every downstream StepUpGuard (which
 * verifies it), so the ≤5-minute rule has exactly one definition.
 */
export function isStepUpFresh(
  mfaLevel: MfaLevel,
  stepupExpiresAt: Date | null,
  now: Date,
): boolean {
  return (
    mfaLevel === 'stepup' && stepupExpiresAt !== null && stepupExpiresAt.getTime() > now.getTime()
  );
}
