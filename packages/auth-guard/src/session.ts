import type { MfaLevel } from '@estate/contracts';

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
 * `account` is the ordinary session every existing flow uses. `vault` is minted
 * only by identity's handoff redemption, carries no refresh token, and lives 15
 * minutes.
 *
 * The enforcement is DENY BY DEFAULT and lives in `CallerGuard`: a service
 * admits `account` and nothing else unless it is explicitly constructed with a
 * wider set. Adding an audience is therefore a decision a reviewer sees, and
 * the nine services that never opt in reject a vault session without any of
 * them changing a line.
 */
export const SESSION_AUDIENCES = ['account', 'vault'] as const;

export type SessionAudience = (typeof SESSION_AUDIENCES)[number];

/**
 * What a session is when nothing says otherwise.
 *
 * Also what an ABSENT `audience` field means on the introspection response, and
 * that is sound rather than lax: a non-`account` audience can only exist
 * because identity minted one, and an identity old enough to omit the field has
 * no handoff route and therefore no such session to describe. An UNRECOGNISED
 * value is a different matter and fails closed — see the verifier's enum.
 */
export const DEFAULT_SESSION_AUDIENCE: SessionAudience = 'account';

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
};

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
