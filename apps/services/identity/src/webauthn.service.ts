import { BadRequestException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { SessionContext } from '@estate/auth-guard';
import { NOTIFICATIONS, type NotificationsPort } from '@estate/notifications-client';
import { AuthEventsRepo } from './auth-events.repo';
import type { StepUpResult } from './auth.service';
import type { IdentityConfig } from './config';
import { CLOCK, CONFIG, type Clock } from './di-tokens';
import { EventsService } from './events.service';
import { SecondFactorGate } from './second-factor-gate';
import { SessionsRepo } from './sessions.repo';
import { STEPUP_WINDOW_MS } from './stepup';
import { WebAuthnRepo, type WebAuthnCredentialRow } from './webauthn.repo';

/** Server-side challenge lifetime; short by design (a live ceremony is seconds). */
export const WEBAUTHN_CHALLENGE_TTL_MS = 5 * 60 * 1000;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Generic ceremony failures — never leak which step failed (no enumeration). */
function registrationFailed(): BadRequestException {
  return new BadRequestException({ error: 'webauthn_failed' });
}
function authenticationFailed(): UnauthorizedException {
  return new UnauthorizedException({ error: 'webauthn_failed' });
}

/**
 * Copy a Node Buffer into a fresh ArrayBuffer-backed Uint8Array. A Buffer is
 * `Uint8Array<ArrayBufferLike>`, which TS will not narrow to the library's
 * `Uint8Array<ArrayBuffer>`; `new Uint8Array(length)` is typed the latter way.
 */
function toBytes(buf: Buffer): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(buf.length);
  out.set(buf);
  return out;
}

/** UUID string → its 16 raw bytes (the WebAuthn user handle). */
function uuidToBytes(uuid: string): Uint8Array<ArrayBuffer> {
  return toBytes(Buffer.from(uuid.replace(/-/g, ''), 'hex'));
}

/**
 * A stored credential row (BYTEA id, TEXT[] transports) as the descriptor shape
 * the library expects (Base64URL id, typed transports). `transports` is omitted
 * entirely when absent — exactOptionalPropertyTypes forbids an explicit
 * `undefined`.
 */
function toDescriptor(row: WebAuthnCredentialRow): {
  id: string;
  transports?: AuthenticatorTransportFuture[];
} {
  const id = row.credential_id.toString('base64url');
  if (row.transports && row.transports.length > 0) {
    // TEXT[] widened to the transport union; values originate from the browser.
    return { id, transports: row.transports as AuthenticatorTransportFuture[] };
  }
  return { id };
}

/**
 * WebAuthn/passkey ceremonies (Milestone 2). Wraps @simplewebauthn/server:
 * challenges are minted, persisted server-side, and consumed single-use; a
 * successful authentication is a valid step-up factor (docs/01 §5), mirroring
 * the TOTP stepUp path in AuthService.
 *
 * SCOPING (M2): both ceremonies are session-scoped — the caller already holds a
 * live session and we key everything off `userId`. Passwordless discovery login
 * (resident-key first, no prior session) is deliberately deferred; see README.
 */
@Injectable()
export class WebAuthnService {
  constructor(
    private readonly repo: WebAuthnRepo,
    private readonly sessions: SessionsRepo,
    private readonly authEvents: AuthEventsRepo,
    private readonly events: EventsService,
    @Inject(CONFIG) private readonly config: IdentityConfig,
    @Inject(CLOCK) private readonly clock: Clock,
    private readonly factors: SecondFactorGate,
    // M17 follow-up: the clone signal's whole response is telling the owner, so
    // this service gained the account-security port identity already holds the
    // credential for (M17 PR2). It sends ONE closed kind and can reach nothing
    // else — the wire carries a user id and a kind and has no field for text.
    @Inject(NOTIFICATIONS) private readonly notifications: NotificationsPort,
  ) {}

  private challengeExpiry(): Date {
    return new Date(this.clock().getTime() + WEBAUTHN_CHALLENGE_TTL_MS);
  }

  async startRegistration(
    userId: string,
    caller: Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'>,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    // ADDING A FACTOR TO AN ACCOUNT THAT HAS ONE REQUIRES PROVING ONE.
    //
    // Gated at BOTH ends of the ceremony. This end is where a caller learns
    // they may not, before an authenticator is touched; `finishRegistration` is
    // where the credential is WRITTEN and is therefore the load-bearing one.
    // Neither alone: refusing only here would leave the write ungated for
    // anyone holding a challenge, and refusing only there would walk a
    // legitimate user through a hardware ceremony before telling them no.
    await this.factors.assertMayAddFactor(userId, caller, this.clock());
    const existing = await this.repo.findCredentialsByUser(userId);
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      // No PII in the ceremony: the opaque user id doubles as the user name.
      userName: userId,
      userID: uuidToBytes(userId),
      excludeCredentials: existing.map(toDescriptor),
      // userVerification 'required': a passkey here is a STEP-UP factor
      // (docs/01 §5), so only enroll credentials that perform user verification
      // (PIN/biometric) — a presence-only tap must never satisfy step-up.
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    });
    await this.repo.insertChallenge({
      userId,
      challenge: options.challenge,
      kind: 'registration',
      expiresAt: this.challengeExpiry(),
    });
    return options;
  }

  async finishRegistration(
    userId: string,
    response: RegistrationResponseJSON,
    caller: Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'>,
  ): Promise<{ verified: true }> {
    // THE WRITE, so this is the gate that matters. See `startRegistration`.
    await this.factors.assertMayAddFactor(userId, caller, this.clock());
    const expectedChallenge = await this.repo.consumeChallenge(
      userId,
      'registration',
      this.clock(),
    );
    if (!expectedChallenge) {
      throw registrationFailed();
    }
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin: this.config.rpOrigin,
        expectedRPID: this.config.rpId,
        // Enforce that the credential performed user verification at enrollment.
        requireUserVerification: true,
      });
    } catch {
      // Malformed/forged response — surface a single generic failure.
      throw registrationFailed();
    }
    if (!verification.verified || !verification.registrationInfo) {
      throw registrationFailed();
    }
    const info = verification.registrationInfo;
    // Heuristic: a cross-platform (roaming) authenticator is a hardware key;
    // platform authenticators (Touch ID, Windows Hello) are not.
    const isHardwareKey = response.authenticatorAttachment === 'cross-platform';
    const outcome = await this.repo.insertCredential({
      userId,
      credentialId: Buffer.from(info.credential.id, 'base64url'),
      publicKey: Buffer.from(info.credential.publicKey),
      signCount: info.credential.counter,
      transports: info.credential.transports ?? null,
      aaguid: UUID_RE.test(info.aaguid) ? info.aaguid : null,
      nickname: null,
      isHardwareKey,
    });
    if (outcome === 'duplicate') {
      // This authenticator already backs a credential — on ANOTHER account
      // (excludeCredentials stops same-account re-registration in the
      // browser). One generic refusal: "that authenticator belongs to a
      // different account" is a fact about somebody else's account.
      throw registrationFailed();
    }
    // Append-only local ledger AND the Kafka audit stream (the latter feeds
    // insider-anomaly detection, docs/03 §5.3).
    await this.authEvents.insert({ userId, kind: 'webauthn.registered' });
    await this.events.webauthnRegistered(userId);
    return { verified: true };
  }

  async startAuthentication(userId?: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    let allowCredentials: { id: string; transports?: AuthenticatorTransportFuture[] }[] | undefined;
    if (userId) {
      const creds = await this.repo.findCredentialsByUser(userId);
      allowCredentials = creds.map(toDescriptor);
    }
    const options = await generateAuthenticationOptions({
      rpID: this.config.rpId,
      ...(allowCredentials ? { allowCredentials } : {}),
      // 'required': step-up must be a strong (UV) re-auth, not presence-only.
      userVerification: 'required',
    });
    await this.repo.insertChallenge({
      userId: userId ?? null,
      challenge: options.challenge,
      kind: 'authentication',
      expiresAt: this.challengeExpiry(),
    });
    return options;
  }

  /**
   * Verify an assertion and, on success, elevate the session to a fresh step-up
   * (≤5-minute window) — a passkey is a valid step-up factor per docs/01 §5.
   * Reuses SessionsRepo.grantStepUp, exactly as the TOTP stepUp path does.
   */
  async finishAuthentication(
    userId: string,
    sessionId: string,
    response: AuthenticationResponseJSON,
  ): Promise<StepUpResult> {
    const expectedChallenge = await this.repo.consumeChallenge(
      userId,
      'authentication',
      this.clock(),
    );
    if (!expectedChallenge) {
      // RECORDED, like every other failing branch (M17 PR6). A verify with no
      // live challenge is ordinarily a stale tab — and is also what replaying a
      // captured assertion body looks like, which is precisely the shape an
      // investigator would want to see.
      await this.recordAssertionFailure(userId, sessionId);
      throw authenticationFailed();
    }
    const credentialId = Buffer.from(response.id, 'base64url');
    const cred = await this.repo.findCredentialById(credentialId);
    if (!cred || cred.user_id !== userId) {
      // THE MOST SUSPICIOUS PROBE CLASS OF ALL, and until the M17 PR6 review it
      // was the one that left no trace: a credential id that names nothing, or
      // names somebody ELSE's authenticator, submitted against this account.
      // Nobody's browser produces that by accident. It short-circuits before
      // the crypto verify, so the catch below never saw it — which is how two
      // of the four failing branches came to be silent while PR5's own
      // docstring said the kind existed to make assertion failures visible.
      await this.recordAssertionFailure(userId, sessionId);
      throw authenticationFailed();
    }
    const storedCounter = Number(cred.sign_count);
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: this.config.rpOrigin,
        expectedRPID: this.config.rpId,
        credential: {
          id: cred.credential_id.toString('base64url'),
          // Fresh ArrayBuffer-backed copy to match the library's Uint8Array_.
          publicKey: toBytes(cred.public_key),
          // ZERO, DELIBERATELY — this service owns the counter policy, not the
          // library (M17 follow-up, found by driving the ceremony live).
          //
          // Passing `storedCounter` makes @simplewebauthn/server run its OWN
          // regression check (verifyAuthenticationResponse: `(counter > 0 ||
          // credential.counter > 0) && counter <= credential.counter` throws)
          // — which preempts the clone branch below and made it UNREACHABLE
          // from M2 until this line changed. Measured, not reasoned about: a
          // forced regression produced two `webauthn.assertion_failed` rows and
          // zero `webauthn.clone_detected`, so the ledger kind, the audit
          // action and the owner notification were all dead code behind a
          // refusal that came from somewhere else.
          //
          // Zero is the documented "this RP does not track counters" value, so
          // the library's clause cannot fire, and the check moves below where
          // it runs on a VERIFIED assertion. That ordering is the security
          // half: checking the counter ourselves BEFORE verification would act
          // on unsigned attacker-supplied bytes, letting anyone holding a
          // session make the platform mail the owner a clone warning at will.
          // The trigger set is unchanged for every reachable state — stored 5 /
          // presented 3, and stored 5 / presented 0, both still refuse — so
          // this gives up no refusal and gains the signal.
          counter: 0,
          ...(cred.transports && cred.transports.length > 0
            ? { transports: cred.transports as AuthenticatorTransportFuture[] }
            : {}),
        },
        // The library rejects a presence-only assertion outright…
        requireUserVerification: true,
      });
    } catch {
      await this.recordAssertionFailure(userId, sessionId);
      throw authenticationFailed();
    }
    // …and we gate the step-up elevation on userVerified explicitly (defence in
    // depth): a passkey step-up must be a strong re-auth, never a bare tap.
    if (!verification.verified || !verification.authenticationInfo.userVerified) {
      await this.recordAssertionFailure(userId, sessionId);
      throw authenticationFailed();
    }
    const newCounter = verification.authenticationInfo.newCounter;
    // Clone detection: a non-incrementing counter (when the authenticator
    // reports one at all) means two copies of the credential exist.
    //
    // REJECT AND TELL THE OWNER — and deliberately DO NOT REVOKE, which is the
    // obvious response and the wrong one (the M17 PR6 review's item, answered
    // rather than adopted). The counter check is a HEURISTIC: synced passkeys
    // report 0 and never reach here at all (the `storedCounter > 0` guard), so
    // it fires only on counter-maintaining authenticators, where a regression
    // is a clone OR a firmware/state bug. Destroying a factor on a hint would
    // strip an owner's only passkey without asking — the M6 rule pointed the
    // wrong way — and on an account with no TOTP it lands them in exactly the
    // bootstrap-lockout state M17 spent a milestone making survivable. The
    // owner revokes it themselves, from the surface M17 PR5 shipped.
    if (storedCounter > 0 && newCounter <= storedCounter) {
      // NOTIFY FIRST, then record — the M13 rule. The audit emit propagates
      // broker failures by design, so emitting first would let a Kafka hiccup
      // cancel the one control that makes this signal actionable by the person
      // it is about. The delivery outcome then rides the audit event, so a
      // failed warning is visible rather than merely absent.
      const notice = await this.notifications.sendAccountSecurity({
        userId,
        kind: 'identity.passkey_clone_detected',
      });
      await this.authEvents.insert({
        userId,
        sessionId,
        kind: 'webauthn.clone_detected',
        decision: 'counter_regression',
      });
      await this.events.webauthnCloneDetected(
        userId,
        sessionId,
        notice.accepted && notice.delivered,
      );
      throw authenticationFailed();
    }
    const now = this.clock();
    await this.repo.updateSignCount(credentialId, newCounter, now);
    const stepupExpiresAt = new Date(now.getTime() + STEPUP_WINDOW_MS);
    await this.sessions.grantStepUp(sessionId, stepupExpiresAt);
    await this.authEvents.insert({ userId, sessionId, kind: 'stepup.granted' });
    await this.events.stepUpGranted(userId, sessionId, stepupExpiresAt, 'webauthn');
    return { mfaLevel: 'stepup', stepupExpiresAt: stepupExpiresAt.toISOString() };
  }

  /**
   * A failed assertion, on the ledger (M17 PR5). The 2026-08-10 decision said
   * failed WebAuthn assertions "emit their own kind"; the code emitted NOTHING
   * — an investigator reading the ledger for a §5.1 case saw no trace of
   * assertion failures at all. The kind exists for visibility and is
   * deliberately NOT in any rate-bound set: a passkey assertion is not
   * brute-forceable (the authenticator holds the key), so counting it toward
   * the step-up cap would let a flaky authenticator lock its own owner out.
   * `rate-bounds.ts` records the exclusion beside the sets.
   */
  private async recordAssertionFailure(userId: string, sessionId: string): Promise<void> {
    await this.authEvents.insert({ userId, sessionId, kind: 'webauthn.assertion_failed' });
  }

  /** The management projection (M17 PR5) — see `WebAuthnRepo.listForUser`. */
  async listCredentials(userId: string): Promise<
    Array<{
      id: string;
      nickname: string | null;
      isHardwareKey: boolean;
      createdAt: string;
      lastUsedAt: string | null;
    }>
  > {
    const rows = await this.repo.listForUser(userId);
    return rows.map((row) => ({
      id: row.id,
      nickname: row.nickname,
      isHardwareKey: row.is_hardware_key,
      createdAt: row.created_at.toISOString(),
      lastUsedAt: row.last_used_at ? row.last_used_at.toISOString() : null,
    }));
  }

  /**
   * Revoke one passkey (M17 PR5). STEP-UP GATED AT THE ROUTE, and the reason
   * is the downgrade attack rather than ceremony for its own sake: an ungated
   * revoke plus a stolen bearer strips the account's factors, which DISARMS
   * `SecondFactorGate` (no factor ⇒ nothing to prove ⇒ enrolment ungated), and
   * the thief then enrols their own factor and owns step-up — the 2026-08-12
   * escalation reached through the back door. The M6 "protective action never
   * harder" rule does not apply because removing a factor is not protective:
   * it weakens the gate that protects everything else. Contrast the M16
   * session revoke, which stays ungated because revoking a session only ever
   * REDUCES authority.
   *
   * Returns whether anything was revoked; the route answers a uniform 404
   * otherwise (no such credential and not-yours are one answer).
   */
  async revokeCredential(userId: string, id: string): Promise<boolean> {
    if (!UUID_RE.test(id)) {
      return false;
    }
    const revoked = await this.repo.revokeCredential(userId, id, this.clock());
    if (revoked) {
      await this.authEvents.insert({ userId, kind: 'webauthn.revoked' });
      await this.events.webauthnRevoked(userId);
    }
    return revoked;
  }

  /** Name one passkey — a display label, ungated beyond the session (the
   * `documents.title` class). Uniform 404 semantics like the revoke. */
  async renameCredential(userId: string, id: string, nickname: string): Promise<boolean> {
    if (!UUID_RE.test(id)) {
      return false;
    }
    return this.repo.renameCredential(userId, id, nickname);
  }
}
