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
import { AuthEventsRepo } from './auth-events.repo';
import type { StepUpResult } from './auth.service';
import type { IdentityConfig } from './config';
import { CLOCK, CONFIG, type Clock } from './di-tokens';
import { EventsService } from './events.service';
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
  ) {}

  private challengeExpiry(): Date {
    return new Date(this.clock().getTime() + WEBAUTHN_CHALLENGE_TTL_MS);
  }

  async startRegistration(userId: string): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const existing = await this.repo.findCredentialsByUser(userId);
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      // No PII in the ceremony: the opaque user id doubles as the user name.
      userName: userId,
      userID: uuidToBytes(userId),
      excludeCredentials: existing.map(toDescriptor),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
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
  ): Promise<{ verified: true }> {
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
    await this.repo.insertCredential({
      userId,
      credentialId: Buffer.from(info.credential.id, 'base64url'),
      publicKey: Buffer.from(info.credential.publicKey),
      signCount: info.credential.counter,
      transports: info.credential.transports ?? null,
      aaguid: UUID_RE.test(info.aaguid) ? info.aaguid : null,
      nickname: null,
      isHardwareKey,
    });
    // Audit lands in the append-only local auth_events ledger. A dedicated
    // Kafka AuditAction (e.g. auth.webauthn.registered) needs a new enum value
    // in @estate/contracts — out of this milestone's scope; see README gap.
    await this.authEvents.insert({ userId, kind: 'webauthn.registered' });
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
      userVerification: 'preferred',
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
      throw authenticationFailed();
    }
    const credentialId = Buffer.from(response.id, 'base64url');
    const cred = await this.repo.findCredentialById(credentialId);
    if (!cred || cred.user_id !== userId) {
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
          counter: storedCounter,
          ...(cred.transports && cred.transports.length > 0
            ? { transports: cred.transports as AuthenticatorTransportFuture[] }
            : {}),
        },
      });
    } catch {
      throw authenticationFailed();
    }
    if (!verification.verified) {
      throw authenticationFailed();
    }
    const newCounter = verification.authenticationInfo.newCounter;
    // Clone detection: a non-incrementing counter (when the authenticator
    // reports one at all) means two copies of the credential exist. Reject.
    if (storedCounter > 0 && newCounter <= storedCounter) {
      await this.authEvents.insert({
        userId,
        sessionId,
        kind: 'webauthn.clone_detected',
        decision: 'counter_regression',
      });
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
}
