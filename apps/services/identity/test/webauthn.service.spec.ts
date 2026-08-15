/**
 * Unit tests for WebAuthnService. The @simplewebauthn/server library is mocked
 * so we can drive controlled `{ verified, registrationInfo/authenticationInfo }`
 * results and assert our own invariants: challenges are persisted then consumed
 * single-use, credentials are persisted on success, clone detection rejects a
 * non-monotonic counter, and every failure path throws a generic error.
 */
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import type { SessionsRepo } from '../src/sessions.repo';
import type { WebAuthnCredentialRow, WebAuthnRepo } from '../src/webauthn.repo';
import type { SecondFactorGate } from '../src/second-factor-gate';
import { WebAuthnService } from '../src/webauthn.service';
import { DELIVERED, UNREACHABLE } from './notifications-double';

jest.mock('@simplewebauthn/server');

const mockGenReg = generateRegistrationOptions as jest.MockedFunction<
  typeof generateRegistrationOptions
>;
const mockGenAuth = generateAuthenticationOptions as jest.MockedFunction<
  typeof generateAuthenticationOptions
>;
const mockVerifyReg = verifyRegistrationResponse as jest.MockedFunction<
  typeof verifyRegistrationResponse
>;
const mockVerifyAuth = verifyAuthenticationResponse as jest.MockedFunction<
  typeof verifyAuthenticationResponse
>;

const NOW = new Date('2026-07-21T12:00:00Z');
/** A session with no step-up — the gate is stubbed here, so it only has to typecheck. */
const NO_STEPUP = { mfaLevel: 'none', stepupExpiresAt: null } as const;
const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';

function makeFakes(): {
  repo: {
    insertCredential: jest.Mock;
    findCredentialsByUser: jest.Mock;
    findCredentialById: jest.Mock;
    revokeCredential: jest.Mock;
    updateSignCount: jest.Mock;
    insertChallenge: jest.Mock;
    consumeChallenge: jest.Mock;
  };
  sessions: { grantStepUp: jest.Mock };
  factors: { assertMayAddFactor: jest.Mock; holdsVerifiedFactor: jest.Mock };
  notifications: { sendAccountSecurity: jest.Mock };
  authEvents: { insert: jest.Mock };
  events: {
    stepUpGranted: jest.Mock;
    webauthnRegistered: jest.Mock;
    webauthnCloneDetected: jest.Mock;
  };
} {
  return {
    repo: {
      insertCredential: jest.fn(),
      findCredentialsByUser: jest.fn().mockResolvedValue([]),
      findCredentialById: jest.fn().mockResolvedValue(null),
      // Present so the clone case's `not.toHaveBeenCalled` is a real assertion
      // rather than one about an absent method — an undefined mock would let
      // that expectation pass vacuously, which is the shape this repo keeps
      // finding in its own tests.
      revokeCredential: jest.fn(),
      updateSignCount: jest.fn(),
      insertChallenge: jest.fn(),
      consumeChallenge: jest.fn().mockResolvedValue(null),
    },
    sessions: { grantStepUp: jest.fn() },
    // Stubbed permissive: the gate's own behaviour is pinned against real
    // Postgres in `factor-enrollment-gate.int.spec.ts`. These cases are about
    // the ceremony, and a gate that refused here would mask them.
    factors: {
      assertMayAddFactor: jest.fn().mockResolvedValue(undefined),
      holdsVerifiedFactor: jest.fn().mockResolvedValue(false),
    },
    notifications: {
      // The clone branch's ONLY outbound call. Defaults to a delivered send;
      // the case that cares about a failed one overrides it, because a double
      // that always succeeds cannot see the `notified: failed` path.
      sendAccountSecurity: jest.fn().mockResolvedValue(DELIVERED),
    },
    authEvents: { insert: jest.fn() },
    events: {
      stepUpGranted: jest.fn(),
      webauthnRegistered: jest.fn(),
      webauthnCloneDetected: jest.fn(),
    },
  };
}

const config: IdentityConfig = {
  nodeEnv: 'test',
  port: 3001,
  databaseUrl: 'postgres://unused',
  kms: { mode: 'local', masterKey: Buffer.alloc(32, 7) },
  emailIndexKey: Buffer.alloc(32, 9),
  kafkaBrokers: null,
  kekAlias: 'test/kek',
  rpId: 'localhost',
  rpOrigin: 'http://localhost:3000',
  rpName: 'Estate Platform',
  internalApiToken: '',
  notificationsUrl: 'http://localhost:3008',
  notificationsInternalToken: '',
  notificationsVerifyToken: '',
  notificationsStatusToken: '',
  notificationsSecurityToken: '',
  notificationsEmailChangeToken: 'echange-secret',
  notificationsRecoveryToken: '',
};

function makeService(fakes: ReturnType<typeof makeFakes>): WebAuthnService {
  return new WebAuthnService(
    fakes.repo as unknown as WebAuthnRepo,
    fakes.sessions as unknown as SessionsRepo,
    fakes.authEvents as unknown as AuthEventsRepo,
    fakes.events as unknown as EventsService,
    config,
    () => NOW,
    fakes.factors as unknown as SecondFactorGate,
    fakes.notifications as never,
  );
}

function credRow(overrides: Partial<WebAuthnCredentialRow> = {}): WebAuthnCredentialRow {
  return {
    id: 'cred-row-1',
    user_id: USER_ID,
    credential_id: Buffer.from('credential-id-bytes'),
    public_key: Buffer.from('public-key-bytes'),
    sign_count: '5',
    transports: ['internal'],
    aaguid: null,
    nickname: null,
    is_hardware_key: false,
    ...overrides,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe('WebAuthnService.startRegistration', () => {
  it('persists the returned challenge and excludes existing credentials', async () => {
    const fakes = makeFakes();
    fakes.repo.findCredentialsByUser.mockResolvedValue([credRow()]);
    mockGenReg.mockResolvedValue({
      challenge: 'reg-challenge',
    } as Awaited<ReturnType<typeof generateRegistrationOptions>>);
    const service = makeService(fakes);

    const options = await service.startRegistration(USER_ID, NO_STEPUP);

    expect(options.challenge).toBe('reg-challenge');
    const genArgs = mockGenReg.mock.calls[0]?.[0];
    expect(genArgs?.rpName).toBe('Estate Platform');
    expect(genArgs?.rpID).toBe('localhost');
    expect(genArgs?.excludeCredentials).toHaveLength(1);
    expect(fakes.repo.insertChallenge).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: USER_ID,
        challenge: 'reg-challenge',
        kind: 'registration',
      }),
    );
    // Challenge expiry is in the future (single-use, short-lived).
    const [{ expiresAt }] = fakes.repo.insertChallenge.mock.calls[0] as [{ expiresAt: Date }];
    expect(expiresAt.getTime()).toBeGreaterThan(NOW.getTime());
  });
});

describe('WebAuthnService.finishRegistration', () => {
  const response = {
    id: 'resp-id',
    authenticatorAttachment: 'cross-platform',
  } as unknown as RegistrationResponseJSON;

  it('rejects when there is no matching (single-use) challenge', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue(null);
    const service = makeService(fakes);

    await expect(service.finishRegistration(USER_ID, response, NO_STEPUP)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(fakes.repo.consumeChallenge).toHaveBeenCalledWith(USER_ID, 'registration', NOW);
    expect(mockVerifyReg).not.toHaveBeenCalled();
    expect(fakes.repo.insertCredential).not.toHaveBeenCalled();
  });

  it('persists a credential and audits on a verified attestation', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('reg-challenge');
    mockVerifyReg.mockResolvedValue({
      verified: true,
      registrationInfo: {
        aaguid: '00000000-0000-0000-0000-000000000000',
        credential: {
          id: Buffer.from('new-cred').toString('base64url'),
          publicKey: new Uint8Array([1, 2, 3]),
          counter: 0,
          transports: ['usb'],
        },
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
      },
    } as unknown as Awaited<ReturnType<typeof verifyRegistrationResponse>>);
    const service = makeService(fakes);

    const result = await service.finishRegistration(USER_ID, response, NO_STEPUP);

    expect(result).toEqual({ verified: true });
    // Challenge is consumed (single-use) before verification runs.
    expect(fakes.repo.consumeChallenge).toHaveBeenCalledTimes(1);
    const verifyArgs = mockVerifyReg.mock.calls[0]?.[0];
    expect(verifyArgs?.expectedChallenge).toBe('reg-challenge');
    expect(verifyArgs?.expectedOrigin).toBe('http://localhost:3000');
    expect(verifyArgs?.expectedRPID).toBe('localhost');
    const [inserted] = fakes.repo.insertCredential.mock.calls[0] as [
      { userId: string; credentialId: Buffer; signCount: number; isHardwareKey: boolean },
    ];
    expect(inserted.userId).toBe(USER_ID);
    expect(inserted.credentialId.toString('utf8')).toBe('new-cred');
    expect(inserted.signCount).toBe(0);
    expect(inserted.isHardwareKey).toBe(true); // cross-platform ⇒ hardware key
    expect(fakes.authEvents.insert).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'webauthn.registered' }),
    );
  });

  it('throws a generic error when the attestation does not verify', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('reg-challenge');
    mockVerifyReg.mockResolvedValue({ verified: false });
    const service = makeService(fakes);

    await expect(service.finishRegistration(USER_ID, response, NO_STEPUP)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(fakes.repo.insertCredential).not.toHaveBeenCalled();
  });

  it('does not leak library errors (throws the generic failure instead)', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('reg-challenge');
    mockVerifyReg.mockRejectedValue(new Error('unexpected attestation format: xyz'));
    const service = makeService(fakes);

    await expect(service.finishRegistration(USER_ID, response, NO_STEPUP)).rejects.toEqual(
      new BadRequestException({ error: 'webauthn_failed' }),
    );
  });
});

describe('WebAuthnService.startAuthentication', () => {
  it('scopes allowCredentials to the user and persists the challenge', async () => {
    const fakes = makeFakes();
    fakes.repo.findCredentialsByUser.mockResolvedValue([credRow()]);
    mockGenAuth.mockResolvedValue({
      challenge: 'auth-challenge',
    });
    const service = makeService(fakes);

    const options = await service.startAuthentication(USER_ID);

    expect(options.challenge).toBe('auth-challenge');
    expect(mockGenAuth.mock.calls[0]?.[0]?.allowCredentials).toHaveLength(1);
    expect(fakes.repo.insertChallenge).toHaveBeenCalledWith(
      expect.objectContaining({ userId: USER_ID, kind: 'authentication' }),
    );
  });
});

describe('WebAuthnService.finishAuthentication', () => {
  const response = {
    id: Buffer.from('credential-id-bytes').toString('base64url'),
  } as unknown as AuthenticationResponseJSON;

  it('elevates the session to step-up on a valid, monotonic assertion', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('auth-challenge');
    fakes.repo.findCredentialById.mockResolvedValue(credRow({ sign_count: '5' }));
    mockVerifyAuth.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 6, userVerified: true },
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);
    const service = makeService(fakes);

    const result = await service.finishAuthentication(USER_ID, SESSION_ID, response);

    expect(result.mfaLevel).toBe('stepup');
    expect(fakes.repo.updateSignCount).toHaveBeenCalledWith(expect.any(Buffer), 6, NOW);
    expect(fakes.sessions.grantStepUp).toHaveBeenCalledWith(SESSION_ID, expect.any(Date));
    expect(fakes.events.stepUpGranted).toHaveBeenCalledWith(
      USER_ID,
      SESSION_ID,
      expect.any(Date),
      'webauthn',
    );
  });

  it('rejects a cloned authenticator (non-monotonic counter) without elevating', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('auth-challenge');
    fakes.repo.findCredentialById.mockResolvedValue(credRow({ sign_count: '5' }));
    mockVerifyAuth.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 5, userVerified: true }, // did not advance ⇒ clone
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);
    const service = makeService(fakes);

    await expect(
      service.finishAuthentication(USER_ID, SESSION_ID, response),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(fakes.sessions.grantStepUp).not.toHaveBeenCalled();
    expect(fakes.repo.updateSignCount).not.toHaveBeenCalled();
    expect(fakes.authEvents.insert).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'webauthn.clone_detected', decision: 'counter_regression' }),
    );
    // …AND THE CREDENTIAL SURVIVES. The M17 PR6 review proposed auto-revoking
    // here; this asserts the answer taken instead. The counter check is a
    // heuristic, and destroying an owner's only factor on a heuristic is the
    // M6 rule pointed the wrong way — so the owner is TOLD and revokes it
    // themselves from the M17 PR5 surface.
    expect(fakes.repo.revokeCredential).not.toHaveBeenCalled();
    expect(fakes.notifications.sendAccountSecurity).toHaveBeenCalledWith({
      userId: USER_ID,
      kind: 'identity.passkey_clone_detected',
    });
    expect(fakes.events.webauthnCloneDetected).toHaveBeenCalledWith(USER_ID, SESSION_ID, true);
  });

  it('OWNS THE COUNTER POLICY — the library is told 0 so its check cannot preempt ours', () => {
    // The regression this pins is the one the live drive found: passing
    // `storedCounter` lets @simplewebauthn/server throw on the regression
    // first, which routes a clone into the generic verify catch and makes the
    // clone branch — its ledger kind, its audit action and the owner's warning
    // — unreachable. Asserted against the ARGUMENT the library actually
    // receives, which is the only place the property lives.
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('auth-challenge');
    fakes.repo.findCredentialById.mockResolvedValue(credRow({ sign_count: '5' }));
    mockVerifyAuth.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 6, userVerified: true },
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);

    return makeService(fakes)
      .finishAuthentication(USER_ID, SESSION_ID, response)
      .then(() => {
        const passed = mockVerifyAuth.mock.calls[0]?.[0] as {
          credential: { counter: number };
        };
        expect(passed.credential.counter).toBe(0);
      });
  });

  it('NOTIFIES BEFORE it records, so a broker hiccup cannot cancel the warning', async () => {
    // The M13 ordering rule. `webauthnCloneDetected` reaches Kafka and
    // propagates broker failures by design, so emitting first would let an
    // audit outage swallow the one control that makes this signal actionable
    // by the person it is about.
    const fakes = makeFakes();
    const order: string[] = [];
    fakes.repo.consumeChallenge.mockResolvedValue('auth-challenge');
    fakes.repo.findCredentialById.mockResolvedValue(credRow({ sign_count: '5' }));
    fakes.notifications.sendAccountSecurity.mockImplementation(() => {
      order.push('notify');
      return Promise.resolve(DELIVERED);
    });
    fakes.events.webauthnCloneDetected.mockImplementation(() => {
      order.push('audit');
      return Promise.resolve();
    });
    mockVerifyAuth.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 5, userVerified: true },
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);

    await expect(
      makeService(fakes).finishAuthentication(USER_ID, SESSION_ID, response),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(order).toEqual(['notify', 'audit']);
  });

  it('a FAILED warning is recorded as failed — visible, not merely absent', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('auth-challenge');
    fakes.repo.findCredentialById.mockResolvedValue(credRow({ sign_count: '5' }));
    fakes.notifications.sendAccountSecurity.mockResolvedValue(UNREACHABLE);
    mockVerifyAuth.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 5, userVerified: true },
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);

    // The refusal still happens: the notification is the SIGNAL, the rejection
    // is the CONTROL, and a send failure must never roll back a refusal (M6/M9).
    await expect(
      makeService(fakes).finishAuthentication(USER_ID, SESSION_ID, response),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(fakes.events.webauthnCloneDetected).toHaveBeenCalledWith(USER_ID, SESSION_ID, false);
  });

  it('rejects when no challenge was outstanding', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue(null);
    const service = makeService(fakes);

    await expect(
      service.finishAuthentication(USER_ID, SESSION_ID, response),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(mockVerifyAuth).not.toHaveBeenCalled();
  });

  it('rejects when the credential is unknown or belongs to another user', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('auth-challenge');
    fakes.repo.findCredentialById.mockResolvedValue(credRow({ user_id: 'someone-else' }));
    const service = makeService(fakes);

    await expect(
      service.finishAuthentication(USER_ID, SESSION_ID, response),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(mockVerifyAuth).not.toHaveBeenCalled();
    expect(fakes.sessions.grantStepUp).not.toHaveBeenCalled();
  });

  it('allows the first use of a fresh credential (stored counter 0)', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('auth-challenge');
    fakes.repo.findCredentialById.mockResolvedValue(credRow({ sign_count: '0' }));
    mockVerifyAuth.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 0, userVerified: true }, // authenticator reports no counter
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);
    const service = makeService(fakes);

    const result = await service.finishAuthentication(USER_ID, SESSION_ID, response);
    expect(result.mfaLevel).toBe('stepup');
    expect(fakes.sessions.grantStepUp).toHaveBeenCalledTimes(1);
  });

  it('rejects a presence-only assertion (userVerified false) — step-up needs UV', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('auth-challenge');
    fakes.repo.findCredentialById.mockResolvedValue(credRow({ sign_count: '5' }));
    mockVerifyAuth.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 6, userVerified: false }, // tap only, no PIN/biometric
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);
    const service = makeService(fakes);

    await expect(
      service.finishAuthentication(USER_ID, SESSION_ID, response),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(fakes.sessions.grantStepUp).not.toHaveBeenCalled();
    expect(fakes.repo.updateSignCount).not.toHaveBeenCalled();
  });
});
