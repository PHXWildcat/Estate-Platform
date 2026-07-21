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
import { WebAuthnService } from '../src/webauthn.service';

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
const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';

function makeFakes(): {
  repo: {
    insertCredential: jest.Mock;
    findCredentialsByUser: jest.Mock;
    findCredentialById: jest.Mock;
    updateSignCount: jest.Mock;
    insertChallenge: jest.Mock;
    consumeChallenge: jest.Mock;
  };
  sessions: { grantStepUp: jest.Mock };
  authEvents: { insert: jest.Mock };
  events: { stepUpGranted: jest.Mock };
} {
  return {
    repo: {
      insertCredential: jest.fn(),
      findCredentialsByUser: jest.fn().mockResolvedValue([]),
      findCredentialById: jest.fn().mockResolvedValue(null),
      updateSignCount: jest.fn(),
      insertChallenge: jest.fn(),
      consumeChallenge: jest.fn().mockResolvedValue(null),
    },
    sessions: { grantStepUp: jest.fn() },
    authEvents: { insert: jest.fn() },
    events: { stepUpGranted: jest.fn() },
  };
}

const config: IdentityConfig = {
  nodeEnv: 'test',
  port: 3001,
  databaseUrl: 'postgres://unused',
  kmsMasterKey: Buffer.alloc(32, 7),
  emailIndexKey: Buffer.alloc(32, 9),
  kafkaBrokers: null,
  kekAlias: 'test/kek',
  rpId: 'localhost',
  rpOrigin: 'http://localhost:3000',
  rpName: 'Estate Platform',
};

function makeService(fakes: ReturnType<typeof makeFakes>): WebAuthnService {
  return new WebAuthnService(
    fakes.repo as unknown as WebAuthnRepo,
    fakes.sessions as unknown as SessionsRepo,
    fakes.authEvents as unknown as AuthEventsRepo,
    fakes.events as unknown as EventsService,
    config,
    () => NOW,
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

    const options = await service.startRegistration(USER_ID);

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

    await expect(service.finishRegistration(USER_ID, response)).rejects.toBeInstanceOf(
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

    const result = await service.finishRegistration(USER_ID, response);

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

    await expect(service.finishRegistration(USER_ID, response)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(fakes.repo.insertCredential).not.toHaveBeenCalled();
  });

  it('does not leak library errors (throws the generic failure instead)', async () => {
    const fakes = makeFakes();
    fakes.repo.consumeChallenge.mockResolvedValue('reg-challenge');
    mockVerifyReg.mockRejectedValue(new Error('unexpected attestation format: xyz'));
    const service = makeService(fakes);

    await expect(service.finishRegistration(USER_ID, response)).rejects.toEqual(
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
      authenticationInfo: { newCounter: 6 },
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
      authenticationInfo: { newCounter: 5 }, // did not advance ⇒ clone
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
      authenticationInfo: { newCounter: 0 }, // authenticator reports no counter
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);
    const service = makeService(fakes);

    const result = await service.finishAuthentication(USER_ID, SESSION_ID, response);
    expect(result.mfaLevel).toBe('stepup');
    expect(fakes.sessions.grantStepUp).toHaveBeenCalledTimes(1);
  });
});
