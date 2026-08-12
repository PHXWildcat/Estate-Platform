/**
 * BINDING A PASSKEY TO SOMEBODY ELSE'S ACCOUNT — the escalation, closed.
 *
 * The M16 PR5 review found and fixed the TOTP form of this. VERIFYING that fix
 * found the identical escalation still open through WebAuthn, and it was
 * MEASURED end to end against real Postgres before anything was changed:
 *
 *   1. startRegistration      : OK, challenge issued
 *   2. finishRegistration     : credentials now on the account = 1
 *   3. finishAuthentication   : {"mfaLevel":"stepup", ...}
 *   4. attacker session in DB : mfa_level=stepup, stepup_expires_at live
 *   5. victim's live TOTP     : 1
 *
 * Line 4 is the one that mattered — the attacker's session row, actually
 * elevated. `excludeCredentials` looks protective and is not: it stops
 * re-registering the SAME authenticator, never a different one.
 *
 * IT WAS QUIETER THAN THE TOTP VERSION, which is why it is worth its own file.
 * That one locked the owner out (`findActiveTotp` takes the newest, so their
 * codes started failing — a signal). Here the victim's factors keep working, so
 * nothing they can observe changes. Line 5 above is that difference, measured.
 *
 * ═══ WHAT IS REAL HERE AND WHAT IS STOOD IN FOR ═══
 *
 * REAL: the WebAuthnRepo against Postgres (challenges, credential rows, the
 * lookup SQL), the real WebAuthnService, the real SecondFactorGate over the
 * real repos, the real SessionsRepo write, and the real auth_events ledger.
 *
 * STOOD IN FOR: `@simplewebauthn/server`'s cryptographic verification — and the
 * distinction matters, because this is faithful rather than a shortcut. The
 * attacker is not forging an attestation. They physically hold their own
 * security key and complete a genuine ceremony with it. The question is not
 * "can a signature be forged" but "does the service let a session-only caller
 * bind a NEW authenticator to somebody else's account and then elevate with
 * it", and everything that answers that question runs for real.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import type { SessionContext } from '@estate/auth-guard';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { AuthEventsRepo } from '../src/auth-events.repo';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import { MfaRepo } from '../src/mfa.repo';
import { SecondFactorGate } from '../src/second-factor-gate';
import { SessionsRepo } from '../src/sessions.repo';
import { STEPUP_WINDOW_MS } from '../src/stepup';
import { WebAuthnRepo } from '../src/webauthn.repo';
import { WebAuthnService } from '../src/webauthn.service';
import { Db } from '../src/db';

jest.mock('@simplewebauthn/server', () => ({
  ...jest.requireActual<Record<string, unknown>>('@simplewebauthn/server'),
  verifyRegistrationResponse: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
}));

const mockVerifyReg = verifyRegistrationResponse as jest.MockedFunction<
  typeof verifyRegistrationResponse
>;
const mockVerifyAuth = verifyAuthenticationResponse as jest.MockedFunction<
  typeof verifyAuthenticationResponse
>;

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;
const NOW = new Date('2026-08-12T12:00:00.000Z');

/** What a stolen credential is: authenticated, but nothing proved. */
const NO_STEPUP: Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'> = {
  mfaLevel: 'none',
  stepupExpiresAt: null,
};
const FRESH_STEPUP: Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'> = {
  mfaLevel: 'stepup',
  stepupExpiresAt: new Date(NOW.getTime() + STEPUP_WINDOW_MS),
};

describeIfPg('registering a passkey (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitywa_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let service: WebAuthnService;

  /** Seed a user, optionally already holding a verified TOTP factor. */
  async function seedUser(withTotp: boolean): Promise<string> {
    const id = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [id, Buffer.from(`ct-${id}`), Buffer.from(`bidx-${id}`), randomUUID()],
    );
    if (withTotp) {
      await admin.query(
        `INSERT INTO ${schema}.mfa_methods (id, user_id, kind, secret_ct, verified_at)
         VALUES ($1, $2, 'totp', $3, now())`,
        [randomUUID(), id, Buffer.from('SECRETSECRETSECR')],
      );
    }
    return id;
  }

  /** A ceremony completed on the caller's OWN authenticator. */
  function ceremonySucceeds(credentialId: string): void {
    mockVerifyReg.mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: {
          id: credentialId,
          publicKey: new Uint8Array([1, 2, 3, 4]),
          counter: 0,
          transports: ['usb'],
        },
        aaguid: '00000000-0000-0000-0000-000000000000',
      },
    } as unknown as Awaited<ReturnType<typeof verifyRegistrationResponse>>);
  }

  const REGISTRATION = {
    authenticatorAttachment: 'cross-platform',
  } as unknown as RegistrationResponseJSON;

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    const migrClient = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await migrClient.connect();
    try {
      await new Migrator(migrClient, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await migrClient.end();
    }
    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    service = new WebAuthnService(
      new WebAuthnRepo(db),
      new SessionsRepo(db),
      new AuthEventsRepo(db),
      {
        stepUpGranted: (): Promise<void> => Promise.resolve(),
        webauthnRegistered: (): Promise<void> => Promise.resolve(),
        webauthnCloneDetected: (): Promise<void> => Promise.resolve(),
      } as unknown as EventsService,
      { rpName: 'Estate', rpId: 'localhost', rpOrigin: 'http://localhost:3000' } as IdentityConfig,
      () => NOW,
      // THE REAL GATE over the real repos — a fake would make this file vacuous.
      new SecondFactorGate(new MfaRepo(db), new WebAuthnRepo(db)),
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  it('REFUSES a session-only caller when the account already holds a factor', async () => {
    // The measured escalation, refused at its first request. The account holds
    // TOTP and no passkey — a per-factor predicate would have admitted this.
    const victim = await seedUser(true);
    await expect(service.startRegistration(victim, NO_STEPUP)).rejects.toMatchObject({
      status: 403,
      response: { error: 'stepup_required' },
    });
  });

  it('REFUSES AT THE WRITE TOO, not only where the challenge is issued', async () => {
    // Both ends are gated, and this is the load-bearing one: a caller holding a
    // challenge issued while they were still elevated must not be able to spend
    // it after the window lapsed.
    const victim = await seedUser(true);
    await service.startRegistration(victim, FRESH_STEPUP);
    ceremonySucceeds(Buffer.from('late-key').toString('base64url'));

    await expect(service.finishRegistration(victim, REGISTRATION, NO_STEPUP)).rejects.toMatchObject(
      { status: 403, response: { error: 'stepup_required' } },
    );

    const { rows } = await admin.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${schema}.webauthn_credentials WHERE user_id = $1`,
      [victim],
    );
    expect(rows[0]?.n).toBe('0');
  });

  it('ADMITS the FIRST passkey on an ordinary session — the bootstrap', async () => {
    // An account with no factor at all has nothing to prove, so gating here
    // would make a first factor unreachable forever.
    const fresh = await seedUser(false);
    const options = await service.startRegistration(fresh, NO_STEPUP);
    expect(typeof options.challenge).toBe('string');
    ceremonySucceeds(Buffer.from('first-key').toString('base64url'));
    await expect(service.finishRegistration(fresh, REGISTRATION, NO_STEPUP)).resolves.toEqual({
      verified: true,
    });
  });

  it('ADMITS a second passkey behind a fresh step-up, so the legitimate path completes', async () => {
    const owner = await seedUser(true);
    await service.startRegistration(owner, FRESH_STEPUP);
    ceremonySucceeds(Buffer.from('second-key').toString('base64url'));
    await expect(service.finishRegistration(owner, REGISTRATION, FRESH_STEPUP)).resolves.toEqual({
      verified: true,
    });
  });

  it('A PASSKEY ALONE arms the gate against adding another', async () => {
    // The cross-type half from the other side: this account has no TOTP, so
    // `hasVerifiedTotp` is false for it and the first fix would have admitted
    // a session-only caller.
    const passkeyOnly = await seedUser(false);
    await service.startRegistration(passkeyOnly, NO_STEPUP);
    ceremonySucceeds(Buffer.from('only-key').toString('base64url'));
    await service.finishRegistration(passkeyOnly, REGISTRATION, NO_STEPUP);

    await expect(service.startRegistration(passkeyOnly, NO_STEPUP)).rejects.toMatchObject({
      status: 403,
    });
  });

  it('THE ESCALATION, END TO END: no credential is bound, so none can elevate', async () => {
    const victim = await seedUser(true);
    const attackerSession = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.sessions
         (id, user_id, access_token_h, refresh_token_h, mfa_level, audience,
          access_expires_at, expires_at)
       VALUES ($1, $2, $3, $4, 'none', 'account', now() + interval '1 hour',
               now() + interval '30 days')`,
      [
        attackerSession,
        victim,
        Buffer.from(`a-${attackerSession}`),
        Buffer.from(`r-${attackerSession}`),
      ],
    );

    await expect(service.startRegistration(victim, NO_STEPUP)).rejects.toMatchObject({
      status: 403,
    });

    // Nothing was bound, so there is nothing to authenticate with...
    const { rows: creds } = await admin.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${schema}.webauthn_credentials WHERE user_id = $1`,
      [victim],
    );
    expect(creds[0]?.n).toBe('0');

    // ...and the attacker's session is still un-elevated in the DATABASE, which
    // is where the measurement that opened this file found `mfa_level=stepup`.
    const { rows: sess } = await admin.query<{ mfa_level: string; stepup_expires_at: Date | null }>(
      `SELECT mfa_level, stepup_expires_at FROM ${schema}.sessions WHERE id = $1`,
      [attackerSession],
    );
    expect({ level: sess[0]?.mfa_level, until: sess[0]?.stepup_expires_at }).toEqual({
      level: 'none',
      until: null,
    });
  });

  it('an authentication ceremony still elevates a LEGITIMATE holder', async () => {
    // The gate must not have broken the thing passkeys are for.
    const owner = await seedUser(false);
    const ownerSession = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.sessions
         (id, user_id, access_token_h, refresh_token_h, mfa_level, audience,
          access_expires_at, expires_at)
       VALUES ($1, $2, $3, $4, 'none', 'account', now() + interval '1 hour',
               now() + interval '30 days')`,
      [ownerSession, owner, Buffer.from(`a-${ownerSession}`), Buffer.from(`r-${ownerSession}`)],
    );
    const credentialId = Buffer.from('owner-key').toString('base64url');
    await service.startRegistration(owner, NO_STEPUP); // bootstrap: allowed
    ceremonySucceeds(credentialId);
    await service.finishRegistration(owner, REGISTRATION, NO_STEPUP);

    await service.startAuthentication(owner);
    mockVerifyAuth.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1, userVerified: true },
    } as unknown as Awaited<ReturnType<typeof verifyAuthenticationResponse>>);

    await expect(
      service.finishAuthentication(owner, ownerSession, {
        id: credentialId,
      } as unknown as AuthenticationResponseJSON),
    ).resolves.toMatchObject({ mfaLevel: 'stepup' });
  });
});
