/**
 * ADDING A SECOND FACTOR TO AN ACCOUNT THAT ALREADY HAS ONE (M16 review).
 *
 * The defect this pins is PRE-EXISTING and was the worst thing the review
 * found. `POST /v1/auth/totp/enroll` had been `SessionGuard`-only since M2, and
 * `revokeUnverifiedTotp` spares a VERIFIED method while `findActiveTotp` takes
 * the NEWEST one — so a caller holding nothing but a stolen session could enrol
 * a secret of their own, confirm it with a code they computed themselves, and
 * step up. Three ordinary requests, no guessing. Step-up stopped being a second
 * factor for anyone holding a session, and the owner's own authenticator
 * answered 401 afterwards, so it was a takeover and a lockout at once —
 * including of docs/03 §5.1's liveness proof.
 *
 * AGAINST REAL POSTGRES, because both halves are SQL. `hasVerifiedTotp` is a
 * predicate and `findActiveTotp`'s ordering is the thing that made the
 * escalation work; a faked repo cannot get either wrong, which is exactly the
 * M13 rule about which layer a test proves. Only the crypto is stubbed, and
 * store-the-bytes is faithful for a question about WHICH ROW is selected.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import type { SessionContext } from '@estate/auth-guard';
import type { DekRepository, FieldCrypto } from '@estate/crypto';
import { AuthEventsRepo } from '../src/auth-events.repo';
import { AuthService } from '../src/auth.service';
import type { EmailVerificationService } from '../src/email-verification.service';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import { MfaRepo } from '../src/mfa.repo';
import type { PasswordHasher } from '../src/password';
import type { SessionsRepo } from '../src/sessions.repo';
import { STEPUP_WINDOW_MS } from '../src/stepup';
import type { UsersRepo } from '../src/users.repo';
import { Db } from '../src/db';
import { currentTotpCode, generateTotpSecretBase32 } from '../src/totp';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

/** A session that has NOT proved a factor — what a stolen credential is. */
const NO_STEPUP: Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'> = {
  mfaLevel: 'none',
  stepupExpiresAt: null,
};

describeIfPg('enrolling a second factor (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identityenrol_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let service: AuthService;

  const withFactor = randomUUID();
  const withoutFactor = randomUUID();
  const session = randomUUID();
  const victimSecret = generateTotpSecretBase32();

  /** A session context carrying a step-up that is still fresh. */
  const freshStepUp = (): Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'> => ({
    mfaLevel: 'stepup',
    stepupExpiresAt: new Date(Date.now() + STEPUP_WINDOW_MS),
  });

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
    for (const id of [withFactor, withoutFactor]) {
      await admin.query(
        `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
         VALUES ($1, $2, $3, 'x', $4)`,
        [id, Buffer.from(`ct-${id}`), Buffer.from(`bidx-${id}`), randomUUID()],
      );
    }
    // One user already holds a verified authenticator; the other holds none.
    await admin.query(
      `INSERT INTO ${schema}.mfa_methods (id, user_id, kind, secret_ct, verified_at, created_at)
       VALUES ($1, $2, 'totp', $3, now() - interval '30 days', now() - interval '30 days')`,
      [randomUUID(), withFactor, Buffer.from(victimSecret, 'utf8')],
    );

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    service = new AuthService(
      {} as unknown as UsersRepo,
      { grantStepUp: (): Promise<void> => Promise.resolve() } as unknown as SessionsRepo,
      new MfaRepo(db),
      new AuthEventsRepo(db),
      {} as unknown as PasswordHasher,
      {
        stepUpGranted: (): Promise<void> => Promise.resolve(),
        stepUpRateLimited: (): Promise<void> => Promise.resolve(),
      } as unknown as EventsService,
      {
        encryptField: (_u: string, _f: string, v: string): Promise<{ ciphertext: Buffer }> =>
          Promise.resolve({ ciphertext: Buffer.from(v, 'utf8') }),
        decryptField: (input: { ciphertext: Buffer }): Promise<Buffer> =>
          Promise.resolve(Buffer.from(input.ciphertext)),
      } as unknown as FieldCrypto,
      {
        findActiveByUser: (): Promise<{ dekId: string }> =>
          Promise.resolve({ dekId: randomUUID() }),
      } as unknown as DekRepository,
      {} as unknown as IdentityConfig,
      () => new Date(),
      {} as never,
      {} as unknown as EmailVerificationService,
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  it('REFUSES a session with no fresh step-up when a verified factor exists', async () => {
    // The whole escalation, refused at its first request.
    await expect(service.enrollTotp(withFactor, session, NO_STEPUP)).rejects.toMatchObject({
      status: 403,
      response: { error: 'stepup_required' },
    });
    // Nothing was minted, so nothing is sitting there waiting to be confirmed.
    const { rows } = await admin.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${schema}.mfa_methods WHERE user_id = $1`,
      [withFactor],
    );
    expect(rows[0]?.n).toBe('1');
  });

  it('ADMITS the FIRST enrolment on an ordinary session — the bootstrap, which cannot be gated', async () => {
    // An account with no factor has nothing to step up with: `checkTotp`
    // returns invalid for it, so an unconditional gate would make a second
    // factor unreachable forever.
    const enrolled = await service.enrollTotp(withoutFactor, session, NO_STEPUP);
    expect(enrolled.otpauthUri).toContain('secret=');
  });

  it('ADMITS a re-enrolment behind a fresh step-up', async () => {
    const enrolled = await service.enrollTotp(withFactor, session, freshStepUp());
    const secret = new URL(enrolled.otpauthUri).searchParams.get('secret') as string;
    expect(secret).not.toBe(victimSecret);
    // And it is confirmable, so the legitimate path still completes.
    await expect(
      service.verifyTotp(withFactor, session, currentTotpCode(secret)),
    ).resolves.toBeUndefined();
  });

  it('THE ESCALATION, END TO END: a stolen session cannot reach a step-up it did not have', async () => {
    // ITS OWN USER, seeded here. The re-enrolment case above deliberately
    // replaces `withFactor`'s newest verified method, and `findActiveTotp`
    // takes the newest — so sharing a user between the two would make this
    // case's outcome depend on the order they ran in, which is the whole
    // mechanism under test and no way to test it.
    const victim = randomUUID();
    const secret = generateTotpSecretBase32();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [victim, Buffer.from(`ct-${victim}`), Buffer.from(`bidx-${victim}`), randomUUID()],
    );
    await admin.query(
      `INSERT INTO ${schema}.mfa_methods (id, user_id, kind, secret_ct, verified_at, created_at)
       VALUES ($1, $2, 'totp', $3, now() - interval '30 days', now() - interval '30 days')`,
      [randomUUID(), victim, Buffer.from(secret, 'utf8')],
    );

    // The measured sequence, re-run against the fix. Before it, the enrol
    // succeeded, a self-computed code confirmed it, and the step-up was granted.
    const attackerSession = randomUUID();
    await expect(service.enrollTotp(victim, attackerSession, NO_STEPUP)).rejects.toMatchObject({
      status: 403,
    });

    // And the owner's own authenticator still works, which is the half that
    // made this a lockout as well as a takeover.
    await expect(
      service.stepUp(victim, attackerSession, currentTotpCode(secret)),
    ).resolves.toMatchObject({ mfaLevel: 'stepup' });
  });

  it('a re-enrolment RETIRES the previous authenticator, silently — recorded, not fixed', async () => {
    // Not a new defect and not closed by the gate: `findActiveTotp` orders by
    // `created_at DESC LIMIT 1`, so adding an authenticator stops the previous
    // one working, with no audit event and nothing on screen saying so. It is
    // behind step-up now, so only the owner can cause it — but "add a second
    // device" and "replace your device" are different intentions and the
    // platform offers one behaviour for both. Pinned so the behaviour is
    // stated rather than discovered; docs/03 §6j carries it as a residual.
    const owner = randomUUID();
    const first = generateTotpSecretBase32();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [owner, Buffer.from(`ct-${owner}`), Buffer.from(`bidx-${owner}`), randomUUID()],
    );
    await admin.query(
      `INSERT INTO ${schema}.mfa_methods (id, user_id, kind, secret_ct, verified_at, created_at)
       VALUES ($1, $2, 'totp', $3, now() - interval '30 days', now() - interval '30 days')`,
      [randomUUID(), owner, Buffer.from(first, 'utf8')],
    );

    const enrolled = await service.enrollTotp(owner, session, freshStepUp());
    const second = new URL(enrolled.otpauthUri).searchParams.get('secret') as string;
    await service.verifyTotp(owner, session, currentTotpCode(second));

    await expect(service.stepUp(owner, session, currentTotpCode(second))).resolves.toMatchObject({
      mfaLevel: 'stepup',
    });
    // The FIRST device no longer opens anything, though nothing told its owner.
    await expect(service.stepUp(owner, session, currentTotpCode(first))).rejects.toMatchObject({
      status: 401,
    });
  });
});
