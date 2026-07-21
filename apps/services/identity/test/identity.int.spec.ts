/**
 * End-to-end integration test against a real Postgres, gated exactly like
 * packages/db: set PG_TEST_URL to run (CI service container; locally e.g.
 * postgres://estate:estate_dev@localhost:5433/auth). Runs the service's real
 * migrations into a scratch schema, boots the Nest app over it with an
 * in-memory audit producer, and drives the full auth flow with supertest.
 */
import 'reflect-metadata';
import type { Server } from 'node:http';
import { randomBytes } from 'node:crypto';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import { Migrator } from '@estate/db';
import { TOPICS } from '@estate/contracts';
import { Client } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { AUDIT_PRODUCER, PG_POOL_CONFIG } from '../src/di-tokens';
import { currentTotpCode } from '../src/totp';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const EMAIL = 'flow-user@example.com';
const PASSWORD = 'correct horse battery staple 9!';

interface TokensBody {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  userId: string;
}

describeIfPg('identity service end to end', () => {
  jest.setTimeout(120_000); // argon2id at m=64MiB is deliberately slow

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `idsvc_test_${Date.now()}`;
  let admin: Client;
  let app: INestApplication;
  let server: Server;
  let producer: InMemoryAuditProducer;

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);

    // Run the service's real migrations into the scratch schema.
    const migrClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrClient.connect();
    try {
      const migrator = new Migrator(migrClient, `${__dirname}/../migrations`);
      const { applied } = await migrator.migrate();
      expect(applied).toContain('001_auth_schema.sql');
    } finally {
      await migrClient.end();
    }

    process.env['DATABASE_URL'] = pgUrl;
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['EMAIL_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];

    producer = new InMemoryAuditProducer();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AUDIT_PRODUCER)
      .useValue(producer)
      .overrideProvider(PG_POOL_CONFIG)
      .useValue({ connectionString: pgUrl, options: `-c search_path=${schema}` })
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    server = app.getHttpServer() as Server;
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  let tokens: TokensBody;
  let totpSecret: string;

  it('registers a user (generic 201)', async () => {
    const res = await request(server)
      .post('/v1/auth/register')
      .send({ email: EMAIL, password: PASSWORD });
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('duplicate registration returns the IDENTICAL response and creates nothing', async () => {
    const res = await request(server)
      .post('/v1/auth/register')
      .send({ email: EMAIL, password: 'another-password-42!' });
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ status: 'ok' });
    const { rows } = await admin.query(`SELECT count(*)::int AS n FROM ${schema}.users`);
    expect((rows[0] as { n: number }).n).toBe(1);
  });

  it('rejects a wrong password and an unknown email with the same generic 401', async () => {
    const wrongPw = await request(server)
      .post('/v1/auth/login')
      .send({ email: EMAIL, password: 'wrong-password-000' });
    const unknown = await request(server)
      .post('/v1/auth/login')
      .send({ email: 'ghost@example.com', password: 'wrong-password-000' });
    expect(wrongPw.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrongPw.body).toEqual({ error: 'invalid_credentials' });
    expect(unknown.body).toEqual(wrongPw.body);
  });

  it('logs in and issues opaque tokens', async () => {
    const res = await request(server)
      .post('/v1/auth/login')
      .send({ email: EMAIL, password: PASSWORD });
    expect(res.status).toBe(200);
    tokens = res.body as TokensBody;
    expect(tokens.accessToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(tokens.refreshToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Raw tokens are never at rest — only hashes.
    const { rows } = await admin.query(
      `SELECT refresh_token_h, access_token_h FROM ${schema}.sessions WHERE id = $1`,
      [tokens.sessionId],
    );
    const row = rows[0] as { refresh_token_h: Buffer; access_token_h: Buffer };
    expect(row.refresh_token_h.toString('utf8')).not.toContain(tokens.refreshToken);
    expect(row.access_token_h.toString('utf8')).not.toContain(tokens.accessToken);
  });

  it('blocks the step-up-gated endpoint before step-up (403) and without a session (401)', async () => {
    const noStepup = await request(server)
      .post('/v1/auth/export-demo')
      .set('Authorization', `Bearer ${tokens.accessToken}`);
    expect(noStepup.status).toBe(403);
    expect(noStepup.body).toEqual({ error: 'stepup_required' });

    const noSession = await request(server).post('/v1/auth/export-demo');
    expect(noSession.status).toBe(401);
  });

  it('enrolls TOTP (PII-free otpauth URI, encrypted secret at rest)', async () => {
    const res = await request(server)
      .post('/v1/auth/totp/enroll')
      .set('Authorization', `Bearer ${tokens.accessToken}`);
    expect(res.status).toBe(201);
    const body = res.body as { methodId: string; otpauthUri: string };
    expect(body.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    expect(body.otpauthUri).not.toContain('flow-user'); // no email/PII in the URI
    const match = /[?&]secret=([A-Z2-7]+)/.exec(body.otpauthUri);
    expect(match).not.toBeNull();
    totpSecret = (match as RegExpExecArray)[1] as string;
    const { rows } = await admin.query(
      `SELECT secret_ct FROM ${schema}.mfa_methods WHERE id = $1`,
      [body.methodId],
    );
    const secretCt = (rows[0] as { secret_ct: Buffer }).secret_ct;
    expect(secretCt.toString('utf8')).not.toContain(totpSecret); // ciphertext only
  });

  it('verifies TOTP enrollment', async () => {
    const res = await request(server)
      .post('/v1/auth/totp/verify')
      .set('Authorization', `Bearer ${tokens.accessToken}`)
      .send({ code: currentTotpCode(totpSecret) });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ verified: true });
  });

  it('rejects step-up with a wrong code', async () => {
    const res = await request(server)
      .post('/v1/auth/stepup')
      .set('Authorization', `Bearer ${tokens.accessToken}`)
      .send({ code: '000000' });
    expect(res.status).toBe(401);
  });

  it('grants step-up with a valid code (≤5-minute window)', async () => {
    const res = await request(server)
      .post('/v1/auth/stepup')
      .set('Authorization', `Bearer ${tokens.accessToken}`)
      .send({ code: currentTotpCode(totpSecret) });
    expect(res.status).toBe(200);
    const body = res.body as { mfaLevel: string; stepupExpiresAt: string };
    expect(body.mfaLevel).toBe('stepup');
    const windowMs = new Date(body.stepupExpiresAt).getTime() - Date.now();
    expect(windowMs).toBeGreaterThan(0);
    expect(windowMs).toBeLessThanOrEqual(5 * 60 * 1000);
  });

  it('now passes the step-up gate end to end (204)', async () => {
    const res = await request(server)
      .post('/v1/auth/export-demo')
      .set('Authorization', `Bearer ${tokens.accessToken}`);
    expect(res.status).toBe(204);
  });

  let rotated: TokensBody;

  it('rotates refresh + access tokens on refresh', async () => {
    const res = await request(server)
      .post('/v1/auth/refresh')
      .send({ refreshToken: tokens.refreshToken });
    expect(res.status).toBe(200);
    rotated = res.body as TokensBody;
    expect(rotated.sessionId).toBe(tokens.sessionId);
    expect(rotated.refreshToken).not.toBe(tokens.refreshToken);
    expect(rotated.accessToken).not.toBe(tokens.accessToken);
    // The pre-rotation access token no longer authenticates.
    const stale = await request(server)
      .post('/v1/auth/export-demo')
      .set('Authorization', `Bearer ${tokens.accessToken}`);
    expect(stale.status).toBe(401);
  });

  it('replaying the rotated-away refresh token revokes the whole session', async () => {
    const reuse = await request(server)
      .post('/v1/auth/refresh')
      .send({ refreshToken: tokens.refreshToken });
    expect(reuse.status).toBe(401);

    const { rows } = await admin.query(
      `SELECT revoked_at, revoke_reason FROM ${schema}.sessions WHERE id = $1`,
      [tokens.sessionId],
    );
    const row = rows[0] as { revoked_at: Date | null; revoke_reason: string | null };
    expect(row.revoked_at).not.toBeNull();
    expect(row.revoke_reason).toBe('rotation_reuse_detected');

    // The freshly rotated tokens are dead too — theft response is total.
    const refreshAfterRevoke = await request(server)
      .post('/v1/auth/refresh')
      .send({ refreshToken: rotated.refreshToken });
    expect(refreshAfterRevoke.status).toBe(401);
    const accessAfterRevoke = await request(server)
      .post('/v1/auth/export-demo')
      .set('Authorization', `Bearer ${rotated.accessToken}`);
    expect(accessAfterRevoke.status).toBe(401);
  });

  it('wrote the local auth_events ledger', async () => {
    const { rows } = await admin.query(
      `SELECT DISTINCT kind FROM ${schema}.auth_events ORDER BY kind`,
    );
    const kinds = rows.map((r) => (r as { kind: string }).kind);
    expect(kinds).toEqual(
      expect.arrayContaining([
        'user.registered',
        'login.succeeded',
        'login.failed',
        'totp.enrolled',
        'totp.verified',
        'stepup.granted',
        'session.revoked',
      ]),
    );
  });

  it('emitted the required audit actions through the AuditEmitter', () => {
    const auditActions = producer.messages
      .filter((m) => m.topic === TOPICS.auditEvents)
      .map((m) => (JSON.parse(m.value) as { action: string }).action);
    expect(auditActions).toEqual(
      expect.arrayContaining([
        'auth.user.registered',
        'auth.login.succeeded',
        'crypto.field.decrypted',
        'auth.stepup.granted',
        'auth.session.revoked',
      ]),
    );
    // Domain events flowed on the auth topic as well.
    const authTypes = producer.messages
      .filter((m) => m.topic === TOPICS.authEvents)
      .map((m) => (JSON.parse(m.value) as { type: string }).type);
    expect(authTypes).toEqual(
      expect.arrayContaining(['auth.user.registered', 'auth.login.succeeded']),
    );
    // PII firewall: nothing on the wire carries the email or password.
    for (const message of producer.messages) {
      expect(message.value).not.toContain(EMAIL);
      expect(message.value).not.toContain(PASSWORD);
    }
  });
});
