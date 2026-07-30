/**
 * Settlement acceptance E2E (M7 PR1, docs/03 §5.1): the fraudulent-death-
 * trigger controls, proven across REAL service boundaries — identity (the
 * session authority AND the account lock), profile (the role-holder grant
 * freeze, co-tenant of the core cluster), and settlement (the case state
 * machine) — with settlement's produced audit bytes ingested into a verified
 * hash chain.
 *
 * What this file proves that the unit/int suites cannot:
 *  - the settlement-lock internal API is reached through the REAL
 *    ServiceCredentialGuard (a wrong credential is 401; identity's own
 *    transition table refuses an un-ceremonied unlock of a settled account);
 *  - locking to deceased_pending leaves the owner's login and sessions ALIVE
 *    (the §5.1 rescue path) while freezing profile's role-holder reads;
 *  - verification kills every decedent credential: live tokens die via the
 *    session-status allowlist and re-login gets the generic 401;
 *  - the owner's step-up-gated void kills a case end to end.
 *
 * Deep `dist` imports are sanctioned HERE ONLY: this is a test-only package;
 * runtime services never import each other (docs/04 boundary rule 4).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { Test, type TestingModule } from '@nestjs/testing';
import supertest from 'supertest';
import { Client } from 'pg';
import { Migrator } from '@estate/db';
import { AuditEventSchema, TOPICS } from '@estate/contracts';
import { HttpSessionVerifier, SESSION_VERIFIER, type FetchLike } from '@estate/auth-guard';
import { AppModule as IdentityAppModule } from '@estate/service-identity/dist/app.module';
import { currentTotpCode } from '@estate/service-identity/dist/totp';
import { AppModule as ProfileAppModule } from '@estate/service-profile/dist/app.module';
import { PG_POOL_CONFIG as PROFILE_PG_POOL_CONFIG } from '@estate/service-profile/dist/di-tokens';
import { AppModule as SettlementAppModule } from '@estate/service-settlement/dist/app.module';
import {
  AUDIT_PRODUCER as SETTLEMENT_AUDIT_PRODUCER,
  CLOCK as SETTLEMENT_CLOCK,
  IDENTITY_LOCK,
  NOTIFIER as SETTLEMENT_NOTIFIER,
  PG_POOL_CONFIG as SETTLEMENT_PG_POOL_CONFIG,
} from '@estate/service-settlement/dist/di-tokens';
import { InMemoryAuditProducer } from '@estate/kafka';
import {
  HttpIdentityLock,
  type FetchLike as LockFetchLike,
} from '@estate/service-settlement/dist/identity-lock';
import { StubNotifier } from '@estate/service-settlement/dist/notifications';
import { AuditIngestor } from '@estate/service-audit/dist/ingestor';
import { ChainVerifier } from '@estate/service-audit/dist/verifier';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

function migrationsDirOf(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'migrations');
}

function schemaScopedUrl(base: string, schema: string): string {
  const url = new URL(base);
  url.searchParams.set('options', `-c search_path=${schema}`);
  return url.toString();
}

// TWO service credentials, one per CALLEE. IDENTITY_TOKEN opens identity's
// account-lock API and is held only by settlement; SETTLEMENT_TOKEN opens
// settlement's read-only gate route and is held by vault/documents. The M7
// security review found these collapsed into one value, which handed the Zone
// A service a working key to irreversibly mark a living user deceased.
const IDENTITY_TOKEN = `e2e-identity-${'t'.repeat(36)}`;
const SETTLEMENT_TOKEN = `e2e-settlement-${'g'.repeat(36)}`;
const DAY = 24 * 60 * 60 * 1000;

describeIfPg('settlement (M7): fraudulent-death-trigger controls end to end', () => {
  const stamp = Date.now();
  const authSchema = `e2e_stl_auth_${stamp}`;
  const coreSchema = `e2e_stl_core_${stamp}`;
  const auditSchema = `e2e_stl_audit_${stamp}`;
  let admin: Client;
  /** Core-cluster DML must run with the scratch schema on the search_path:
   * the version-capture triggers resolve `<table>_versions` through it, so a
   * public-search_path client fails inside the trigger. */
  let coreAdmin: Client;
  let auditDb: Client;
  let identityApp: ReturnType<TestingModule['createNestApplication']>;
  let profileApp: ReturnType<TestingModule['createNestApplication']>;
  let settlementApp: ReturnType<TestingModule['createNestApplication']>;

  const settlementProducer = new InMemoryAuditProducer();
  const settlementNotifier = new StubNotifier();
  const clockHolder = { value: new Date() };

  beforeAll(async () => {
    const baseUrl = process.env['PG_TEST_URL']!;
    admin = new Client({ connectionString: baseUrl });
    await admin.connect();
    for (const schema of [authSchema, coreSchema, auditSchema]) {
      await admin.query(`CREATE SCHEMA ${schema}`);
    }

    // identity → auth schema; audit → audit schema; profile AND settlement
    // co-migrate the SAME core schema — the production co-tenancy, for real.
    for (const [pkg, schema] of [
      ['@estate/service-identity', authSchema],
      ['@estate/service-audit', auditSchema],
      ['@estate/service-profile', coreSchema],
      ['@estate/service-settlement', coreSchema],
    ] as const) {
      const client = new Client({ connectionString: schemaScopedUrl(baseUrl, schema) });
      await client.connect();
      await new Migrator(client, migrationsDirOf(pkg)).migrate();
      await client.end();
    }
    auditDb = new Client({ connectionString: schemaScopedUrl(baseUrl, auditSchema) });
    await auditDb.connect();
    coreAdmin = new Client({ connectionString: schemaScopedUrl(baseUrl, coreSchema) });
    await coreAdmin.connect();

    // --- identity (session authority + the settlement lock) ---
    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, authSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['EMAIL_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['IDENTITY_INTERNAL_TOKEN'] = IDENTITY_TOKEN;
    delete process.env['SETTLEMENT_INTERNAL_TOKEN'];
    delete process.env['KAFKA_BROKERS'];
    const identityRef = await Test.createTestingModule({ imports: [IdentityAppModule] }).compile();
    identityApp = identityRef.createNestApplication({ logger: false });
    await identityApp.init();
    const identityHttp = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);

    const sessionFetch: FetchLike = async (url, init) => {
      const res = await identityHttp
        .get(new URL(url).pathname)
        .set('authorization', init.headers['authorization'] ?? '');
      return {
        ok: res.status >= 200 && res.status < 300,
        status: res.status,
        json: () => Promise.resolve(res.body as unknown),
      };
    };
    const verifier = new HttpSessionVerifier({
      identityUrl: 'http://identity.internal',
      cacheTtlMs: 0, // re-introspect every call so a mid-test step-up is seen at once
      fetchImpl: sessionFetch,
    });

    // The settlement-lock transport: dispatches to identity's REAL internal
    // routes, ServiceCredentialGuard included.
    const lockFetch: LockFetchLike = async (url, init) => {
      const path = new URL(url).pathname;
      let req = init.method === 'PUT' ? identityHttp.put(path) : identityHttp.get(path);
      for (const [key, value] of Object.entries(init.headers)) {
        req = req.set(key, value);
      }
      const res = await (init.body ? req.send(JSON.parse(init.body) as object) : req);
      return {
        ok: res.status >= 200 && res.status < 300,
        status: res.status,
        json: () => Promise.resolve(res.body as unknown),
      };
    };

    // --- profile (core-cluster co-tenant; the grant-freeze surface) ---
    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, coreSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];
    const profileRef = await Test.createTestingModule({ imports: [ProfileAppModule] })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(verifier)
      .overrideProvider(PROFILE_PG_POOL_CONFIG)
      .useValue({ connectionString: schemaScopedUrl(baseUrl, coreSchema) })
      .compile();
    profileApp = profileRef.createNestApplication({ logger: false });
    await profileApp.init();

    // --- settlement ---
    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, coreSchema);
    process.env['SETTLEMENT_INTERNAL_TOKEN'] = SETTLEMENT_TOKEN;
    process.env['IDENTITY_INTERNAL_TOKEN'] = IDENTITY_TOKEN;
    delete process.env['KAFKA_BROKERS'];
    const settlementRef = await Test.createTestingModule({ imports: [SettlementAppModule] })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(verifier)
      .overrideProvider(SETTLEMENT_PG_POOL_CONFIG)
      .useValue({ connectionString: schemaScopedUrl(baseUrl, coreSchema) })
      .overrideProvider(SETTLEMENT_AUDIT_PRODUCER)
      .useValue(settlementProducer)
      .overrideProvider(SETTLEMENT_NOTIFIER)
      .useValue(settlementNotifier)
      .overrideProvider(SETTLEMENT_CLOCK)
      .useValue((): Date => clockHolder.value)
      .overrideProvider(IDENTITY_LOCK)
      .useValue(
        new HttpIdentityLock({
          identityUrl: 'http://identity.internal',
          credential: IDENTITY_TOKEN,
          fetchImpl: lockFetch,
        }),
      )
      .compile();
    settlementApp = settlementRef.createNestApplication({ logger: false });
    await settlementApp.init();
  }, 180_000);

  afterAll(async () => {
    await settlementApp?.close();
    await profileApp?.close();
    await identityApp?.close();
    await auditDb?.end();
    await coreAdmin?.end();
    if (admin) {
      for (const schema of [authSchema, coreSchema, auditSchema]) {
        await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      }
      await admin.end();
    }
  });

  interface User {
    userId: string;
    accessToken: string;
    bearer: { authorization: string };
    email: string;
    password: string;
  }

  async function registerAndLogin(label: string): Promise<User> {
    const identity = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const email = `${label}-${randomUUID()}@example.com`;
    const password = `Pw-${randomBytes(18).toString('base64url')}`;
    await identity.post('/v1/auth/register').send({ email, password }).expect(201);
    const login = await identity.post('/v1/auth/login').send({ email, password }).expect(200);
    const body = login.body as { accessToken: string; userId: string };
    return {
      userId: body.userId,
      accessToken: body.accessToken,
      bearer: { authorization: `Bearer ${body.accessToken}` },
      email,
      password,
    };
  }

  async function stepUp(user: User): Promise<void> {
    const identity = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const enroll = await identity.post('/v1/auth/totp/enroll').set(user.bearer).expect(201);
    const secret = new URL((enroll.body as { otpauthUri: string }).otpauthUri).searchParams.get(
      'secret',
    )!;
    await identity
      .post('/v1/auth/totp/verify')
      .set(user.bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);
    await identity
      .post('/v1/auth/stepup')
      .set(user.bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);
  }

  /**
   * Seed the decedent's estate through profile's REAL owner-authenticated API,
   * so the contact row carries genuine envelope-encrypted fields and a real
   * DEK (the reporter later READS these contacts, which decrypts them). Only
   * `linked_user_id` is set directly: it is unencrypted metadata normally set
   * when a contact accepts an invite, and no invite flow exists yet.
   *
   * The contact gets two designations: an executor role effective
   * on_death_verified (what makes the reporter a plausible settlement
   * reporter) and an immediate viewer role with a contact-read grant (the
   * live non-owner read path whose freeze this test asserts).
   */
  async function seedEstate(owner: User, linkedUserId: string): Promise<void> {
    const profile = supertest(profileApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const created = await profile
      .post('/v1/contacts')
      .set(owner.bearer)
      .send({ name: 'Estate Contact', relationship: 'child' })
      .expect(201);
    const contactId = (created.body as { id: string }).id;
    await coreAdmin.query(`UPDATE contacts SET linked_user_id = $2 WHERE id = $1`, [
      contactId,
      linkedUserId,
    ]);
    await profile
      .post('/v1/role-assignments')
      .set(owner.bearer)
      .send({
        contactId,
        role: 'executor',
        scopeType: 'estate',
        effectiveCondition: 'on_death_verified',
      })
      .expect(201);
    const viewer = await profile
      .post('/v1/role-assignments')
      .set(owner.bearer)
      .send({ contactId, role: 'viewer', scopeType: 'estate', effectiveCondition: 'immediate' })
      .expect(201);
    await profile
      .post(`/v1/role-assignments/${(viewer.body as { id: string }).id}/permissions`)
      .set(owner.bearer)
      .send({ resource: 'contact', action: 'read' })
      .expect(201);
  }

  it('runs the §5.1 flow: report → review → deceased_pending (rescue stays open, grants freeze) → verify (credentials die)', async () => {
    const identity = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const profile = supertest(profileApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const settlement = supertest(settlementApp.getHttpServer() as Parameters<typeof supertest>[0]);

    const owner = await registerAndLogin('owner');
    const reporter = await registerAndLogin('reporter');
    const operator = await registerAndLogin('operator');
    await seedEstate(owner, reporter.userId);
    // The operator allowlist has no runtime grant API; this INSERT is the
    // ops-CLI write path.
    await admin.query(`INSERT INTO ${coreSchema}.settlement_operators (user_id) VALUES ($1)`, [
      operator.userId,
    ]);

    // Unauthenticated and forged callers are rejected outright.
    await settlement.get('/v1/settlement/cases').expect(401, { error: 'unauthorized' });
    await settlement.get('/v1/settlement/cases').set('authorization', 'Bearer forged').expect(401);

    // The reporter sees the estate that names them, and only that path in.
    const estates = await settlement
      .get('/v1/settlement/reportable-estates')
      .set(reporter.bearer)
      .expect(200);
    expect(estates.body).toEqual([
      expect.objectContaining({ decedentUserId: owner.userId, roles: ['executor', 'viewer'] }),
    ]);

    // Intake opens a case and nothing else: no lock, owner notified.
    const reported = await settlement
      .post('/v1/settlement/cases')
      .set(reporter.bearer)
      .send({ decedentUserId: owner.userId, source: 'trusted_contact', evidence: [] })
      .expect(201);
    const caseId = (reported.body as { caseId: string }).caseId;
    expect((reported.body as { status: string }).status).toBe('reported');
    const statusAfterReport = await admin.query<{ status: string }>(
      `SELECT status FROM ${authSchema}.users WHERE id = $1`,
      [owner.userId],
    );
    expect(statusAfterReport.rows[0]?.status).toBe('active');
    expect(settlementNotifier.sent).toContainEqual(
      expect.objectContaining({ kind: 'case_opened', ownerUserId: owner.userId, caseId }),
    );

    // The subject and the reporter can read the case; a stranger cannot.
    await settlement.get(`/v1/settlement/cases/${caseId}`).set(owner.bearer).expect(200);
    await settlement.get(`/v1/settlement/cases/${caseId}`).set(reporter.bearer).expect(200);
    const stranger = await registerAndLogin('stranger');
    await settlement
      .get(`/v1/settlement/cases/${caseId}`)
      .set(stranger.bearer)
      .expect(403, { error: 'forbidden' });

    // Before the lock: the reporter's contact-read grant works.
    await profile.get(`/v1/profiles/${owner.userId}/contacts`).set(reporter.bearer).expect(200);

    // Review: operator-only, step-up-gated decision, real account lock.
    await settlement
      .post(`/v1/settlement/cases/${caseId}/review/start`)
      .set(stranger.bearer)
      .expect(403);
    await settlement
      .post(`/v1/settlement/cases/${caseId}/review/start`)
      .set(operator.bearer)
      .expect(200);
    await settlement
      .post(`/v1/settlement/cases/${caseId}/review`)
      .set(operator.bearer)
      .send({ decision: 'approve' })
      .expect(403, { error: 'stepup_required' });
    await stepUp(operator);
    const approved = await settlement
      .post(`/v1/settlement/cases/${caseId}/review`)
      .set(operator.bearer)
      .send({ decision: 'approve' })
      .expect(200);
    expect((approved.body as { status: string }).status).toBe('waiting_period');

    // The lock is REAL (identity's row changed through the guarded API)…
    const statusAfterApprove = await admin.query<{ status: string }>(
      `SELECT status FROM ${authSchema}.users WHERE id = $1`,
      [owner.userId],
    );
    expect(statusAfterApprove.rows[0]?.status).toBe('deceased_pending');
    // …but the rescue path stays open: live session AND fresh login work.
    await identity.get('/v1/auth/session').set(owner.bearer).expect(200);
    await identity
      .post('/v1/auth/login')
      .send({ email: owner.email, password: owner.password })
      .expect(200);
    // While role-holder reads freeze (docs/03 §5.1 control 4).
    await profile
      .get(`/v1/profiles/${owner.userId}/contacts`)
      .set(reporter.bearer)
      .expect(403, { error: 'forbidden' });

    // A wrong service credential cannot reach the lock API.
    await identity
      .put(`/internal/v1/settlement-lock/${owner.userId}`)
      .set('x-estate-service-credential', 'wrong')
      .send({ state: 'active', caseId })
      .expect(401);

    // Verification refuses while the waiting period runs…
    await settlement
      .post(`/v1/settlement/cases/${caseId}/verify`)
      .set(operator.bearer)
      .expect(403, { error: 'waiting_period_active' });
    // …and proceeds once it lapses (the owner never signed in with step-up).
    clockHolder.value = new Date(Date.now() + 5 * DAY + 60_000);
    const verified = await settlement
      .post(`/v1/settlement/cases/${caseId}/verify`)
      .set(operator.bearer)
      .expect(200);
    expect((verified.body as { status: string }).status).toBe('verified');

    // Verified ⇒ no decedent credential survives: the live token dies via
    // the session-status allowlist, re-login gets the generic 401, and the
    // settled account cannot be unlocked by the service API.
    const statusAfterVerify = await admin.query<{ status: string }>(
      `SELECT status FROM ${authSchema}.users WHERE id = $1`,
      [owner.userId],
    );
    expect(statusAfterVerify.rows[0]?.status).toBe('settlement');
    await identity.get('/v1/auth/session').set(owner.bearer).expect(401);
    await identity
      .post('/v1/auth/login')
      .send({ email: owner.email, password: owner.password })
      .expect(401, { error: 'invalid_credentials' });
    await settlement.get(`/v1/settlement/cases/${caseId}`).set(owner.bearer).expect(401);
    await identity
      .put(`/internal/v1/settlement-lock/${owner.userId}`)
      .set('x-estate-service-credential', IDENTITY_TOKEN)
      .send({ state: 'active', caseId })
      .expect(409, { error: 'invalid_transition' });
  }, 180_000);

  it('the gate credential vault holds does NOT open identity’s account-lock API', async () => {
    // The M7 security review's confirmed defect, as an executable claim. Vault
    // and documents hold SETTLEMENT_TOKEN so they can ask settlement about an
    // owner's case state. If that same value were accepted here, anyone who
    // compromised the most exposed service in the product could entomb any
    // living user — no case, no operator, no waiting period (docs/03 §5.1's
    // Critical outcome). Presenting it must be indistinguishable from
    // presenting nothing.
    const identity = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const victim = await registerAndLogin('cred-scope-victim');
    for (const credential of [SETTLEMENT_TOKEN, 'not-a-credential']) {
      await identity
        .put(`/internal/v1/settlement-lock/${victim.userId}`)
        .set('x-estate-service-credential', credential)
        .send({ state: 'deceased_pending', caseId: randomUUID() })
        .expect(401, { error: 'unauthorized' });
    }
    // ...and the victim is untouched: still active, still logged in.
    const status = await admin.query<{ status: string }>(
      `SELECT status FROM ${authSchema}.users WHERE id = $1`,
      [victim.userId],
    );
    expect(status.rows[0]?.status).toBe('active');
    await identity.get('/v1/auth/session').set(victim.bearer).expect(200);
  }, 120_000);

  it('the owner voids a case with step-up, killing it and flagging the reporter', async () => {
    const settlement = supertest(settlementApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const owner2 = await registerAndLogin('owner2');
    const reporter2 = await registerAndLogin('reporter2');
    await seedEstate(owner2, reporter2.userId);

    const reported = await settlement
      .post('/v1/settlement/cases')
      .set(reporter2.bearer)
      .send({ decedentUserId: owner2.userId, source: 'trusted_contact', evidence: [] })
      .expect(201);
    const caseId = (reported.body as { caseId: string }).caseId;

    // Void requires the step-up (the liveness proof), and only the subject.
    await settlement.post(`/v1/settlement/cases/${caseId}/void`).set(reporter2.bearer).expect(403);
    await settlement
      .post(`/v1/settlement/cases/${caseId}/void`)
      .set(owner2.bearer)
      .expect(403, { error: 'stepup_required' });
    await stepUp(owner2);
    const voided = await settlement
      .post(`/v1/settlement/cases/${caseId}/void`)
      .set(owner2.bearer)
      .expect(200);
    expect(voided.body as object).toMatchObject({
      status: 'rejected_fraud',
      resolution: 'owner_voided',
    });
    const status = await admin.query<{ status: string }>(
      `SELECT status FROM ${authSchema}.users WHERE id = $1`,
      [owner2.userId],
    );
    expect(status.rows[0]?.status).toBe('active');
  }, 120_000);

  it('settlement’s produced audit bytes ingest into a verified hash chain, PII-free', async () => {
    // --- bridge: exact produced bytes → audit ingestor ---
    const auditMessages = settlementProducer.messages.filter((m) => m.topic === TOPICS.auditEvents);
    expect(auditMessages.length).toBeGreaterThan(0);
    const ingestor = new AuditIngestor(auditDb);
    for (const message of auditMessages) {
      const result = await ingestor.ingest(message.value);
      expect(result.status).toBe('appended');
    }
    const verdict = await new ChainVerifier(auditDb).verify();
    expect(verdict).toEqual({ ok: true, count: auditMessages.length });

    const actions = auditMessages.map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action);
    for (const expected of [
      'settlement.case.reported',
      'settlement.case.review_started',
      'settlement.case.approved',
      'settlement.case.verified',
      'settlement.case.voided',
    ]) {
      expect(actions).toContain(expected);
    }

    // PII firewall: no message ever carries an email, password, or name.
    for (const message of auditMessages) {
      expect(message.value).not.toContain('@example.com');
      expect(message.value).not.toContain('Pw-');
    }
  }, 60_000);
});
