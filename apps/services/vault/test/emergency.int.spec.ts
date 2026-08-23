/**
 * Emergency access end to end against a real Postgres (PG_TEST_URL gated).
 *
 * The interesting assertions are the refusals. docs/03 §5.2's attack is a
 * designated contact invoking access while the owner is alive but unaware, so
 * this suite spends most of its time proving that the waiting period holds,
 * that a denial sticks, and that a release happens exactly once - and then
 * proves the happy path really does hand back a master key, by reconstructing
 * it through @estate/vault-crypto and decrypting one of the owner's items.
 */
import 'reflect-metadata';
import type { Server } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import { checkConventions, Migrator } from '@estate/db';
import { AuditEventSchema, type MfaLevel } from '@estate/contracts';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import {
  createEscrow,
  createVaultEnrollment,
  decryptItem,
  encryptItem,
  exportMasterKeyBytes,
  generateRecoveryKeyPair,
  importAesKey,
  MIN_ITERATIONS,
  prepareUnlock,
  proveUnlock,
  recoverMasterKey,
  toBase64,
  utf8,
  type RecoveryKeyPair,
} from '@estate/vault-crypto';
import { Client } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { VAULT_SESSION_HEADER } from '../src/vault-session.guard';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AUDIT_PRODUCER, CLOCK, NOTIFIER, PG_POOL_CONFIG } from '../src/di-tokens';
import { SETTLEMENT_AUTHORITY, type SettlementVaultGate } from '@estate/settlement-client';
import { StubNotifier } from '../src/notifications';
import type { EscrowDto, PolicyDto, ReleaseDto } from '../src/emergency.service';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const OWNER = randomUUID();
const GRANTEE = randomUUID();
const OTHER_GRANTEE = randomUUID();
const STRANGER = randomUUID();
const CONTACT_ID = randomUUID();
const OTHER_CONTACT_ID = randomUUID();
const VAULT_PASSWORD = 'a memorable owner vault password';
const ITEM_SECRET = 'the will is in the safe deposit box at first national';
const WAITING_HOURS = 48;

const fakeVerifier: SessionVerifier = {
  verify: (token) => {
    const m = /^(mfa|stepup):([0-9a-f-]{36})$/.exec(token);
    if (!m) return Promise.resolve(null);
    const [, level, userId] = m;
    const ctx: SessionContext = {
      userId: userId!,
      sessionId: '00000000-0000-4000-8000-000000000000',
      mfaLevel: level as MfaLevel,
      audience: 'account',
      stepupExpiresAt: level === 'stepup' ? new Date(Date.now() + 5 * 60 * 1000) : null,
    };
    return Promise.resolve(ctx);
  },
};

const bearer = (level: 'mfa' | 'stepup', userId: string): Record<string, string> => ({
  authorization: `Bearer ${level}:${userId}`,
});

describeIfPg('emergency access end to end', () => {
  jest.setTimeout(180_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `vaultemg_test_${Date.now()}`;
  let admin: Client;
  let app: INestApplication;
  let server: Server;
  let producer: InMemoryAuditProducer;
  let notifier: StubNotifier;

  /**
   * The settlement gate, mutable per-test. Default: the owner has no
   * settlement case, so emergency access behaves exactly as it did in M6.
   */
  const settlementGate: SettlementVaultGate & {
    permitted: boolean;
    caseId: string | null;
  } = {
    permitted: true,
    caseId: null,
    checkVaultRelease() {
      return Promise.resolve({ permitted: this.permitted, caseId: this.caseId });
    },
  };

  /** Injected clock, so the waiting period can be crossed without waiting. */
  let now = new Date('2026-08-01T09:00:00.000Z');

  let ownerMasterKeyBytes: Uint8Array;
  let ownerItemId: string;
  let granteeKeys: RecoveryKeyPair;
  let otherGranteeKeys: RecoveryKeyPair;
  /** Each enrolled user's Secret Key, so `openVaultFor` can unlock as them. */
  const secretKeys = new Map<string, string>();
  let policyId: string;

  const asOwner = (): Record<string, string> => bearer('mfa', OWNER);
  const ownerStepUp = (): Record<string, string> => bearer('stepup', OWNER);
  const asGrantee = (): Record<string, string> => bearer('mfa', GRANTEE);

  /** Arm a fresh escrow over the current grantee set. */
  async function configureEscrow(
    grantees: Array<{ userId: string; contactId: string; keys: RecoveryKeyPair }>,
    threshold = 1,
  ): Promise<EscrowDto> {
    const escrow = await createEscrow({
      ownerUserId: OWNER,
      masterKey: ownerMasterKeyBytes,
      grantees: grantees.map((g) => ({ granteeUserId: g.userId, publicKey: g.keys.publicKey })),
      threshold,
    });

    const res = await request(server)
      .post('/v1/vault/emergency-access')
      .set(ownerStepUp())
      .send({
        threshold: escrow.threshold,
        platformPart: escrow.platformPart,
        wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
        grantees: escrow.shares.map((share, i) => ({
          granteeContactId: grantees[i]!.contactId,
          granteeUserId: share.granteeUserId,
          keyShare: share.sealedShare,
          granteePublicKeySha256: share.publicKeySha256,
          waitingPeriodHours: WAITING_HOURS,
        })),
      })
      .expect(201);
    return res.body as EscrowDto;
  }

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.query(`SET search_path TO ${schema}, public`);

    const migrationClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrationClient.connect();
    try {
      const { applied } = await new Migrator(
        migrationClient,
        `${__dirname}/../migrations`,
      ).migrate();
      expect(applied).toContain('002_emergency_access.sql');
    } finally {
      await migrationClient.end();
    }

    process.env['DATABASE_URL'] = pgUrl;
    process.env['NODE_ENV'] = 'test';
    delete process.env['KAFKA_BROKERS'];

    producer = new InMemoryAuditProducer();
    notifier = new StubNotifier();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AUDIT_PRODUCER)
      .useValue(producer)
      .overrideProvider(NOTIFIER)
      .useValue(notifier)
      .overrideProvider(CLOCK)
      .useValue(() => now)
      .overrideProvider(PG_POOL_CONFIG)
      .useValue({ connectionString: pgUrl, options: `-c search_path=${schema}` })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      // The docs/03 §6a settlement gate. Without this override the REAL client
      // is wired at localhost:3007, no settlement is running, and the gate
      // (correctly) fails closed and blocks every request and release — which
      // is exactly what the dedicated block test below asserts.
      .overrideProvider(SETTLEMENT_AUTHORITY)
      .useValue(settlementGate)
      .compile();

    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    server = app.getHttpServer() as Server;

    // The owner enrols a vault and stores one item worth recovering.
    const enrolled = await createVaultEnrollment({
      userId: OWNER,
      password: VAULT_PASSWORD,
      iterations: MIN_ITERATIONS,
    });
    await request(server)
      .post('/v1/vault/keyset')
      .set(ownerStepUp())
      .send(enrolled.enrollment.payload)
      .expect(201);

    const preparation = await prepareUnlock({
      userId: OWNER,
      password: VAULT_PASSWORD,
      secretKey: enrolled.enrollment.secretKey,
      kdfParams: enrolled.enrollment.payload.kdfParams,
      srpSalt: enrolled.enrollment.payload.srpSalt,
    });
    ownerMasterKeyBytes = await exportMasterKeyBytes({
      userId: OWNER,
      auk: preparation.auk,
      wrappedMasterKey: enrolled.enrollment.payload.wrappedMasterKey,
    });

    ownerItemId = randomUUID();
    const blob = await encryptItem(
      enrolled.masterKey,
      { userId: OWNER, itemId: ownerItemId, blobVersion: 1 },
      utf8(ITEM_SECRET),
    );
    await admin.query(
      `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version)
       VALUES ($1, $2, 'secure_note', $3, 1)`,
      [ownerItemId, OWNER, Buffer.from(blob)],
    );

    // Both grantees enrol vaults of their own and publish a public key.
    // STRANGER enrols too but publishes nothing, which is what makes the
    // own-key 404 case reachable.
    granteeKeys = await generateRecoveryKeyPair();
    otherGranteeKeys = await generateRecoveryKeyPair();
    for (const [userId, keys] of [
      [GRANTEE, granteeKeys],
      [OTHER_GRANTEE, otherGranteeKeys],
      [STRANGER, null],
    ] as const) {
      const theirs = await createVaultEnrollment({
        userId,
        password: `${userId} vault password`,
        iterations: MIN_ITERATIONS,
      });
      secretKeys.set(userId, theirs.enrollment.secretKey);
      await request(server)
        .post('/v1/vault/keyset')
        .set(bearer('stepup', userId))
        .send(theirs.enrollment.payload)
        .expect(201);
      if (!keys) continue;
      await request(server)
        .post('/v1/vault/recovery-key')
        .set(bearer('stepup', userId))
        .send({
          publicKey: toBase64(keys.publicKey),
          wrappedPrivateKey: toBase64(keys.privateKey),
        })
        .expect(201);
    }
  });

  /** Complete a real SRP unlock for one user, the way a client does. */
  async function openVaultFor(userId: string): Promise<{ token: string }> {
    const headers = bearer('stepup', userId);
    const challenge = await request(server)
      .post('/v1/vault/srp/start')
      .set(headers)
      .expect(201)
      .then(
        (res) =>
          res.body as {
            handshakeId: string;
            srpSalt: string;
            kdfParams: unknown;
            serverPublic: string;
          },
      );
    const preparation = await prepareUnlock({
      userId,
      password: `${userId} vault password`,
      secretKey: secretKeys.get(userId) as string,
      kdfParams: challenge.kdfParams,
      srpSalt: challenge.srpSalt,
    });
    const { m1 } = await proveUnlock(preparation, challenge.serverPublic);
    const opened = await request(server)
      .post('/v1/vault/srp/verify')
      .set(headers)
      .send({
        handshakeId: challenge.handshakeId,
        clientPublic: preparation.publicA,
        clientProof: m1,
      })
      .expect(200)
      .then((res) => res.body as { vaultSession: { token: string } });
    return { token: opened.vaultSession.token };
  }

  afterAll(async () => {
    if (app) await app.close();
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  it('keeps the emergency-access tables within the docs/02 conventions', async () => {
    const violations = await checkConventions(admin, {
      schema,
      businessTables: ['vault_items', 'emergency_access_policies'],
      appendOnlyTables: [
        'vault_items_versions',
        'vault_keysets_versions',
        'emergency_access_policies_versions',
        'emergency_access_configs_versions',
      ],
    });
    expect(violations).toEqual([]);
  });

  describe('grantee keys', () => {
    it('publishes a public key others can seal to', async () => {
      const res = await request(server)
        .get(`/v1/vault/recovery-key/${GRANTEE}`)
        .set(asOwner())
        .expect(200);
      expect((res.body as { publicKey: string }).publicKey).toBe(toBase64(granteeKeys.publicKey));
    });

    /**
     * THE ROUTE M6 NEVER HAD (M15 PR3).
     *
     * `wrapped_private_key` was written by publish and cleared by reset, and no
     * route ever returned it — so a share sealed to a grantee could never be
     * opened BY that grantee and the whole release path was structurally
     * incompletable. Nothing noticed because M6 shipped with no client; PR3 is
     * the first consumer, which is the M4 legal-hold shape exactly.
     */
    it('serves the CALLER their own wrapped private key, behind an open vault', async () => {
      const { token } = await openVaultFor(GRANTEE);
      const res = await request(server)
        .get('/v1/vault/recovery-key')
        .set(bearer('stepup', GRANTEE))
        .set(VAULT_SESSION_HEADER, token)
        .expect(200);
      const body = res.body as { publicKey: string; wrappedPrivateKey: string };
      expect(body.publicKey).toBe(toBase64(granteeKeys.publicKey));
      // The private half comes back as the ciphertext that was stored — only
      // this caller's master key opens it.
      expect(body.wrappedPrivateKey).toBe(toBase64(granteeKeys.privateKey));
    });

    it('refuses the own-key route without an OPEN vault', async () => {
      // A session alone must not be enough: completing a release requires the
      // grantee to open their own vault, and fetching the key that does it
      // should be held to the same bar.
      await request(server)
        .get('/v1/vault/recovery-key')
        .set(bearer('stepup', GRANTEE))
        .expect(403, { error: 'vault_locked' });
    });

    it('404s the own-key route for a user who never published one', async () => {
      const { token } = await openVaultFor(STRANGER);
      await request(server)
        .get('/v1/vault/recovery-key')
        .set(bearer('stepup', STRANGER))
        .set(VAULT_SESSION_HEADER, token)
        .expect(404, { error: 'recovery_key_not_found' });
    });

    it('404s a user who has not published one', async () => {
      await request(server)
        .get(`/v1/vault/recovery-key/${STRANGER}`)
        .set(asOwner())
        .expect(404, { error: 'grantee_key_not_found' });
    });

    it('requires step-up to publish', async () => {
      await request(server)
        .post('/v1/vault/recovery-key')
        .set(asOwner())
        .send({
          publicKey: toBase64(granteeKeys.publicKey),
          wrappedPrivateKey: toBase64(granteeKeys.privateKey),
        })
        .expect(403, { error: 'stepup_required' });
    });
  });

  describe('configuring an escrow', () => {
    it('requires step-up', async () => {
      await request(server)
        .post('/v1/vault/emergency-access')
        .set(asOwner())
        .send({
          threshold: 1,
          platformPart: toBase64(new Uint8Array(32)),
          wrappedMasterKeyRecovery: 'AA==',
          grantees: [],
        })
        .expect(403, { error: 'stepup_required' });
    });

    it('arms an escrow over one grantee', async () => {
      const escrow = await configureEscrow([
        { userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys },
      ]);
      expect(escrow.configured).toBe(true);
      expect(escrow.threshold).toBe(1);
      expect(escrow.policies).toHaveLength(1);
      policyId = escrow.policies[0]!.id;
      expect(escrow.policies[0]).toMatchObject({
        granteeUserId: GRANTEE,
        status: 'configured',
        waitingPeriodHours: WAITING_HOURS,
      });
    });

    it('refuses an owner naming themselves', async () => {
      await request(server)
        .post('/v1/vault/emergency-access')
        .set(ownerStepUp())
        .send({
          threshold: 1,
          platformPart: toBase64(new Uint8Array(32)),
          wrappedMasterKeyRecovery: 'AAAA',
          grantees: [
            {
              granteeContactId: CONTACT_ID,
              granteeUserId: OWNER,
              keyShare: 'AAAA',
              granteePublicKeySha256: toBase64(new Uint8Array(32)),
              waitingPeriodHours: WAITING_HOURS,
            },
          ],
        })
        .expect(409, { error: 'self_grantee' });
    });

    it('refuses a waiting period under the documented 24h floor', async () => {
      await request(server)
        .post('/v1/vault/emergency-access')
        .set(ownerStepUp())
        .send({
          threshold: 1,
          platformPart: toBase64(new Uint8Array(32)),
          wrappedMasterKeyRecovery: 'AAAA',
          grantees: [
            {
              granteeContactId: CONTACT_ID,
              granteeUserId: GRANTEE,
              keyShare: 'AAAA',
              granteePublicKeySha256: toBase64(new Uint8Array(32)),
              waitingPeriodHours: 12,
            },
          ],
        })
        .expect(400, { error: 'invalid_request' });
    });

    it('refuses a threshold above the grantee count', async () => {
      await request(server)
        .post('/v1/vault/emergency-access')
        .set(ownerStepUp())
        .send({
          threshold: 3,
          platformPart: toBase64(new Uint8Array(32)),
          wrappedMasterKeyRecovery: 'AAAA',
          grantees: [
            {
              granteeContactId: CONTACT_ID,
              granteeUserId: GRANTEE,
              keyShare: 'AAAA',
              granteePublicKeySha256: toBase64(new Uint8Array(32)),
              waitingPeriodHours: WAITING_HOURS,
            },
          ],
        })
        .expect(409, { error: 'threshold_exceeds_grantees' });
    });

    it('shows the grantee what they have been designated for', async () => {
      const res = await request(server)
        .get('/v1/vault/emergency-access/granted-to-me')
        .set(asGrantee())
        .expect(200);
      const policies = res.body as Array<{ ownerUserId: string; status: string }>;
      expect(policies).toHaveLength(1);
      expect(policies[0]).toMatchObject({ ownerUserId: OWNER, status: 'configured' });
    });

    it('shows a stranger nothing', async () => {
      const res = await request(server)
        .get('/v1/vault/emergency-access/granted-to-me')
        .set(bearer('mfa', STRANGER))
        .expect(200);
      expect(res.body).toEqual([]);
    });
  });

  describe('the waiting period', () => {
    it('refuses a release before anything was requested', async () => {
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(409, { error: 'not_requested' });
    });

    it('starts the clock on request and notifies the owner', async () => {
      const before = notifier.sent.length;
      const res = await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(200);

      const policy = res.body as PolicyDto;
      expect(policy.status).toBe('waiting');
      expect(new Date(policy.releasesAt!).getTime()).toBe(
        now.getTime() + WAITING_HOURS * 60 * 60 * 1000,
      );
      expect(notifier.sent.slice(before)).toEqual([
        expect.objectContaining({ kind: 'requested', ownerUserId: OWNER, policyId }),
      ]);
    });

    it('refuses to release while the period is running', async () => {
      now = new Date('2026-08-02T09:00:00.000Z'); // 24h in, 48h required
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(403, { error: 'waiting_period_active' });
    });

    it('refuses a duplicate request while one is pending', async () => {
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(409, { error: 'already_waiting' });
    });

    it("refuses another user's policy", async () => {
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(bearer('mfa', STRANGER))
        .expect(404, { error: 'not_found' });
    });
  });

  describe('the owner says no', () => {
    it('denies without step-up, because a denial must be one tap', async () => {
      const res = await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/deny`)
        .set(asOwner())
        .expect(200);
      expect((res.body as PolicyDto).status).toBe('denied_by_owner');
    });

    it('blocks the release outright', async () => {
      now = new Date('2026-08-10T09:00:00.000Z'); // long past the original window
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(403, { error: 'denied_by_owner' });
    });

    it('makes the denial STICKY - waiting does not clear it', async () => {
      // The grinding attack from docs/03 §5.2: request again and again until
      // the owner is offline. A time-based cooldown would eventually let this
      // through; a sticky deny never does.
      now = new Date('2026-09-01T09:00:00.000Z');
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(409, { error: 'denied_by_owner' });

      now = new Date('2027-01-01T09:00:00.000Z');
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(409, { error: 'denied_by_owner' });
    });

    it('counts and notifies every blocked attempt', async () => {
      const res = await request(server)
        .get('/v1/vault/emergency-access')
        .set(asOwner())
        .expect(200);
      const policy = (res.body as EscrowDto).policies.find((p) => p.id === policyId)!;
      // One successful request plus the blocked ones.
      expect(policy.requestCount).toBeGreaterThanOrEqual(4);
      expect(notifier.sent.filter((n) => n.kind === 'blocked').length).toBeGreaterThanOrEqual(3);
    });

    it('needs step-up to re-arm, and then the grantee can try again', async () => {
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/rearm`)
        .set(asOwner())
        .expect(403, { error: 'stepup_required' });

      const rearmed = await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/rearm`)
        .set(ownerStepUp())
        .expect(200);
      expect((rearmed.body as PolicyDto).status).toBe('configured');
      expect((rearmed.body as PolicyDto).requestCount).toBe(0);
    });
  });

  describe('a stranger gets one answer from EVERY policy route (M27 PR1a)', () => {
    /**
     * WHY DERIVED, AND WHY EVERY ROUTE. M27 PR1a fused the ownership predicate
     * into the lookup on both arms of this service, so a policy belonging to
     * someone else never arrives to be refused distinguishably. The grantee arm
     * had a test for that; the OWNER arm — deny, rearm, revoke — had none, and
     * a fix nothing exercises is a fix nobody checked.
     *
     * The corpus is read out of the controller rather than listed here. A
     * hand-listed set of routes beside a controller that grows is how a rule
     * ends up applied to one member of its category, which is the defect PR1a
     * opened by fixing. A new `:policyId` route joins this probe by existing.
     */
    const CONTROLLER = join(__dirname, '..', 'src', 'emergency.controller.ts');
    const ROUTE =
      /@(Post|Delete|Put|Patch|Get)\('vault\/emergency-access\/:policyId([^']*)'\)((?:\s*@[^\n]*\n)*)/g;

    const routes = [...readFileSync(CONTROLLER, 'utf8').matchAll(ROUTE)].map((m) => ({
      method: (m[1] as string).toLowerCase() as 'post' | 'delete' | 'put' | 'patch' | 'get',
      suffix: m[2] as string,
      stepUp: /StepUpGuard/.test(m[3] as string),
    }));

    it('finds every policy route, both arms, and the step-up split', () => {
      // ANTI-VACUITY AT EVERY LEVEL. A regex that stopped matching and a
      // controller with no policy routes look identical — and a total alone
      // cannot see the step-up-gated routes drop out, which are exactly the
      // ones a probe would otherwise never reach past a 403.
      expect(routes.length).toBeGreaterThanOrEqual(5);
      expect(routes.filter((r) => r.stepUp).length).toBeGreaterThanOrEqual(2);
      expect(routes.filter((r) => !r.stepUp).length).toBeGreaterThanOrEqual(3);
      // SETS, not counts: a suffix moving between two routes preserves both.
      expect(new Set(routes.map((r) => `${r.method} ${r.suffix}`))).toEqual(
        new Set(['post /request', 'post /deny', 'post /rearm', 'delete ', 'post /release']),
      );
    });

    it.each(routes.map((r) => [`${r.method.toUpperCase()} :policyId${r.suffix}`, r] as const))(
      '%s answers a stranger exactly not_found',
      async (_name, route) => {
        // Step-up freshness where the route demands it, so the probe reaches
        // the lookup instead of stopping at a 403 that says nothing about
        // ownership — the refusal every caller gets is not the one under test.
        const headers = route.stepUp ? bearer('stepup', STRANGER) : bearer('mfa', STRANGER);
        const url = `/v1/vault/emergency-access/${policyId}${route.suffix}`;
        const agent = request(server);
        // Typed as an opaque `{status, body}` on purpose: the assertion compares
        // whole values, and narrowing the body would invite asserting a shape
        // where the point is that every route returns the SAME one.
        const res = (await agent[route.method](url).set(headers)) as {
          status: number;
          body: unknown;
        };
        expect({ route: route.suffix, status: res.status, body: res.body }).toEqual({
          route: route.suffix,
          status: 404,
          body: { error: 'not_found' },
        });
      },
    );

    it('POSITIVE CONTROL: the policy is real and every route reachable', async () => {
      // Without this, all five 404s are equally consistent with a dead policy
      // id, a typo'd path, or a router that answers 404 for everything — and
      // the probe above would be measuring nothing.
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/deny`)
        .set(asOwner())
        .expect(200);
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/rearm`)
        .set(ownerStepUp())
        .expect(200);
      // The grantee arm answers its own refusal rather than not_found, which is
      // the other half of the property: refusals differ by REASON, never by
      // whether the caller is entitled to know the row exists.
      const granteeAnswer = await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee());
      expect(granteeAnswer.status).not.toBe(404);
    });
  });

  describe('release', () => {
    it('hands over the escrow once the period elapses undenied', async () => {
      now = new Date('2027-02-01T09:00:00.000Z');
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(200);

      now = new Date('2027-02-04T09:00:00.000Z'); // past the 48h window
      const res = await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(200);

      const release = res.body as ReleaseDto;
      expect(release.ownerUserId).toBe(OWNER);
      expect(release.threshold).toBe(1);

      // The point of the whole feature: the grantee reconstructs the owner's
      // master key on their own device and can open the owner's item.
      const masterKeyBytes = await recoverMasterKey({
        ownerUserId: OWNER,
        platformPart: release.platformPart,
        wrappedMasterKeyRecovery: release.wrappedMasterKeyRecovery,
        shares: [
          {
            granteeUserId: GRANTEE,
            sealedShare: release.keyShare,
            publicKey: granteeKeys.publicKey,
            privateKey: granteeKeys.privateKey,
          },
        ],
      });
      expect(Buffer.from(masterKeyBytes)).toEqual(Buffer.from(ownerMasterKeyBytes));

      const masterKey = await importAesKey(masterKeyBytes, ['encrypt', 'decrypt', 'unwrapKey']);
      const stored = await admin.query<{ blob_ct: Buffer }>(
        `SELECT blob_ct FROM vault_items WHERE id = $1`,
        [ownerItemId],
      );
      const plaintext = await decryptItem(
        masterKey,
        { userId: OWNER, itemId: ownerItemId, blobVersion: 1 },
        new Uint8Array(stored.rows[0]!.blob_ct),
      );
      expect(Buffer.from(plaintext).toString('utf8')).toBe(ITEM_SECRET);
    });

    it('is one-shot: the escrow is spent', async () => {
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(409, { error: 'already_released' });
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(409, { error: 'already_released' });
    });

    it('tells the owner it happened', () => {
      expect(notifier.sent.filter((n) => n.kind === 'released')).toHaveLength(1);
    });
  });

  describe('M-of-N and revocation', () => {
    it('re-arming from scratch retires the spent escrow', async () => {
      const escrow = await configureEscrow(
        [
          { userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys },
          { userId: OTHER_GRANTEE, contactId: OTHER_CONTACT_ID, keys: otherGranteeKeys },
        ],
        2,
      );
      expect(escrow.threshold).toBe(2);
      expect(escrow.policies).toHaveLength(2);
      // The old policy is gone, not merely superseded.
      expect(escrow.policies.map((p) => p.id)).not.toContain(policyId);
    });

    it('needs BOTH grantees when the threshold is 2', async () => {
      const describe1 = await request(server)
        .get('/v1/vault/emergency-access')
        .set(asOwner())
        .expect(200);
      const policies = (describe1.body as EscrowDto).policies;

      // Keyed by grantee rather than by position: which policy comes back
      // first is not something this test should depend on.
      const keysFor: Record<string, RecoveryKeyPair> = {
        [GRANTEE]: granteeKeys,
        [OTHER_GRANTEE]: otherGranteeKeys,
      };
      const held: Array<{
        granteeUserId: string;
        sealedShare: string;
        publicKey: Uint8Array;
        privateKey: Uint8Array;
      }> = [];
      const releases: ReleaseDto[] = [];

      for (const policy of policies) {
        const grantee = policy.granteeUserId;
        now = new Date('2027-03-01T09:00:00.000Z');
        await request(server)
          .post(`/v1/vault/emergency-access/${policy.id}/request`)
          .set(bearer('mfa', grantee))
          .expect(200);
        now = new Date('2027-03-04T09:00:00.000Z');
        const res = await request(server)
          .post(`/v1/vault/emergency-access/${policy.id}/release`)
          .set(bearer('mfa', grantee))
          .expect(200);
        const release = res.body as ReleaseDto;
        releases.push(release);
        held.push({
          granteeUserId: grantee,
          sealedShare: release.keyShare,
          publicKey: keysFor[grantee]!.publicKey,
          privateKey: keysFor[grantee]!.privateKey,
        });
      }
      expect(held).toHaveLength(2);

      // One share is not enough - either one of them.
      for (const single of held) {
        await expect(
          recoverMasterKey({
            ownerUserId: OWNER,
            platformPart: releases[0]!.platformPart,
            wrappedMasterKeyRecovery: releases[0]!.wrappedMasterKeyRecovery,
            shares: [single],
          }),
        ).rejects.toThrow();
      }

      // ...both together are.
      const recovered = await recoverMasterKey({
        ownerUserId: OWNER,
        platformPart: releases[0]!.platformPart,
        wrappedMasterKeyRecovery: releases[0]!.wrappedMasterKeyRecovery,
        shares: held,
      });
      expect(Buffer.from(recovered)).toEqual(Buffer.from(ownerMasterKeyBytes));
    });

    it('revokes a grantee, with step-up', async () => {
      const escrow = await configureEscrow([
        { userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys },
      ]);
      const target = escrow.policies[0]!.id;

      await request(server)
        .delete(`/v1/vault/emergency-access/${target}`)
        .set(asOwner())
        .expect(403, { error: 'stepup_required' });

      await request(server)
        .delete(`/v1/vault/emergency-access/${target}`)
        .set(ownerStepUp())
        .expect(204);

      await request(server)
        .post(`/v1/vault/emergency-access/${target}/request`)
        .set(asGrantee())
        .expect(404, { error: 'not_found' });
    });
  });

  describe('reset tears the escrow down with it (M6 security review)', () => {
    it('destroys every wrapping of the master key, not just the keyset one', async () => {
      // The regression this exists for: reset used to leave
      // emergency_access_configs intact, so a SECOND live wrapping of the
      // pre-reset master key survived. A grantee could then wait out the
      // period, release, and reconstruct the key the owner had been told was
      // destroyed - defeating the crypto-shred CLAUDE.md mandates for erasure.
      const escrow = await configureEscrow([
        { userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys },
      ]);
      expect(escrow.policies).toHaveLength(1);

      // The owner is also somebody else's emergency contact, which is the
      // normal case in a family: everyone names everyone.
      const ownerKeys = await generateRecoveryKeyPair();
      await request(server)
        .post('/v1/vault/recovery-key')
        .set(ownerStepUp())
        .send({
          publicKey: toBase64(ownerKeys.publicKey),
          wrappedPrivateKey: toBase64(ownerKeys.privateKey),
        })
        .expect(201);
      await request(server).get(`/v1/vault/recovery-key/${OWNER}`).set(asGrantee()).expect(200);

      const before = await admin.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM emergency_access_configs WHERE user_id = $1`,
        [OWNER],
      );
      expect(before.rows[0]!.count).toBe('1');

      const fresh = await createVaultEnrollment({
        userId: OWNER,
        password: 'after the reset',
        iterations: MIN_ITERATIONS,
      });
      await request(server)
        .post('/v1/vault/reset')
        .set(ownerStepUp())
        .send(fresh.enrollment.payload)
        .expect(200);

      // The recovery wrap is gone...
      const after = await admin.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM emergency_access_configs WHERE user_id = $1`,
        [OWNER],
      );
      expect(after.rows[0]!.count).toBe('0');

      // ...the policies are retired...
      const live = await admin.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM emergency_access_policies
          WHERE user_id = $1 AND deleted_at IS NULL`,
        [OWNER],
      );
      expect(live.rows[0]!.count).toBe('0');

      // ...the grantee no longer sees a designation...
      const granted = await request(server)
        .get('/v1/vault/emergency-access/granted-to-me')
        .set(asGrantee())
        .expect(200);
      expect(granted.body).toEqual([]);

      // ...and the release path is closed, so the old key cannot be recovered.
      await request(server)
        .post(`/v1/vault/emergency-access/${escrow.policies[0]!.id}/request`)
        .set(asGrantee())
        .expect(404, { error: 'not_found' });
    });

    it("unpublishes the owner's own grantee key, whose private half is now unusable", async () => {
      // The private half was wrapped under the destroyed master key. Leaving
      // the public half published would invite other owners to seal shares
      // that nobody can ever open - an escrow that looks healthy and fails at
      // the one moment it has to work.
      await request(server)
        .get(`/v1/vault/recovery-key/${OWNER}`)
        .set(asGrantee())
        .expect(404, { error: 'grantee_key_not_found' });

      const row = await admin.query<{
        public_key: Buffer | null;
        wrapped_private_key: Buffer | null;
      }>(`SELECT public_key, wrapped_private_key FROM vault_keysets WHERE user_id = $1`, [OWNER]);
      expect(row.rows[0]).toEqual({ public_key: null, wrapped_private_key: null });
    });

    it('records the escrow teardown in the reset audit event', () => {
      const resets = producer.messages
        .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
        .filter((e) => e.action === 'vault.reset');
      expect(resets.length).toBeGreaterThan(0);
      expect(resets[resets.length - 1]!.detail).toMatchObject({ escrowPoliciesRetired: 1 });
    });
  });

  describe('audit', () => {
    it('records every transition, including the refusals', () => {
      const actions = new Set(
        producer.messages.map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action),
      );
      for (const required of [
        'vault.recovery_key.published',
        'vault.emergency.configured',
        'vault.emergency.requested',
        'vault.emergency.request_blocked',
        'vault.emergency.denied',
        'vault.emergency.rearmed',
        'vault.emergency.released',
        'vault.emergency.revoked',
      ]) {
        expect(actions).toContain(required);
      }
    });

    it('names the owner as the party a release acted on behalf of', () => {
      const released = producer.messages
        .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
        .filter((e) => e.action === 'vault.emergency.released');
      expect(released.length).toBeGreaterThan(0);
      for (const event of released) {
        expect(event.actorId).not.toBe(OWNER);
        expect(event.onBehalfOf).toBe(OWNER);
      }
    });

    it('never carries escrow material or vault content', () => {
      const payloads = producer.messages.map((m) => m.value).join('\n');
      expect(payloads).not.toContain(ITEM_SECRET);
      expect(payloads).not.toContain(VAULT_PASSWORD);
      expect(payloads).not.toContain(toBase64(granteeKeys.privateKey));
      expect(payloads).not.toContain('safe deposit');
    });
  });

  /**
   * docs/03 §6a: emergency access is the LAST staged grant of a settlement
   * (§5.1 control 5). These run last so the escrow above is already armed and
   * released; they re-arm a fresh policy and prove the gate independently.
   */
  describe('the settlement gate', () => {
    const SETTLED_CASE = '11111111-2222-4333-8444-555555555555';

    afterEach(() => {
      settlementGate.permitted = true;
      settlementGate.caseId = null;
    });

    async function freshPolicy(): Promise<string> {
      const escrow = await configureEscrow([
        { userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys },
      ]);
      return escrow.policies[0]!.id;
    }

    it('BLOCKS a request while the estate is in settlement without the vault stage', async () => {
      const gatedPolicy = await freshPolicy();
      settlementGate.permitted = false;
      settlementGate.caseId = SETTLED_CASE;

      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/request`)
        .set(asGrantee())
        .expect(403, { error: 'settlement_stage_not_reached' });

      // The clock never started: the policy is untouched.
      const listed = await request(server)
        .get('/v1/vault/emergency-access')
        .set(asOwner())
        .expect(200);
      expect((listed.body as EscrowDto).policies[0]).toMatchObject({ status: 'configured' });

      // …and the refusal is audited with the case it derives from.
      const blocked = producer.messages
        .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
        .filter((e) => e.action === 'vault.emergency.release_blocked');
      expect(blocked.length).toBeGreaterThan(0);
      expect(blocked.at(-1)?.detail).toEqual({
        reason: 'settlement_stage_not_reached',
        caseId: SETTLED_CASE,
      });
    });

    it('BLOCKS a release when the estate enters settlement mid-waiting-period', async () => {
      const gatedPolicy = await freshPolicy();
      // The request happens while nothing is wrong…
      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/request`)
        .set(asGrantee())
        .expect(200);
      // …then a death case opens and the waiting period lapses.
      settlementGate.permitted = false;
      settlementGate.caseId = SETTLED_CASE;
      now = new Date(now.getTime() + 48 * 60 * 60 * 1000);

      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/release`)
        .set(asGrantee())
        .expect(403, { error: 'settlement_stage_not_reached' });

      // The escrow is unspent: releasing later, once the stage is approved,
      // still works — the gate delays, it does not destroy.
      settlementGate.permitted = true;
      settlementGate.caseId = null;
      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/release`)
        .set(asGrantee())
        .expect(200);
    });
  });
});
