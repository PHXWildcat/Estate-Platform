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
  fromBase64,
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
import { loadBundledPolicies, PolicyDecisionPoint, type EntityInput } from '@estate/authz';
import { VaultAuthz, type VaultAction } from '../src/authz.service';
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

  /** Every question this service put to Cedar, in order (M27 PR3b). */
  const pepCalls: Array<{
    principalUserId: string;
    action: VaultAction;
    resource: EntityInput;
  }> = [];

  /** Arm a fresh escrow over the current grantee set. */
  async function configureEscrow(
    grantees: Array<{ userId: string; contactId: string; keys: RecoveryKeyPair }>,
    threshold = 1,
    label?: string,
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
        ...(label === undefined ? {} : { label }),
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
    /*
     * A RECORDING PEP THAT REFUSES EXACTLY WHAT THE REAL ONE REFUSES (M27 PR3b).
     *
     * It delegates to a real `PolicyDecisionPoint` over the real bundled
     * policies, so no decision changes anywhere in this suite — the only thing
     * added is a log of what was asked. A double that answered differently
     * would make every other test in this file a test of the double.
     */
    const authzSpy = new (class extends VaultAuthz {
      override assertCan(
        principalUserId: string,
        action: VaultAction,
        resource: EntityInput,
        entities: readonly EntityInput[] = [resource],
      ): void {
        pepCalls.push({ principalUserId, action, resource });
        super.assertCan(principalUserId, action, resource, entities);
      }
    })(new PolicyDecisionPoint(loadBundledPolicies()));

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(VaultAuthz)
      .useValue(authzSpy)
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

  /**
   * THE OWNER-AUTHORED LABEL (M27 PR3b), closing docs/03 §6yy's `[OWNER: M27]`.
   *
   * Driven through the REAL route rather than asserted about the schema, because
   * three separate things have to agree for it to work — the zod refusal at the
   * edge, the DDL CHECK behind it, and the LEFT JOIN that carries it onto the
   * grantee's row — and only a request exercises all three. The screen tests
   * cover the rendering against a fake service; nothing but this covers the
   * write path.
   */
  describe('the escrow label', () => {
    afterAll(async () => {
      // Put the escrow back the way the rest of this file expects it: one
      // grantee, no label. `configure` replaces wholesale, so leaving a labelled
      // escrow behind would change what every later block reads.
      const restored = await configureEscrow([
        { userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys },
      ]);
      policyId = restored.policies[0]!.id;
    });

    it('reaches the GRANTEE’s row, and the owner’s own view of it', async () => {
      await configureEscrow(
        [{ userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys }],
        1,
        'The Dehn family vault',
      );

      const mine = await request(server)
        .get('/v1/vault/emergency-access')
        .set(asOwner())
        .expect(200);
      expect((mine.body as EscrowDto & { label: string | null }).label).toBe(
        'The Dehn family vault',
      );

      const theirs = await request(server)
        .get('/v1/vault/emergency-access/granted-to-me')
        .set(asGrantee())
        .expect(200);
      const row = (theirs.body as Array<{ ownerUserId: string; ownerLabel: string | null }>).find(
        (r) => r.ownerUserId === OWNER,
      );
      expect(row?.ownerLabel).toBe('The Dehn family vault');
    });

    /**
     * ABSENT CLEARS IT, and this is the arm a spread would have got wrong.
     * `configure` replaces an escrow wholesale — it retires every prior policy
     * and sends `grantees_changed` — so a label surviving into an arrangement
     * the owner rebuilt without one would be the OLD escrow's name on the NEW
     * escrow's grantee rows.
     */
    it('CLEARS the label when a re-arm omits it', async () => {
      await configureEscrow(
        [{ userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys }],
        1,
        'first name',
      );
      await configureEscrow([{ userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys }]);

      const mine = await request(server)
        .get('/v1/vault/emergency-access')
        .set(asOwner())
        .expect(200);
      expect((mine.body as EscrowDto & { label: string | null }).label).toBeNull();
    });

    /**
     * REFUSED AT THE EDGE, NOT REPAIRED — and refused with a 400, so the DDL
     * CHECK behind it is a backstop rather than the thing users meet. A label
     * that passed zod and violated the constraint would be a 500: an input
     * validation failure wearing the face of an outage.
     *
     * WHICH LAYER: this is the SCHEMA. The DDL's own half is proven by the
     * migration existing and by `checkConventions`; what a request can reach is
     * this one.
     */
    it.each([
      ['a control character', 'Mum\u0000s vault'],
      ['a right-to-left override', 'vault\u202Egnp.exe'],
      ['a zero-width joiner', 'Mum\u200Ds vault'],
      ['pure whitespace', '   '],
      ['81 characters', 'x'.repeat(81)],
    ])('refuses %s with 400, never a constraint violation', async (_name, label) => {
      const escrow = await createEscrow({
        ownerUserId: OWNER,
        masterKey: ownerMasterKeyBytes,
        grantees: [{ granteeUserId: GRANTEE, publicKey: granteeKeys.publicKey }],
        threshold: 1,
      });
      const res = await request(server)
        .post('/v1/vault/emergency-access')
        .set(ownerStepUp())
        .send({
          threshold: escrow.threshold,
          platformPart: escrow.platformPart,
          wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
          label,
          grantees: escrow.shares.map((share) => ({
            granteeContactId: CONTACT_ID,
            granteeUserId: share.granteeUserId,
            keyShare: share.sealedShare,
            granteePublicKeySha256: share.publicKeySha256,
            waitingPeriodHours: WAITING_HOURS,
          })),
        });
      expect(res.status).toBe(400);
      // NOT a 500, and not a token that reads as an outage. The two failures
      // have different remedies and must never share a spelling.
      expect(res.status).not.toBe(500);
      expect(JSON.stringify(res.body)).not.toContain('constraint');
    });

    it('POSITIVE CONTROL: a label at the 80-character boundary is accepted', async () => {
      // The discriminating arm for `81 characters` above: without it, that case
      // is equally consistent with a route that refuses every label.
      const ok = await configureEscrow(
        [{ userId: GRANTEE, contactId: CONTACT_ID, keys: granteeKeys }],
        1,
        'y'.repeat(80),
      );
      expect((ok as EscrowDto & { label: string | null }).label).toBe('y'.repeat(80));
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
      /^\s*@(Post|Delete|Put|Patch|Get)\('vault\/emergency-access\/:policyId([^']*)'\)((?:\s*@[^\n]*\n)*)/gm;

    const routes = [...readFileSync(CONTROLLER, 'utf8').matchAll(ROUTE)].map((m) => ({
      method: (m[1] as string).toLowerCase() as 'post' | 'delete' | 'put' | 'patch' | 'get',
      suffix: m[2] as string,
      stepUp: /StepUpGuard/.test(m[3] as string),
      /**
       * M27 PR3b. A SECOND CREDENTIAL THIS PROBE HAS TO CARRY, for exactly the
       * reason it already carries step-up freshness: the grantee read routes
       * are `VaultSessionGuard`-gated, so a probe without a vault session stops
       * at `403 vault_locked` and never reaches the ownership lookup this fence
       * exists to measure.
       *
       * THAT 403 IS NOT ITSELF A LEAK — it is the same answer whether the
       * policy exists or not — but a fence that stops before the thing it
       * tests is a fence that passes for the wrong reason. This one caught its
       * own new members on the first run, which is what "a new `:policyId`
       * route joins this probe by existing" is worth.
       */
      vaultSession: /VaultSessionGuard/.test(m[3] as string),
    }));

    it('finds every policy route, both arms, and the step-up split', () => {
      // ANTI-VACUITY AT EVERY LEVEL. A regex that stopped matching and a
      // controller with no policy routes look identical — and a total alone
      // cannot see the step-up-gated routes drop out, which are exactly the
      // ones a probe would otherwise never reach past a 403.
      expect(routes.length).toBeGreaterThanOrEqual(6);
      expect(routes.filter((r) => r.stepUp).length).toBeGreaterThanOrEqual(2);
      expect(routes.filter((r) => !r.stepUp).length).toBeGreaterThanOrEqual(4);
      // A FLOOR AT EVERY LEVEL, including the new one: a guard that stopped
      // being detected would silently send the probe back to measuring 403s.
      expect(routes.filter((r) => r.vaultSession).length).toBeGreaterThanOrEqual(1);
      // SETS, not counts: a suffix moving between two routes preserves both.
      expect(new Set(routes.map((r) => `${r.method} ${r.suffix}`))).toEqual(
        new Set([
          'post /request',
          'post /deny',
          'post /rearm',
          'delete ',
          'post /release',
          'get /items',
        ]),
      );
    });

    it.each(routes.map((r) => [`${r.method.toUpperCase()} :policyId${r.suffix}`, r] as const))(
      '%s answers a stranger exactly not_found',
      async (_name, route) => {
        // Step-up freshness where the route demands it, so the probe reaches
        // the lookup instead of stopping at a 403 that says nothing about
        // ownership — the refusal every caller gets is not the one under test.
        const headers = route.stepUp ? bearer('stepup', STRANGER) : bearer('mfa', STRANGER);
        if (route.vaultSession) {
          // STRANGER's OWN vault, really unlocked over SRP. The point of the
          // read routes' guard is that it proves nothing about the owner's
          // vault, so a stranger holding one must still be answered 404.
          headers[VAULT_SESSION_HEADER] = (await openVaultFor(STRANGER)).token;
        }
        const url = `/v1/vault/emergency-access/${policyId}${route.suffix}`.replace(
          ':itemId',
          ownerItemId,
        );
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
      // BEFORE ANYTHING IS COLLECTED, `releasedAt` is null. This is the
      // discriminating arm for `keeps \`releasedAt\` on the DTO …` below: without
      // it, that test passes for a field populated unconditionally.
      const virgin = await request(server)
        .get('/v1/vault/emergency-access')
        .set(asOwner())
        .expect(200);
      expect(
        (virgin.body as EscrowDto).policies.find((p) => p.id === policyId)?.releasedAt,
      ).toBeNull();

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

    /**
     * RE-COLLECTABLE (M27 PR3a), and this test used to assert the opposite.
     *
     * It was `is one-shot: the escrow is spent`, and what it pinned was the
     * §5.2 ceremony's central defect: a grantee who completed everything —
     * waited out the period, was not denied, passed the settlement gate — and
     * then closed the tab had consumed the arrangement and received nothing, in the
     * one scenario the feature exists for. The only recovery was the owner
     * re-arming, which is precisely what an incapacitated owner cannot do.
     *
     * WHAT MAKES IT SAFE IS THAT NOTHING WAS EVER DESTROYED, and this asserts
     * that rather than trusting it: the SECOND collection's material is put
     * through the same reconstruction as the first and must still open the
     * owner's item. `markReleased` writes `status` and `released_at` only —
     * `key_share_ct`, `platform_part` and `wrapped_master_key_recovery` all
     * survive it — so "one-shot" was a status check, never a one-way door.
     */
    it('is RE-COLLECTABLE: a second collection still opens the vault', async () => {
      const res = await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(200);

      const release = res.body as ReleaseDto;
      expect(release.ownerUserId).toBe(OWNER);

      // THE MATERIAL STILL WORKS. A 200 carrying a dead share would pass a
      // status assertion and fail the only thing the grantee needs.
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

      // REQUEST STAYS REFUSED, and that is not an oversight. `markRequested` is
      // the only writer of `status = 'waiting'`, so letting a released policy
      // re-request would restart a waiting period the grantee has already
      // served — making the protective clock a punishment for collecting twice.
      // The token is unchanged because the CONDITION is unchanged; what changed
      // is that its remedy is now "collect it" rather than "nothing".
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(409, { error: 'already_released' });
    });

    /**
     * EXACTLY ONE PER COLLECTION, counted rather than floored.
     *
     * This is the whole compensating control for making release repeatable:
     * §6uu's argument is that a second collection is MORE visible than the
     * first, not less. A `toBeGreaterThanOrEqual` would let a silent third
     * collection pass, which is the failure this number exists to catch.
     */
    it('tells the owner EVERY time, once per collection', () => {
      expect(notifier.sent.filter((n) => n.kind === 'released')).toHaveLength(2);
    });

    /**
     * THE PROTECTIVE ACTION MOVED WITH THE PERMISSIVE ONE (M27 PR3a).
     *
     * `deny` used to refuse on a released policy with `already_released`.
     * Leaving that while release repeated would have put the permissive action
     * one CallerGuard call away and the only ungated stop — `deny` — behind
     * `already_released`, with the other stop, `revoke`, behind StepUpGuard.
     * That is docs/03's rule inverted: the protective action must never be
     * harder than the permissive one.
     *
     * It cannot un-release what the grantee already holds. What it does is end
     * the arrangement's ability to hand over MORE, with one tap.
     */
    it('lets the owner STOP a re-collectable release with one ungated tap', async () => {
      // ANTI-VACUITY, in the test rather than in a neighbouring one: a 403 after
      // the deny proves nothing unless collection was working immediately
      // before it. This is the positive control, and it must be a 200.
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(200);

      const before = await request(server)
        .get('/v1/vault/emergency-access')
        .set(asOwner())
        .expect(200);
      const releasedRow = (before.body as EscrowDto).policies.find((p) => p.id === policyId);
      expect(releasedRow?.status).toBe('released');
      expect(releasedRow?.releasedAt).toEqual(expect.any(String));

      // No step-up header: deny is CallerGuard only, deliberately.
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/deny`)
        .set(asOwner())
        .expect(200);

      // Refused by TOKEN, not merely by status: `waiting_period_active` here
      // would mean the clock stopped it and the denial was never tested.
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(403, { error: 'denied_by_owner' });

      /*
       * THE STOP MUST NOT ERASE THE RECORD OF WHAT IT STOPPED (PR3a review).
       *
       * `markDenied` writes `denied_by_owner` over `released` and clears
       * `releases_at`, so `status` — the durable record only BECAUSE deny used
       * to refuse here — stops carrying the fact that the master key was handed
       * over. `released_at` was on the row already and on no DTO, so the owner's
       * view answered IDENTICALLY for a policy stopped before anything left the
       * server and one stopped after the grantee rebuilt their key. Those two
       * need a vault reset and nothing respectively.
       *
       * The discriminating arm is in `hands over the escrow …`, which asserts
       * this same field is null before any collection.
       */
      const after = await request(server)
        .get('/v1/vault/emergency-access')
        .set(asOwner())
        .expect(200);
      const deniedRow = (after.body as EscrowDto).policies.find((p) => p.id === policyId);
      expect(deniedRow?.status).toBe('denied_by_owner');
      expect(deniedRow?.releasesAt).toBeNull();
      expect(deniedRow?.releasedAt).toBe(releasedRow?.releasedAt);
    });
  });

  /**
   * THE GRANTEE'S READ (M27 PR3b).
   *
   * ESTABLISHES ITS OWN `released` STATE rather than inheriting the one the
   * `release` block leaves behind, and the first draft did inherit it. That
   * draft failed on its first run — the policy arrived `denied_by_owner`,
   * because a block in between had pressed the stop — which is the ordering
   * coupling this suite has produced before. A `beforeAll` that drives the real
   * ceremony costs three requests and removes a class of failure that reads
   * like a broken route.
   */
  describe('grantee read', () => {
    let granteeVault: string;
    let secondItemId: string;

    beforeAll(async () => {
      // Drive the ceremony rather than forging the row: `rearm` clears whatever
      // stop a previous block applied, and the request/elapse/release sequence
      // is the only thing that sets `released_at`, which the once-per-collection
      // predicate reads.
      await request(server).post(`/v1/vault/emergency-access/${policyId}/rearm`).set(ownerStepUp());
      now = new Date('2027-05-01T09:00:00.000Z');
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(200);
      now = new Date('2027-05-04T09:00:00.000Z'); // past the 48h window
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(200);
      /*
       * THE VAULT SESSION IS OPENED LAST, AFTER THE CLOCK HAS STOPPED MOVING.
       * Opening it first cost an hour: the waiting period is simulated by
       * jumping `now` forward three days, which expires any session minted
       * before the jump — so every read answered `403 vault_locked` and looked
       * exactly like a route that refuses released grantees. A time-travelling
       * fixture invalidates anything time-bound it set up earlier.
       */
      granteeVault = (await openVaultFor(GRANTEE)).token;

      /*
       * A SECOND ITEM, AND IT IS THE WHOLE POINT OF THE PEP TEST BELOW.
       * With one item, "one PEP call" and "one PEP call per item" are the same
       * number, and a per-REQUEST check would pass a per-ITEM assertion. Two
       * items make the two claims distinguishable — the fixture has to reach
       * the branch the property is about.
       */
      secondItemId = randomUUID();
      const blob2 = await encryptItem(
        await importAesKey(ownerMasterKeyBytes, ['encrypt', 'decrypt', 'unwrapKey']),
        { userId: OWNER, itemId: secondItemId, blobVersion: 1 },
        utf8('a second thing worth recovering'),
      );
      await admin.query(
        `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version)
         VALUES ($1, $2, 'secure_note', $3, 1)`,
        [secondItemId, OWNER, Buffer.from(blob2)],
      );
    });

    const asReader = (): Record<string, string> => ({
      ...asGrantee(),
      [VAULT_SESSION_HEADER]: granteeVault,
    });

    it('starts from a RELEASED policy — the precondition every test here needs', async () => {
      const row = await admin.query<{ status: string; released_at: Date | null }>(
        `SELECT status, released_at FROM emergency_access_policies WHERE id = $1`,
        [policyId],
      );
      expect(row.rows[0]?.status).toBe('released');
      expect(row.rows[0]?.released_at).not.toBeNull();
    });

    it('serves the owner’s items, and the ciphertext OPENS with the recovered key', async () => {
      const res = await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asReader())
        .expect(200);

      const page = res.body as { items: Array<{ id: string; blob: string; blobVersion: number }> };
      const item = page.items.find((i) => i.id === ownerItemId);
      expect(item).toBeDefined();

      // NOT A STATUS ASSERTION. A 200 carrying a blob that will not open is
      // exactly the failure this route could have and a shape check could not
      // see. The AAD is built with the OWNER's id — the grantee's would refuse
      // every blob, and the refusal would look like a wrong key.
      const masterKey = await importAesKey(ownerMasterKeyBytes, [
        'encrypt',
        'decrypt',
        'unwrapKey',
      ]);
      const plaintext = await decryptItem(
        masterKey,
        { userId: OWNER, itemId: ownerItemId, blobVersion: item!.blobVersion },
        fromBase64(item!.blob),
      );
      expect(Buffer.from(plaintext).toString('utf8')).toBe(ITEM_SECRET);
    });

    /**
     * EVERY ITEM SERVED GOES THROUGH THE PEP — and this test says exactly what
     * that is worth, because a mutation showed it is worth less than it looks.
     *
     * DELETING THE CEDAR CALL ALTOGETHER LEFT ALL 62 TESTS GREEN. That is not
     * a weak test and not an unfaithful mutation; it is CLAUDE.md's third
     * reason, and the honest reading is that the call CANNOT DENY here today.
     * `listReleasedGranteeIds` selects `status='released' AND deleted_at IS
     * NULL` for the owner, and `lockLiveByIdForGrantee` has already returned
     * this very row under the same two filters — so the principal is in the
     * set by construction, and `contains` is a foregone conclusion.
     *
     * WHAT THIS TEST THEREFORE CLAIMS, AND NOTHING MORE: the PEP is CONSULTED,
     * once per item handed over, with the owner and the released grantee set
     * on the resource. That is the shape a future narrowing attaches to — by
     * item type, by settlement stage, by anything Cedar can see — and it is
     * the thing that would rot silently, because nothing else in this service
     * would notice its absence. The gate that actually refuses a stopped
     * grantee is the status guard, and `STOPS serving items the moment the
     * owner denies` is the test that proves it.
     *
     * The limit is recorded in docs/03 §6yy and docs/06 rather than left as a
     * comment nobody re-reads.
     */
    it('consults the PEP once per item served, with owner and grantee set', async () => {
      const before = pepCalls.filter((c) => c.action === 'read_by_grantee').length;
      const res = await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asReader())
        .expect(200);
      const served = (res.body as { items: unknown[] }).items;
      // ANTI-VACUITY, and the reason the fixture inserts a second item: with a
      // one-item vault this assertion is satisfied by a per-REQUEST check.
      expect(served.length).toBeGreaterThanOrEqual(2);

      const asked = pepCalls.filter((c) => c.action === 'read_by_grantee').slice(before);
      expect(asked.length).toBe(served.length);
      for (const call of asked) {
        expect(call.principalUserId).toBe(GRANTEE);
        expect(call.resource.uid.type).toBe('VaultItem');
        expect(call.resource.attrs?.['owner']).toEqual({
          __entity: { type: 'User', id: OWNER },
        });
        // The set is READ FROM THE TABLE, not assembled from the caller — the
        // difference between a fence and a mirror. It cannot deny today (see
        // above), but what it carries has to be the real designation.
        expect(call.resource.attrs?.['emergencyGrantees']).toEqual([
          { __entity: { type: 'User', id: GRANTEE } },
        ]);
      }
    });

    /**
     * THE AUDIT TRAIL IS THE OWNER'S, WITH THE GRANTEE NAMED AS ACTOR. This is
     * the first producer for `vault.emergency.items_read`, which
     * `packages/contracts/src/audit.ts` has carried with no caller since PR0.
     */
    it('writes items_read to the OWNER’s trail with the grantee as actor', () => {
      const events = producer.messages
        .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
        .filter((e) => e.action === 'vault.emergency.items_read');
      // ANTI-VACUITY: `every` over an empty list is true, and this action had
      // ZERO producers before PR3b — so an emitter that was never wired up
      // would satisfy the loop below and nothing else in the suite would care.
      expect(events.length).toBeGreaterThan(0);
      for (const event of events) {
        expect(event.actorId).toBe(GRANTEE);
        // `onBehalfOf` is what makes this legible on the OWNER's trail. The
        // audit contract warns it is set per-call-site and inherited from
        // nowhere, so this is the assertion that says it actually was.
        expect(event.onBehalfOf).toBe(OWNER);
        expect(event.resourceId).toBe(OWNER);
      }
    });

    /**
     * ONCE PER COLLECTION, NOT PER READ — and the discriminating arm is that
     * the reads above ALREADY happened. A test that only counted after one
     * read would pass for an emitter that fires every time.
     */
    it('tells the owner ONCE per collection, however many reads follow', async () => {
      // COUNTED SINCE THIS BLOCK'S OWN COLLECTION, not over all time: earlier
      // blocks collect too, so a lifetime count would measure their history.
      const since = async (): Promise<number> => {
        const rows = await admin.query<{ count: string }>(
          `SELECT count(*)::text AS count FROM emergency_access_notifications n
             JOIN emergency_access_policies p ON p.id = n.policy_id
            WHERE n.policy_id = $1 AND n.kind = 'read_by_grantee'
              AND n.created_at >= p.released_at`,
          [policyId],
        );
        return Number(rows.rows[0]!.count);
      };
      expect(await since()).toBe(1);

      await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asReader())
        .expect(200);
      await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asReader())
        .expect(200);

      expect(await since()).toBe(1);

      /*
       * AND IT WAS ACTUALLY SENT (M27 PR3b review).
       *
       * Everything above counts ROWS in `emergency_access_notifications`, so a
       * service that claimed the notice and never handed it to the notifier
       * would pass a test named for telling the owner. `claimNotification` and
       * the send are deliberately separate steps — that is what makes the
       * dedupe safe under concurrency — which is exactly why the send needs
       * its own assertion rather than being implied by the claim.
       */
      const notices = notifier.sent.filter((n) => n.kind === 'read_by_grantee');
      expect(notices).toHaveLength(1);
      expect(notices[0]).toMatchObject({ kind: 'read_by_grantee', ownerUserId: OWNER, policyId });
      // …and the outcome was written back, so `delivered_at` is not left null
      // on a notice that did go out.
      const delivered = await admin.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM emergency_access_notifications n
           JOIN emergency_access_policies p ON p.id = n.policy_id
          WHERE n.policy_id = $1 AND n.kind = 'read_by_grantee'
            AND n.created_at >= p.released_at AND n.delivered_at IS NOT NULL`,
        [policyId],
      );
      expect(Number(delivered.rows[0]!.count)).toBe(1);

      // POSITIVE CONTROL: the audit trail is deliberately NOT deduped, so the
      // two reads above must have produced two events. Without this, an
      // emitter that had silently stopped doing anything would pass the count
      // above for the wrong reason.
      const audits = producer.messages
        .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
        .filter((e) => e.action === 'vault.emergency.items_read');
      expect(audits.length).toBeGreaterThanOrEqual(4);
    });

    it('RE-ARMS the notice on the next collection', async () => {
      const releasedAt = async (): Promise<string> =>
        (
          await admin.query<{ released_at: string }>(
            `SELECT released_at::text AS released_at FROM emergency_access_policies WHERE id = $1`,
            [policyId],
          )
        ).rows[0]!.released_at;
      const totalNotices = async (): Promise<number> =>
        Number(
          (
            await admin.query<{ count: string }>(
              `SELECT count(*)::text AS count FROM emergency_access_notifications
                WHERE policy_id = $1 AND kind = 'read_by_grantee'`,
              [policyId],
            )
          ).rows[0]!.count,
        );

      const firstReleasedAt = await releasedAt();
      const noticesBefore = await totalNotices();
      const sentBefore = notifier.sent.filter((n) => n.kind === 'read_by_grantee').length;

      /*
       * THE CLOCK MUST MOVE, AND THAT IS THE WHOLE TEST (M27 PR3b review).
       *
       * The dedupe predicate is `created_at >= released_at`, both written from
       * the injected clock. With the clock frozen, a second collection writes
       * the SAME `released_at`, the previous collection's notice still
       * satisfies the predicate, and the read is deduped — so the count stayed
       * 1 and the test passed. It passed identically for a `hasNotifiedSince`
       * that ignored its `since` argument altogether, which is to say it could
       * not observe the re-arm it is named for. Advancing the clock is what
       * makes the two collections distinguishable at all.
       */
      now = new Date(now.getTime() + 60 * 60 * 1000);
      // A VAULT SESSION MINTED BEFORE A CLOCK JUMP IS EXPIRED AFTER IT, and
      // its 403 `vault_locked` would stand in for this test's own refusals —
      // the failure mode that costs an hour every time it is rediscovered.
      // Re-minting here also repairs the reader for the tests that follow,
      // which share this block's `granteeVault`.
      granteeVault = (await openVaultFor(GRANTEE)).token;
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/release`)
        .set(asGrantee())
        .expect(200);

      // ANTI-VACUITY: if `released_at` did not actually move, everything below
      // is measuring the frozen-clock case again.
      const secondReleasedAt = await releasedAt();
      expect(secondReleasedAt).not.toBe(firstReleasedAt);

      await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asReader())
        .expect(200);

      const rows = await admin.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM emergency_access_notifications n
           JOIN emergency_access_policies p ON p.id = n.policy_id
          WHERE n.policy_id = $1 AND n.kind = 'read_by_grantee'
            AND n.created_at >= p.released_at`,
        [policyId],
      );
      /*
       * ONE AGAIN, NOT TWO, and that is the assertion. `released_at` moved
       * forward with the new collection, so the predicate now counts only the
       * notices earned SINCE it — the previous collection's notice falls out
       * of scope by itself. A stored `notified` flag would have needed each of
       * the four writers that move a policy in and out of `released` to reset
       * it; this needs none of them.
       */
      expect(Number(rows.rows[0]!.count)).toBe(1);
      // …and it is a NEW notice, not the old one recounted. This is the pair
      // the frozen clock made indistinguishable: one row in scope, two rows in
      // total, and a second send actually handed to the notifier.
      expect(await totalNotices()).toBe(noticesBefore + 1);
      expect(notifier.sent.filter((n) => n.kind === 'read_by_grantee')).toHaveLength(
        sentBefore + 1,
      );
    });

    /**
     * THE GUARD, NOT THE POLICY. A released grantee who has not unlocked their
     * own vault gets `vault_locked` — the same refusal any locked caller gets
     * on any vault route, and deliberately NOT one of this route's own tokens.
     * A control firing must not read as an outage, and a locked vault must not
     * read as a revoked arrangement.
     */
    /**
     * PAGING, on the SAME cursor grammar as the owner's own list.
     *
     * `toDto`, `encodeCursor` and `decodeCursor` are exported from
     * `vault.service.ts` and reused here rather than reimplemented, because two
     * codecs are two things to keep in step and could disagree about a
     * malformed cursor while looking identical. That reuse is only worth
     * anything if the grantee path actually walks a cursor, which nothing did
     * until this test — the paging branch was shipped uncovered.
     */
    it('pages the owner’s items, and the pages do not overlap', async () => {
      const first = await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items?limit=1`)
        .set(asReader())
        .expect(200);
      const page1 = first.body as { items: Array<{ id: string }>; nextCursor: string | null };
      expect(page1.items).toHaveLength(1);
      expect(page1.nextCursor).not.toBeNull();

      const second = await request(server)
        .get(
          `/v1/vault/emergency-access/${policyId}/items?limit=1&cursor=${encodeURIComponent(
            page1.nextCursor as string,
          )}`,
        )
        .set(asReader())
        .expect(200);
      const page2 = second.body as { items: Array<{ id: string }>; nextCursor: string | null };
      expect(page2.items).toHaveLength(1);

      // SETS, not counts. A cursor that was ignored would return page 1 again
      // and every length assertion above would still pass.
      expect(page2.items[0]?.id).not.toBe(page1.items[0]?.id);
      expect(new Set([page1.items[0]?.id, page2.items[0]?.id])).toEqual(
        new Set([ownerItemId, secondItemId]),
      );
    });

    /*
     * EVERY MALFORMED SHAPE, NOT JUST THE ONE THAT FAILS FIRST (PR3b review).
     *
     * This asserted a single cursor — one that dies on the `lastIndexOf('|')`
     * guard, the very first check — so it said nothing about the arms after
     * it. The one that mattered was `<valid ISO>|<not a uuid>`: it passed
     * every check the function made, bound against a `uuid` column, and came
     * back as 500 `internal_error`. A crafted input answering with an outage's
     * face is the defect this test is named for, and it was reachable on a
     * Zone A cross-user route.
     *
     * The table names WHICH guard each row exercises, so a future change that
     * collapses two of them cannot leave a row silently testing the same arm
     * twice.
     */
    it.each([
      ['not base64url at all', 'not-a-cursor'],
      ['no separator', Buffer.from('2020-01-01T00:00:00.000Z').toString('base64url')],
      ['a separator but no id', Buffer.from('2020-01-01T00:00:00.000Z|').toString('base64url')],
      ['an unparseable timestamp', Buffer.from(`nonsense|${'a'.repeat(8)}`).toString('base64url')],
      [
        'a valid timestamp and an id that is not a uuid',
        Buffer.from('2020-01-01T00:00:00.000Z|zzz').toString('base64url'),
      ],
    ])(
      'refuses a malformed cursor (%s) as a CLIENT error, not an outage',
      async (_name, cursor) => {
        const res = await request(server)
          .get(
            `/v1/vault/emergency-access/${policyId}/items?limit=1&cursor=${encodeURIComponent(cursor)}`,
          )
          .set(asReader());
        expect(res.status).toBe(409);
        expect((res.body as { error: string }).error).toBe('invalid_cursor');
      },
    );

    it('refuses a released grantee who has not opened their OWN vault', async () => {
      const res = await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asGrantee());
      expect(res.status).toBe(403);
      expect((res.body as { error: string }).error).toBe('vault_locked');
      expect((res.body as { error: string }).error).not.toBe('denied_by_owner');
    });

    /**
     * UNIFORM 404 for "no such policy" and "not yours" alike. STRANGER holds a
     * real vault session of their own, so what is being measured is the policy
     * lookup and not the guard.
     */
    it('answers 404 to a policy that is not the caller’s', async () => {
      const strangerVault = (await openVaultFor(STRANGER)).token;
      await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set({ ...bearer('mfa', STRANGER), [VAULT_SESSION_HEADER]: strangerVault })
        .expect(404);
      await request(server)
        .get(`/v1/vault/emergency-access/${randomUUID()}/items`)
        .set({ ...bearer('mfa', STRANGER), [VAULT_SESSION_HEADER]: strangerVault })
        .expect(404);
    });

    /**
     * THE STOP ACTUALLY STOPS THE READ, which is the property PR3a's one-tap
     * deny was for and the reason this route reads `status` inside the
     * transaction rather than trusting the collection that preceded it.
     *
     * WHICH LAYER: this is the SERVICE's guard, not Cedar's. The two are
     * separable and both real — `authz.spec.ts` proves the Cedar layer on its
     * own resource — and saying which one each test exercises is the whole
     * point of having named them.
     */
    it('STOPS serving items the moment the owner denies', async () => {
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/deny`)
        .set(asOwner())
        .expect(200);

      const res = await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asReader());
      expect(res.status).toBe(403);
      expect((res.body as { error: string }).error).toBe('denied_by_owner');

      // AND THE REFUSAL IS NOT AN OUTAGE. Two failures with different remedies
      // never share a token: a stopped grantee must not read the same word as
      // one whose service is down.
      expect((res.body as { error: string }).error).not.toBe('service_unavailable');
    });

    it('refuses a policy that was never collected, with its own token', async () => {
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/rearm`)
        .set(ownerStepUp())
        .expect(200);

      const res = await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asReader());
      expect(res.status).toBe(409);
      expect((res.body as { error: string }).error).toBe('not_collected');
      // The DISAGREEING arm: `not_collected` and `denied_by_owner` are the two
      // states an owner reaches with two different buttons, and a grantee has
      // to be able to tell them apart to know whether to ask again.
      expect((res.body as { error: string }).error).not.toBe('denied_by_owner');
    });

    /**
     * MID-WAITING-PERIOD, WITH A STALE `released_at` — the arm that makes the
     * read guard's `status === 'released'` load-bearing, and the one the first
     * draft of this block did not reach.
     *
     * FOUND BY MUTATION. Widening the guard to admit `waiting` left all 61
     * tests green, because the only refusal case here went through `rearm`,
     * which writes `status = 'configured'`. That looked like a redundant
     * guard. It is not, and the reason is a field `rearm` does NOT touch:
     * `markRearmed` clears `denied_at`, `requested_at`, `releases_at` and
     * `request_count`, and leaves `released_at` standing — deliberately, since
     * M27 PR3a anchors "was this ever collected" on it precisely because no
     * transition clears it.
     *
     * So a policy that was collected, stopped, re-armed and re-requested sits
     * at `waiting` with a `released_at` from the PREVIOUS collection. A guard
     * keyed on "has a released_at" rather than on the status would hand that
     * grantee the owner's items while the owner's waiting period — the whole
     * §5.2 control — was still running, using a collection the owner had
     * already stopped. This is that state, driven rather than forged.
     */
    it('refuses a re-requested policy MID-WAITING-PERIOD, stale released_at and all', async () => {
      now = new Date('2027-06-01T09:00:00.000Z');
      // RE-OPENED AFTER THE JUMP, for the reason `beforeAll` gives: a vault
      // session minted before a clock jump is expired on the other side of it,
      // and the resulting `403 vault_locked` would masquerade as this test's
      // own refusal — a false green wearing the right status code.
      granteeVault = (await openVaultFor(GRANTEE)).token;
      await request(server)
        .post(`/v1/vault/emergency-access/${policyId}/request`)
        .set(asGrantee())
        .expect(200);

      // THE FIXTURE REACHES THE BRANCH, asserted rather than assumed: this is
      // only a test of the status arm if the row really is `waiting` AND
      // really does carry a released_at from before.
      const row = await admin.query<{ status: string; released_at: Date | null }>(
        `SELECT status, released_at FROM emergency_access_policies WHERE id = $1`,
        [policyId],
      );
      expect(row.rows[0]?.status).toBe('waiting');
      expect(row.rows[0]?.released_at).not.toBeNull();

      const res = await request(server)
        .get(`/v1/vault/emergency-access/${policyId}/items`)
        .set(asReader());
      expect(res.status).toBe(409);
      expect((res.body as { error: string }).error).toBe('not_collected');
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
        surface: 'request',
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

    /**
     * THE GATE RUNS ON EVERY COLLECTION, NOT ONLY THE FIRST (M27 PR3a review).
     *
     * The test above walks `waiting → released`, so it is structurally unable
     * to see the released arm — and the review proved that with a mutation
     * skipping `assertSettlementPermits` whenever the policy was already
     * `released`, which left all 46 tests green. The behaviour that mutation
     * describes is the window docs/03 §5.1 control 5 exists to close: grantee
     * collects legitimately on day 0, the owner dies, a case opens with the
     * vault stage unapproved, and the grantee collects the platform half again
     * anyway.
     *
     * Repeatable release is what makes per-collection gating load-bearing. It
     * was correct in the shipped service and unasserted, which is the weak-test
     * arm of CLAUDE.md's three-way rule rather than a live hole.
     */
    it('BLOCKS a RE-collection when settlement opens after the first one', async () => {
      const gatedPolicy = await freshPolicy();
      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/request`)
        .set(asGrantee())
        .expect(200);
      now = new Date(now.getTime() + 48 * 60 * 60 * 1000);

      // A legitimate first collection, while nothing is wrong.
      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/release`)
        .set(asGrantee())
        .expect(200);

      // The estate then enters settlement without the vault stage approved.
      settlementGate.permitted = false;
      settlementGate.caseId = SETTLED_CASE;
      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/release`)
        .set(asGrantee())
        .expect(403, { error: 'settlement_stage_not_reached' });

      // POSITIVE CONTROL, and it is what tells this test apart from one that
      // merely observes a released policy refusing: lift the gate and the same
      // policy collects again. Without it, a mutation making `released`
      // uncollectable outright would satisfy the assertion above.
      settlementGate.permitted = true;
      settlementGate.caseId = null;
      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/release`)
        .set(asGrantee())
        .expect(200);
    });

    /**
     * THE STATUS HALF OF `collectable` IS LOAD-BEARING, and nothing proved it.
     *
     * `const collectable = true;` survived all 46 tests, because on every state
     * the API can reach, a non-null `releases_at` already implies
     * `status ∈ {waiting, released}` — so the predicate's status test is
     * carried entirely by `!policy.releases_at`. The invariant making that safe
     * is that `markRearmed` clears `releases_at` alongside `status =
     * 'configured'`; if a future change ever cleared one without the other, the
     * status test is the only thing standing between a re-armed policy and a
     * collection with no waiting period served.
     *
     * The API cannot construct that state, so this forges it directly. That is
     * deliberate: a fence for an invariant has to exercise the arm where the
     * two facts DISAGREE, and here only the database can disagree.
     */
    /**
     * THE READ IS GATED TOO, AND NOTHING TESTED IT (M27 PR3b).
     *
     * FOUND BY MUTATION: deleting `assertSettlementPermits` from the grantee
     * read left all 62 tests green. The gate was in the code and correct — the
     * weak-test arm of CLAUDE.md's three-way rule, not a live hole — but a
     * control nothing exercises is a control nobody has checked.
     *
     * IT MATTERS MOST HERE, of all the places it appears. A collection hands
     * over key material once; a READ is the repeatable act that follows it, and
     * it can follow by days. docs/03 §5.1 control 5 makes Zone A the LAST
     * staged grant of a settlement, so an estate that enters settlement after a
     * legitimate collection must stop the reading, not merely refuse the next
     * collection — otherwise the gate is a speed bump around a door already
     * open.
     */
    it('BLOCKS a grantee READ when settlement opens after the collection', async () => {
      const gatedPolicy = await freshPolicy();
      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/request`)
        .set(asGrantee())
        .expect(200);
      now = new Date(now.getTime() + 48 * 60 * 60 * 1000);
      await request(server)
        .post(`/v1/vault/emergency-access/${gatedPolicy}/release`)
        .set(asGrantee())
        .expect(200);

      // The session is minted AFTER the clock jump, for the reason the grantee
      // read block gives at length: one minted before it is already expired,
      // and its 403 would stand in for this test's.
      const vaultToken = (await openVaultFor(GRANTEE)).token;
      const reader = { ...asGrantee(), [VAULT_SESSION_HEADER]: vaultToken };

      // POSITIVE CONTROL FIRST: the read works while nothing is wrong. Without
      // it, the refusal below is equally consistent with a route that never
      // served anything.
      await request(server)
        .get(`/v1/vault/emergency-access/${gatedPolicy}/items`)
        .set(reader)
        .expect(200);

      settlementGate.permitted = false;
      settlementGate.caseId = SETTLED_CASE;
      const before = producer.messages.length;
      await request(server)
        .get(`/v1/vault/emergency-access/${gatedPolicy}/items`)
        .set(reader)
        .expect(403, { error: 'settlement_stage_not_reached' });

      /*
       * THE TRAIL MUST SAY WHICH ACT WAS REFUSED (M27 PR3b review).
       *
       * All three grantee acts go through one gate and produced one
       * indistinguishable event, so a reading screen refetching looked exactly
       * like a grantee hammering the release route — the probing signal this
       * action exists to surface. Asserted on the event emitted by THIS
       * request (sliced from `before`) rather than on `.at(-1)`, so it cannot
       * pass by reading some earlier arm's event.
       */
      const blockedByRead = producer.messages
        .slice(before)
        .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
        .filter((e) => e.action === 'vault.emergency.release_blocked');
      expect(blockedByRead).toHaveLength(1);
      expect(blockedByRead[0]?.detail).toEqual({
        reason: 'settlement_stage_not_reached',
        caseId: SETTLED_CASE,
        surface: 'read',
      });

      settlementGate.permitted = true;
      settlementGate.caseId = null;
      // …and it comes back when the gate does, so the refusal was the gate and
      // not the collection being spent.
      await request(server)
        .get(`/v1/vault/emergency-access/${gatedPolicy}/items`)
        .set(reader)
        .expect(200);
    });

    it('refuses a policy whose status and releases_at DISAGREE', async () => {
      const forged = await freshPolicy();
      await admin.query(
        `UPDATE emergency_access_policies
            SET status = 'configured', releases_at = $2
          WHERE id = $1`,
        [forged, new Date(now.getTime() - 60 * 60 * 1000)],
      );

      // `configured` is not collectable however elapsed the clock looks.
      await request(server)
        .post(`/v1/vault/emergency-access/${forged}/release`)
        .set(asGrantee())
        .expect(409, { error: 'not_requested' });

      // POSITIVE CONTROL on the forgery itself: the row really does carry a
      // past `releases_at`, so the refusal above came from the STATUS test and
      // not from the elapsed test finding nothing to read.
      const row = await admin.query<{ status: string; releases_at: Date | null }>(
        `SELECT status, releases_at FROM emergency_access_policies WHERE id = $1`,
        [forged],
      );
      expect(row.rows[0]?.status).toBe('configured');
      expect(row.rows[0]?.releases_at).not.toBeNull();
      expect(row.rows[0]!.releases_at!.getTime()).toBeLessThan(now.getTime());
    });
  });
});
