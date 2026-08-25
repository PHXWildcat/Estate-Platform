/**
 * M6 vault E2E: identity + vault, wired the way production wires them.
 *
 * The vault app's SessionVerifier is a REAL `HttpSessionVerifier` whose
 * transport dispatches to identity's in-process `/v1/auth/session` handler, so
 * every gate in this test is cleared by a genuine identity-minted session that
 * the vault service independently verified — including a real TOTP step-up.
 *
 * What the test is really asserting is a negative: the user's vault password
 * and Secret Key are used only on the "client" side of this file, and the
 * server never sees either. The audit chain is then ingested and verified, and
 * every emitted payload is swept for vault content.
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
import { SETTLEMENT_AUTHORITY } from '@estate/settlement-client';
import {
  createEscrow,
  createVaultEnrollment,
  decryptItem,
  encryptItem,
  exportMasterKeyBytes,
  finishUnlock,
  generateRecoveryKeyPair,
  MIN_ITERATIONS,
  prepareUnlock,
  proveUnlock,
  toBase64,
  utf8,
} from '@estate/vault-crypto';
import { AppModule as IdentityAppModule } from '@estate/service-identity/dist/app.module';
import { currentTotpCode } from '@estate/service-identity/dist/totp';
import { STEPUP_MAX_DENIALS } from '@estate/service-identity/dist/stepup';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AUDIT_PRODUCER as IDENTITY_AUDIT_PRODUCER } from '@estate/service-identity/dist/di-tokens';
import { AppModule as VaultAppModule } from '@estate/service-vault/dist/app.module';
import {
  AUDIT_PRODUCER as VAULT_AUDIT_PRODUCER,
  PG_POOL_CONFIG as VAULT_PG_POOL_CONFIG,
} from '@estate/service-vault/dist/di-tokens';
import { VAULT_SESSION_HEADER } from '@estate/service-vault/dist/vault-session.guard';
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

describeIfPg('vault (Zone A) end to end', () => {
  jest.setTimeout(180_000);

  const stamp = Date.now();
  const authSchema = `e2e_vault_auth_${stamp}`;
  const vaultSchema = `e2e_vault_${stamp}`;
  const auditSchema = `e2e_vault_audit_${stamp}`;

  const VAULT_PASSWORD = 'a memorable but long vault password';
  const ITEM_SECRET = 'brokerage.example.com / alexandra / s3cr3t-passphrase';

  let admin: Client;
  let auditDb: Client;
  let identityApp: ReturnType<TestingModule['createNestApplication']>;
  let vaultApp: ReturnType<TestingModule['createNestApplication']>;
  let identityProducer: InMemoryAuditProducer;
  let vaultProducer: InMemoryAuditProducer;

  beforeAll(async () => {
    const baseUrl = process.env['PG_TEST_URL']!;
    admin = new Client({ connectionString: baseUrl });
    await admin.connect();
    for (const schema of [authSchema, vaultSchema, auditSchema]) {
      await admin.query(`CREATE SCHEMA ${schema}`);
    }

    for (const [pkg, schema] of [
      ['@estate/service-identity', authSchema],
      ['@estate/service-vault', vaultSchema],
      ['@estate/service-audit', auditSchema],
    ] as const) {
      const client = new Client({ connectionString: schemaScopedUrl(baseUrl, schema) });
      await client.connect();
      await new Migrator(client, migrationsDirOf(pkg)).migrate();
      await client.end();
    }

    // --- identity (the session authority) ---
    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, authSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['EMAIL_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];
    identityProducer = new InMemoryAuditProducer();
    const identityRef = await Test.createTestingModule({ imports: [IdentityAppModule] })
      .overrideProvider(IDENTITY_AUDIT_PRODUCER)
      .useValue(identityProducer)
      .compile();
    identityApp = identityRef.createNestApplication({ logger: false });
    await identityApp.init();
    const identityHttp = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);

    // Real introspection transport: the vault's verifier calls identity's
    // in-process /v1/auth/session handler.
    const fetchImpl: FetchLike = async (url, init) => {
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
      fetchImpl,
    });

    // --- vault (the downstream service) ---
    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, vaultSchema);
    delete process.env['KAFKA_BROKERS'];
    vaultProducer = new InMemoryAuditProducer();
    const vaultRef = await Test.createTestingModule({ imports: [VaultAppModule] })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(verifier)
      .overrideProvider(VAULT_AUDIT_PRODUCER)
      .useValue(vaultProducer)
      // M7 PR2 (docs/03 §6a): emergency access now consults settlement. No
      // settlement service runs in this spec, and the real client fails CLOSED
      // — which would block every request/release here. This owner has no
      // death case, so the honest stand-in permits; the gate's blocking
      // behaviour is proven in the vault service's own integration suite and
      // in settlement.e2e.spec.ts.
      .overrideProvider(SETTLEMENT_AUTHORITY)
      .useValue({
        checkVaultRelease: () => Promise.resolve({ permitted: true, caseId: null }),
      })
      .overrideProvider(VAULT_PG_POOL_CONFIG)
      .useValue({ connectionString: schemaScopedUrl(baseUrl, vaultSchema) })
      .compile();
    vaultApp = vaultRef.createNestApplication({ logger: false });
    await vaultApp.init();

    auditDb = new Client({ connectionString: schemaScopedUrl(baseUrl, auditSchema) });
    await auditDb.connect();
  });

  afterAll(async () => {
    await vaultApp?.close();
    await identityApp?.close();
    await auditDb?.end();
    for (const schema of [authSchema, vaultSchema, auditSchema]) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    }
    await admin.end();
  });

  it('opens a Zone A vault end to end without the server ever seeing the password', async () => {
    const identity = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const vault = supertest(vaultApp.getHttpServer() as Parameters<typeof supertest>[0]);

    // --- account: register, log in, step up for real ---
    const email = `vault-${randomUUID()}@example.com`;
    const password = `Pw-${randomBytes(18).toString('base64url')}`;
    await identity.post('/v1/auth/register').send({ email, password }).expect(201);
    const login = await identity.post('/v1/auth/login').send({ email, password }).expect(200);
    const { accessToken, userId } = login.body as { accessToken: string; userId: string };
    const bearer = { authorization: `Bearer ${accessToken}` };

    // A forged credential never gets in.
    await vault.get('/v1/vault/keyset').set('authorization', 'Bearer forged').expect(401);
    await vault.get('/v1/vault/keyset').expect(401, { error: 'unauthorized' });

    // The vault is not enrolled, and enrolling needs step-up.
    await vault
      .get('/v1/vault/keyset')
      .set(bearer)
      .expect(200, { enrolled: false, updatedAt: null });

    const enrolled = await createVaultEnrollment({
      userId,
      password: VAULT_PASSWORD,
      iterations: MIN_ITERATIONS,
    });
    await vault
      .post('/v1/vault/keyset')
      .set(bearer)
      .send(enrolled.enrollment.payload)
      .expect(403, { error: 'stepup_required' });

    const enroll = await identity.post('/v1/auth/totp/enroll').set(bearer).expect(201);
    const secret = new URL((enroll.body as { otpauthUri: string }).otpauthUri).searchParams.get(
      'secret',
    )!;
    await identity
      .post('/v1/auth/totp/verify')
      .set(bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);
    await identity
      .post('/v1/auth/stepup')
      .set(bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);

    // The SAME token now clears the gate, because the vault re-introspects and
    // sees the fresh step-up.
    await vault.post('/v1/vault/keyset').set(bearer).send(enrolled.enrollment.payload).expect(201);

    // --- unlock: a real SRP exchange ---
    const challenge = await vault
      .post('/v1/vault/srp/start')
      .set(bearer)
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
      password: VAULT_PASSWORD,
      secretKey: enrolled.enrollment.secretKey,
      kdfParams: challenge.kdfParams,
      srpSalt: challenge.srpSalt,
    });
    const { m1, session } = await proveUnlock(preparation, challenge.serverPublic);

    const opened = await vault
      .post('/v1/vault/srp/verify')
      .set(bearer)
      .send({
        handshakeId: challenge.handshakeId,
        clientPublic: preparation.publicA,
        clientProof: m1,
      })
      .expect(200)
      .then(
        (res) =>
          res.body as {
            serverProof: string;
            wrappedMasterKey: string;
            vaultSession: { id: string; token: string };
          },
      );

    // The client verifies the SERVER too, then unwraps the master key locally.
    const unlocked = await finishUnlock({
      preparation,
      session,
      serverM2: opened.serverProof,
      wrappedMasterKey: opened.wrappedMasterKey,
      vaultSessionId: opened.vaultSession.id,
    });
    const unlockedHeaders = { ...bearer, [VAULT_SESSION_HEADER]: opened.vaultSession.token };

    // --- items: encrypted here, opaque there ---
    const itemId = randomUUID();
    const blob = await encryptItem(
      unlocked.masterKey,
      { userId, itemId, blobVersion: 1 },
      utf8(ITEM_SECRET),
    );
    await vault
      .post('/v1/vault/items')
      .set(unlockedHeaders)
      .send({ id: itemId, itemType: 'password', blob: Buffer.from(blob).toString('base64') })
      .expect(201);

    const fetched = await vault
      .get(`/v1/vault/items/${itemId}`)
      .set(unlockedHeaders)
      .expect(200)
      .then((res) => res.body as { blob: string; blobVersion: number });

    const plaintext = await decryptItem(
      unlocked.masterKey,
      { userId, itemId, blobVersion: fetched.blobVersion },
      new Uint8Array(Buffer.from(fetched.blob, 'base64')),
    );
    expect(Buffer.from(plaintext).toString('utf8')).toBe(ITEM_SECRET);

    // --- emergency access: a second real user, the full multi-party flow ---
    //
    // docs/03 §5.2 end to end, across two genuinely separate identity accounts:
    // the owner arms an escrow, the contact asks, the owner says no, the owner
    // relents, the contact asks again, waits, and finally reconstructs the
    // owner's master key on their own device.
    const granteeEmail = `grantee-${randomUUID()}@example.com`;
    const granteePassword = `Pw-${randomBytes(18).toString('base64url')}`;
    await identity
      .post('/v1/auth/register')
      .send({ email: granteeEmail, password: granteePassword })
      .expect(201);
    const granteeLogin = await identity
      .post('/v1/auth/login')
      .send({ email: granteeEmail, password: granteePassword })
      .expect(200);
    const { accessToken: granteeToken, userId: granteeUserId } = granteeLogin.body as {
      accessToken: string;
      userId: string;
    };
    const granteeBearer = { authorization: `Bearer ${granteeToken}` };

    // The grantee needs their own vault and a published public key.
    const granteeEnrolled = await createVaultEnrollment({
      userId: granteeUserId,
      password: 'the grantee has a vault of their own',
      iterations: MIN_ITERATIONS,
    });
    const granteeEnroll = await identity
      .post('/v1/auth/totp/enroll')
      .set(granteeBearer)
      .expect(201);
    const granteeSecret = new URL(
      (granteeEnroll.body as { otpauthUri: string }).otpauthUri,
    ).searchParams.get('secret')!;
    await identity
      .post('/v1/auth/totp/verify')
      .set(granteeBearer)
      .send({ code: currentTotpCode(granteeSecret) })
      .expect(200);
    await identity
      .post('/v1/auth/stepup')
      .set(granteeBearer)
      .send({ code: currentTotpCode(granteeSecret) })
      .expect(200);
    await vault
      .post('/v1/vault/keyset')
      .set(granteeBearer)
      .send(granteeEnrolled.enrollment.payload)
      .expect(201);

    const granteeKeys = await generateRecoveryKeyPair();
    await vault
      .post('/v1/vault/recovery-key')
      .set(granteeBearer)
      .send({
        publicKey: toBase64(granteeKeys.publicKey),
        wrappedPrivateKey: toBase64(granteeKeys.privateKey),
      })
      .expect(201);

    // The owner fetches that key (and would confirm its fingerprint out of
    // band before trusting it) and seals a share to it.
    const published = await vault
      .get(`/v1/vault/recovery-key/${granteeUserId}`)
      // The owner's OWN open vault, as of M27 PR5: the key-offer route sits
      // behind the same guard its sibling `GET /v1/vault/recovery-key` always
      // had, so the caller proves a vault password and Secret Key rather than
      // only a session. `unlockedHeaders` is that proof, already in hand here.
      .set(unlockedHeaders)
      .expect(200)
      .then((res) => (res.body as { publicKey: string }).publicKey);
    expect(published).toBe(toBase64(granteeKeys.publicKey));

    const ownerMasterKeyBytes = await exportMasterKeyBytes({
      userId,
      auk: preparation.auk,
      wrappedMasterKey: enrolled.enrollment.payload.wrappedMasterKey,
    });
    const escrow = await createEscrow({
      ownerUserId: userId,
      masterKey: ownerMasterKeyBytes,
      grantees: [{ granteeUserId, publicKey: granteeKeys.publicKey }],
      threshold: 1,
    });

    const configured = await vault
      .post('/v1/vault/emergency-access')
      .set(bearer)
      .send({
        threshold: escrow.threshold,
        platformPart: escrow.platformPart,
        wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
        grantees: [
          {
            granteeContactId: randomUUID(),
            granteeUserId,
            keyShare: escrow.shares[0]!.sealedShare,
            granteePublicKeySha256: escrow.shares[0]!.publicKeySha256,
            waitingPeriodHours: 24,
          },
        ],
      })
      .expect(201)
      .then((res) => res.body as { policies: Array<{ id: string }> });
    const policyId = configured.policies[0]!.id;

    // The contact asks; the owner refuses; the refusal sticks.
    await vault
      .post(`/v1/vault/emergency-access/${policyId}/request`)
      .set(granteeBearer)
      .expect(200);
    await vault
      .post(`/v1/vault/emergency-access/${policyId}/release`)
      .set(granteeBearer)
      .expect(403, { error: 'waiting_period_active' });
    await vault.post(`/v1/vault/emergency-access/${policyId}/deny`).set(bearer).expect(200);
    await vault
      .post(`/v1/vault/emergency-access/${policyId}/request`)
      .set(granteeBearer)
      .expect(409, { error: 'denied_by_owner' });

    // The owner relents. The waiting period is real, so the release itself is
    // covered by the service's integration suite with an injected clock; here
    // what matters is that two separate identities drove the whole exchange.
    await vault.post(`/v1/vault/emergency-access/${policyId}/rearm`).set(bearer).expect(200);
    const rearmed = await vault
      .get('/v1/vault/emergency-access')
      .set(bearer)
      .expect(200)
      .then((res) => res.body as { policies: Array<{ status: string }> });
    expect(rearmed.policies[0]!.status).toBe('configured');

    // A stranger cannot see or touch someone else's escrow.
    await vault
      .post(`/v1/vault/emergency-access/${policyId}/request`)
      .set(bearer)
      .expect(404, { error: 'not_found' });

    // Locking ends item access immediately.
    await vault.post('/v1/vault/lock').set(unlockedHeaders).expect(204);
    await vault.get('/v1/vault/items').set(unlockedHeaders).expect(403, { error: 'vault_locked' });

    // --- a wrong vault password fails, and is audited ---
    const wrongChallenge = await vault
      .post('/v1/vault/srp/start')
      .set(bearer)
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
    const wrongPrep = await prepareUnlock({
      userId,
      password: 'not the vault password',
      secretKey: enrolled.enrollment.secretKey,
      kdfParams: wrongChallenge.kdfParams,
      srpSalt: wrongChallenge.srpSalt,
    });
    const wrongProof = await proveUnlock(wrongPrep, wrongChallenge.serverPublic);
    await vault
      .post('/v1/vault/srp/verify')
      .set(bearer)
      .send({
        handshakeId: wrongChallenge.handshakeId,
        clientPublic: wrongPrep.publicA,
        clientProof: wrongProof.m1,
      })
      .expect(401, { error: 'srp_failed' });

    // --- audit: the chain accepts every event and stays intact ---
    const auditMessages = [...identityProducer.messages, ...vaultProducer.messages].filter(
      (m) => m.topic === TOPICS.auditEvents,
    );
    const ingestor = new AuditIngestor(auditDb);
    for (const message of auditMessages) {
      const result = await ingestor.ingest(message.value);
      expect(result.status).toBe('appended');
    }
    const verdict = await new ChainVerifier(auditDb).verify();
    expect(verdict).toEqual({ ok: true, count: auditMessages.length });

    const actions = new Set(
      auditMessages.map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action),
    );
    for (const required of [
      'auth.stepup.granted',
      'vault.keyset.created',
      'vault.opened',
      'vault.item.created',
      'vault.item.accessed',
      'vault.session.revoked',
      'vault.open.failed',
      // emergency access, driven by two separate real identities
      'vault.recovery_key.published',
      'vault.emergency.configured',
      'vault.emergency.requested',
      'vault.emergency.request_blocked',
      'vault.emergency.denied',
      'vault.emergency.rearmed',
    ]) {
      expect(actions).toContain(required);
    }

    // --- the firewall sweep: nothing Zone A ever reaches the bus ---
    const allPayloads = [...identityProducer.messages, ...vaultProducer.messages]
      .map((m) => m.value)
      .join('\n');
    expect(allPayloads).not.toContain(VAULT_PASSWORD);
    expect(allPayloads).not.toContain(ITEM_SECRET);
    expect(allPayloads).not.toContain(enrolled.enrollment.secretKey);
    expect(allPayloads).not.toContain(enrolled.enrollment.payload.wrappedMasterKey);
    expect(allPayloads).not.toContain(enrolled.enrollment.payload.srpVerifier);
    expect(allPayloads).not.toContain(email);
    expect(allPayloads).not.toContain(password);
    expect(allPayloads).not.toContain('brokerage.example.com');

    // ...and the vault cluster itself holds only ciphertext.
    const stored = await admin.query<{ blob_ct: Buffer }>(
      `SELECT blob_ct FROM ${vaultSchema}.vault_items`,
    );
    for (const row of stored.rows) {
      expect(row.blob_ct.toString('binary')).not.toContain(ITEM_SECRET);
    }
  });

  /*
   * WHAT `POST /v1/auth/stepup` ACTUALLY ANSWERS, OBSERVED ON THE WIRE.
   *
   * BOTH vault clients word these three refusals, and until now both derived
   * the vocabulary from identity's SOURCE without either ever seeing identity
   * send one. That gap is not academic: the defect M27 PR6 and M44 PR1 fixed was
   * two clients being confidently wrong about what this route says. The
   * extension answered a mistyped authenticator digit with PAIRING copy; the
   * vault origin answered an ENDED SESSION with "try the current one". Both
   * carried a comment asserting identity replies `invalid_credentials` here —
   * the LOGIN refusal, which this route never sends, and which this test would
   * have contradicted the day it was written.
   *
   * A derivation and an observation are different evidence. This is the
   * observation, and it is the only place in the repo that holds it.
   */
  it('answers a missing session, a wrong code and the cap with THREE distinct refusals', async () => {
    const identity = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const email = `stepup-${randomUUID()}@example.com`;
    const password = `Pw-${randomBytes(18).toString('base64url')}`;
    await identity.post('/v1/auth/register').send({ email, password }).expect(201);
    const login = await identity.post('/v1/auth/login').send({ email, password }).expect(200);
    const bearer = {
      authorization: `Bearer ${(login.body as { accessToken: string }).accessToken}`,
    };
    const enroll = await identity.post('/v1/auth/totp/enroll').set(bearer).expect(201);
    const secret = new URL((enroll.body as { otpauthUri: string }).otpauthUri).searchParams.get(
      'secret',
    )!;
    await identity
      .post('/v1/auth/totp/verify')
      .set(bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);

    /** A code that is wrong at the moment it is computed. */
    const wrongCode = (): string => (currentTotpCode(secret) === '000000' ? '111111' : '000000');

    /*
     * Post a wrong code, tolerating the ONE way this can legitimately succeed.
     *
     * The TOTP window can rotate between computing the guess and identity
     * scoring it, so the guess is occasionally the real code — about one attempt
     * in a million. That is not a failure of the thing under test, and a bare
     * `.expect(401)` would make this suite flake on a coin nobody can see. It is
     * retried rather than ignored, and the retries are COUNTED and asserted to
     * stay negligible, so a mapping that started answering 200 for every wrong
     * code could not hide inside the tolerance.
     */
    let rotations = 0;
    const postWrongCode = async (): Promise<{ status: number; body: unknown }> => {
      for (let tries = 0; tries < 4; tries += 1) {
        const answer = await identity
          .post('/v1/auth/stepup')
          .set(bearer)
          .send({ code: wrongCode() });
        if (answer.status !== 200) return { status: answer.status, body: answer.body };
        rotations += 1;
      }
      throw new Error('the wrong code was accepted four times running — that is not a rotation');
    };

    // NO SESSION — `SessionGuard`, not the code. The remedy is to authenticate
    // again, and the vault origin used to answer this "try the current one".
    await identity
      .post('/v1/auth/stepup')
      .send({ code: wrongCode() })
      .expect(401, { error: 'unauthorized' });

    // A WRONG CODE. `invalid_code`, never `invalid_credentials`.
    const refused = await postWrongCode();
    expect(refused.status).toBe(401);
    expect(refused.body).toEqual({ error: 'invalid_code' });

    /*
     * THE CAP, with a token of its own so a bound firing cannot read as a wrong
     * code. Driven to the refusal rather than to a hard-coded attempt index:
     * every answer before it must still be `invalid_code`, and the refusal must
     * arrive within the documented bound. Asserting the SEQUENCE is what makes
     * this more than "a 429 happened eventually".
     */
    const before: number[] = [];
    let capped = false;
    for (let attempt = 0; attempt < STEPUP_MAX_DENIALS + 2 && !capped; attempt += 1) {
      const answer = await postWrongCode();
      if (answer.status === 429) {
        expect(answer.body).toEqual({ error: 'too_many_attempts' });
        capped = true;
      } else {
        expect(answer.body).toEqual({ error: 'invalid_code' });
        before.push(answer.status);
      }
    }
    expect(capped).toBe(true);
    // ANTI-VACUITY: a cap that fired immediately would satisfy `capped` alone.
    expect(before.length).toBeGreaterThan(0);
    expect([...new Set(before)]).toEqual([401]);
    // And the rotation tolerance must stay a tolerance. If this is not ~0 the
    // route is accepting wrong codes and the retries are hiding it.
    expect(rotations).toBeLessThanOrEqual(1);
  });
});
