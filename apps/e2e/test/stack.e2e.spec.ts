import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { parseEnvFile } from '@estate/stack';
import { currentTotpCode } from '@estate/service-identity/dist/totp';
import { ChainVerifier } from '@estate/service-audit/dist/verifier';
import { VAULT_SESSION_HEADER } from '@estate/service-vault/dist/vault-session.guard';
import {
  createVaultEnrollment,
  decryptItem,
  encryptItem,
  finishUnlock,
  MIN_ITERATIONS,
  prepareUnlock,
  proveUnlock,
  utf8,
} from '@estate/vault-crypto';
import { malwarePng, textPng } from './stack-fixtures';

/**
 * THE STACK TEST: the platform as running processes, over real HTTP, against
 * every real dependency — LocalStack KMS + S3, Redpanda, clamd, tesseract —
 * with nothing faked and nothing in-process.
 *
 * The in-process e2e suite proves flow logic; this suite proves the
 * INTEGRATIONS the stubs used to hide: the AWS adapter against a real KMS API,
 * the INSTREAM protocol against a real scanner (both verdicts), real OCR text
 * through the token pipeline into encrypted search, cross-service session
 * verification over the wire, the service credential on a real gate, and the
 * audit hash chain assembled from events that crossed a real broker.
 *
 * DETERMINISM CONTRACT: no bare sleeps. Every wait is a poll with a deadline.
 *
 * Gated on STACK_TEST=1 (the CI workflow sets it after bringing the stack up;
 * ci-guard.spec.ts turns a missing gate into a FAILURE when CI_REQUIRE_STACK
 * is set, so this suite cannot silently skip where it is required).
 */
const describeIfStack = process.env['STACK_TEST'] ? describe : describe.skip;

/** 'production' runs the rehearsal assertions; anything else the full journey. */
const PROFILE = process.env['STACK_PROFILE'] === 'production' ? 'production' : 'development';
const describeDev = PROFILE === 'development' ? describe : describe.skip;
const describeProd = PROFILE === 'production' ? describe : describe.skip;

const IDENTITY = process.env['STACK_IDENTITY_URL'] ?? 'http://localhost:3001';
const PROFILE_URL = process.env['STACK_PROFILE_URL'] ?? 'http://localhost:3002';
const ASSETS = process.env['STACK_ASSETS_URL'] ?? 'http://localhost:3003';
const DOCUMENTS = process.env['STACK_DOCUMENTS_URL'] ?? 'http://localhost:3005';
const VAULT = process.env['STACK_VAULT_URL'] ?? 'http://localhost:3006';
const SETTLEMENT = process.env['STACK_SETTLEMENT_URL'] ?? 'http://localhost:3007';
// M10: the AI assistant runs in the DEVELOPMENT profile only — production pins
// LLM_MODE=anthropic and no provider credential exists in this project, so the
// container is absent there (apps/stack/src/service-env.ts).
const ASSISTANT = process.env['STACK_ASSISTANT_URL'] ?? 'http://localhost:3009';
const AUDIT_DB =
  process.env['STACK_AUDIT_DB_URL'] ?? 'postgres://estate:estate_dev@localhost:5438/audit';
const CORE_DB =
  process.env['STACK_CORE_DB_URL'] ?? 'postgres://estate:estate_dev@localhost:5434/core';
const ENV_FILE = process.env['STACK_ENV_FILE'] ?? join(__dirname, '..', '..', '..', '.env.stack');

jest.setTimeout(240_000);

interface ApiResponse {
  status: number;
  body: unknown;
}

async function api(
  base: string,
  method: string,
  path: string,
  options: { token?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<ApiResponse> {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(options.body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      ...options.headers,
    },
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });
  const text = await response.text();
  return { status: response.status, body: text.length > 0 ? JSON.parse(text) : null };
}

function expectStatus(response: ApiResponse, status: number, context: string): unknown {
  if (response.status !== status) {
    throw new Error(
      `${context}: expected ${status}, got ${response.status}: ${JSON.stringify(response.body)}`,
    );
  }
  return response.body;
}

/** Poll until `fn` returns non-null. Deadline-bounded; never a bare sleep. */
async function pollUntil<T>(
  what: string,
  fn: () => Promise<T | null>,
  deadlineMs = 60_000,
  intervalMs = 750,
): Promise<T> {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    const result = await fn();
    if (result !== null) {
      return result;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

interface Session {
  token: string;
  userId: string;
  /** The address identity fed into the notifications recipient store (M9). */
  email: string;
}

async function registerAndLogin(base = IDENTITY): Promise<Session> {
  const email = `stack-${randomUUID()}@example.com`;
  const password = `Pw-${randomBytes(18).toString('base64url')}`;
  expectStatus(
    await api(base, 'POST', '/v1/auth/register', { body: { email, password } }),
    201,
    'register',
  );
  const login = expectStatus(
    await api(base, 'POST', '/v1/auth/login', { body: { email, password } }),
    200,
    'login',
  ) as { accessToken: string; userId: string };
  return { token: login.accessToken, userId: login.userId, email };
}

/** LocalStack's SES message store, read directly (not through the TLS front). */
const SES_QUERY = process.env['STACK_SES_QUERY_URL'] ?? 'http://localhost:4566';

interface SesStoredMessage {
  Source?: string;
  Destination?: { ToAddresses?: string[] };
  Subject?: string;
  Body?: { text_part?: string | null };
}

/** Poll LocalStack for a REAL delivered email matching `predicate` (M9). */
async function awaitSesMessage(
  what: string,
  predicate: (message: SesStoredMessage) => boolean,
): Promise<SesStoredMessage> {
  return pollUntil(what, async () => {
    const response = await fetch(`${SES_QUERY}/_aws/ses`);
    if (!response.ok) {
      return null;
    }
    const parsed = (await response.json()) as { messages?: SesStoredMessage[] };
    return parsed.messages?.find(predicate) ?? null;
  });
}

/** Enroll TOTP and elevate the session to step-up. */
async function stepUp(session: Session): Promise<void> {
  const enroll = expectStatus(
    await api(IDENTITY, 'POST', '/v1/auth/totp/enroll', { token: session.token }),
    201,
    'totp enroll',
  ) as { otpauthUri: string };
  const secret = new URL(enroll.otpauthUri).searchParams.get('secret');
  if (!secret) {
    throw new Error('totp enroll returned no secret');
  }
  expectStatus(
    await api(IDENTITY, 'POST', '/v1/auth/totp/verify', {
      token: session.token,
      body: { code: currentTotpCode(secret) },
    }),
    200,
    'totp verify',
  );
  expectStatus(
    await api(IDENTITY, 'POST', '/v1/auth/stepup', {
      token: session.token,
      body: { code: currentTotpCode(secret) },
    }),
    200,
    'stepup',
  );
}

describeIfStack('the running stack', () => {
  describeDev('owner journey across every real dependency', () => {
    let owner: Session;

    beforeAll(async () => {
      owner = await registerAndLogin();
    });

    it('verifies sessions across services: a forged token is refused everywhere', async () => {
      // Cross-service introspection over real HTTP — the M2->M7 trust chain.
      expect((await api(ASSETS, 'GET', '/v1/assets', { token: 'forged' })).status).toBe(401);
      expect((await api(DOCUMENTS, 'GET', '/v1/documents', { token: 'forged' })).status).toBe(401);
      expect((await api(ASSETS, 'GET', '/v1/assets', { token: owner.token })).status).toBe(200);
    });

    it('enforces step-up on beneficiary changes over the wire, then admits it', async () => {
      const created = expectStatus(
        await api(ASSETS, 'POST', '/v1/assets', {
          token: owner.token,
          body: { category: 'cash', title: 'stack probe account' },
        }),
        201,
        'create asset',
      ) as { assetId: string };

      const contact = expectStatus(
        await api(PROFILE_URL, 'POST', '/v1/contacts', {
          token: owner.token,
          body: { name: 'Stack Probe Beneficiary' },
        }),
        201,
        'create contact',
      ) as { id: string };

      // Fresh login, no step-up: the designation must be refused...
      const refused = await api(ASSETS, 'POST', `/v1/assets/${created.assetId}/beneficiaries`, {
        token: owner.token,
        body: { contactId: contact.id, designation: 'primary', sharePct: 100 },
      });
      expect(refused.status).toBe(403);

      // ...and admitted once identity records a real TOTP step-up, seen by
      // assets through introspection — no headers, no shortcuts. POLLED, not
      // immediate: the 403 above put a negative-step-up session into assets'
      // 30s introspection cache (the documented 2026-07-23 trade-off), so
      // step-up PROPAGATES to peer services within the cache TTL rather than
      // instantly. The deadline is the contract; a bare retry would hide it.
      await stepUp(owner);
      await pollUntil(
        'step-up to propagate through the introspection cache',
        async () => {
          const attempt = await api(ASSETS, 'POST', `/v1/assets/${created.assetId}/beneficiaries`, {
            token: owner.token,
            body: { contactId: contact.id, designation: 'primary', sharePct: 100 },
          });
          if (attempt.status === 201) {
            return true;
          }
          if (attempt.status === 403) {
            return null; // cache not expired yet — keep polling
          }
          throw new Error(
            `designation failed unexpectedly: ${attempt.status} ${JSON.stringify(attempt.body)}`,
          );
        },
        45_000,
      );
    });

    it('uploads through real clamd, reads real OCR text, finds it in encrypted search', async () => {
      const upload = expectStatus(
        await api(DOCUMENTS, 'POST', '/v1/documents/upload', {
          token: owner.token,
          body: {
            kind: 'property',
            title: 'scanned deed upload',
            mime: 'image/png',
            contentBase64: textPng('ESTATE STACK PROBE').toString('base64'),
          },
        }),
        201,
        'upload clean scan',
      ) as { documentId: string; ocrIndexed: boolean };

      // Tesseract actually READ the fixture — not a stub, not printable-run
      // extraction. This is the whole OCR pipeline being real.
      expect(upload.ocrIndexed).toBe(true);

      // 'probe' appears only in the scanned IMAGE, never in the title — a
      // search hit proves OCR text became per-user HMAC tokens and matched.
      const hits = expectStatus(
        await api(DOCUMENTS, 'GET', '/v1/documents/search?q=probe', { token: owner.token }),
        200,
        'search by OCR content',
      ) as Array<{ documentId: string }>;
      expect(hits.map((h) => h.documentId)).toContain(upload.documentId);
    });

    it('rejects a signature match from real clamd, storing nothing', async () => {
      const rejected = await api(DOCUMENTS, 'POST', '/v1/documents/upload', {
        token: owner.token,
        body: {
          kind: 'other',
          title: 'malware carrier probe',
          mime: 'image/png',
          contentBase64: malwarePng().toString('base64'),
        },
      });
      // The FOUND path of the hand-written INSTREAM client, against the real
      // daemon — the half PR3's smoke could not reach (see infra/clamav/).
      expect(rejected.status).toBe(422);
      expect((rejected.body as { error: string }).error).toBe('malware_detected');

      const listed = expectStatus(
        await api(DOCUMENTS, 'GET', '/v1/documents', { token: owner.token }),
        200,
        'list after rejection',
      ) as Array<{ title: string }>;
      expect(listed.some((d) => d.title === 'malware carrier probe')).toBe(false);
    });

    it('refuses a mislabeled text file before any scan (sniff gate)', async () => {
      const eicar = Buffer.from(
        'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
      );
      const response = await api(DOCUMENTS, 'POST', '/v1/documents/upload', {
        token: owner.token,
        body: {
          kind: 'other',
          title: 'raw eicar',
          mime: 'application/pdf',
          contentBase64: eicar.toString('base64'),
        },
      });
      expect(response.status).toBe(422);
      expect((response.body as { error: string }).error).toBe('unsupported_content');
    });

    it('runs Zone A over the wire: SRP enrollment, unlock, and an opaque item', async () => {
      // The vault password never transits; the server stores a verifier and
      // wrapped keys it cannot open. Until now this had only ever run against
      // an in-process transport.
      const password = `Vault-${randomBytes(12).toString('base64url')}`;
      const enrolled = await createVaultEnrollment({
        userId: owner.userId,
        password,
        iterations: MIN_ITERATIONS,
      });
      expectStatus(
        await api(VAULT, 'POST', '/v1/vault/keyset', {
          token: owner.token,
          body: enrolled.enrollment.payload,
        }),
        201,
        'vault enroll (step-up held from the beneficiary test)',
      );

      const challenge = expectStatus(
        await api(VAULT, 'POST', '/v1/vault/srp/start', { token: owner.token }),
        201,
        'srp start',
      ) as { handshakeId: string; srpSalt: string; kdfParams: unknown; serverPublic: string };

      const preparation = await prepareUnlock({
        userId: owner.userId,
        password,
        secretKey: enrolled.enrollment.secretKey,
        kdfParams: challenge.kdfParams,
        srpSalt: challenge.srpSalt,
      });
      const { m1, session: srpSession } = await proveUnlock(preparation, challenge.serverPublic);
      const opened = expectStatus(
        await api(VAULT, 'POST', '/v1/vault/srp/verify', {
          token: owner.token,
          body: {
            handshakeId: challenge.handshakeId,
            clientPublic: preparation.publicA,
            clientProof: m1,
          },
        }),
        200,
        'srp verify',
      ) as {
        serverProof: string;
        wrappedMasterKey: string;
        vaultSession: { id: string; token: string };
      };

      const unlocked = await finishUnlock({
        preparation,
        session: srpSession,
        serverM2: opened.serverProof,
        wrappedMasterKey: opened.wrappedMasterKey,
        vaultSessionId: opened.vaultSession.id,
      });

      const itemId = randomUUID();
      const secret = 'stack probe vault item';
      const blob = await encryptItem(
        unlocked.masterKey,
        { userId: owner.userId, itemId, blobVersion: 1 },
        utf8(secret),
      );
      const vaultHeaders = { [VAULT_SESSION_HEADER]: opened.vaultSession.token };
      expectStatus(
        await api(VAULT, 'POST', '/v1/vault/items', {
          token: owner.token,
          headers: vaultHeaders,
          body: { id: itemId, itemType: 'password', blob: Buffer.from(blob).toString('base64') },
        }),
        201,
        'vault item put',
      );
      const fetched = expectStatus(
        await api(VAULT, 'GET', `/v1/vault/items/${itemId}`, {
          token: owner.token,
          headers: vaultHeaders,
        }),
        200,
        'vault item get',
      ) as { blob: string; blobVersion: number };
      const plaintext = await decryptItem(
        unlocked.masterKey,
        { userId: owner.userId, itemId, blobVersion: fetched.blobVersion },
        new Uint8Array(Buffer.from(fetched.blob, 'base64')),
      );
      expect(Buffer.from(plaintext).toString('utf8')).toBe(secret);
    });

    it('answers the Zone A gate only to the service credential', async () => {
      // The §6a question about an OWNER's estate must not be mintable by a
      // user token — only by the credential the graph grants to vault.
      const path = `/v1/settlement/authority/vault-release?ownerUserId=${owner.userId}`;
      expect((await api(SETTLEMENT, 'GET', path)).status).toBe(401);
      expect((await api(SETTLEMENT, 'GET', path, { token: owner.token })).status).toBe(401);

      if (!existsSync(ENV_FILE)) {
        throw new Error(`stack env file not found at ${ENV_FILE}`);
      }
      const stackEnv = parseEnvFile(readFileSync(ENV_FILE, 'utf8'));
      const credential = stackEnv.get('VAULT_SETTLEMENT_INTERNAL_TOKEN');
      if (!credential) {
        throw new Error('VAULT_SETTLEMENT_INTERNAL_TOKEN missing from the stack env');
      }
      const answered = expectStatus(
        await api(SETTLEMENT, 'GET', path, {
          headers: { 'x-estate-service-credential': credential },
        }),
        200,
        'gate with the real credential',
      ) as { permitted: boolean; caseId: string | null };
      // No case exists for this owner, so nothing blocks: the gate permits and
      // the vault's own ≥24h waiting period governs. Blocking is reserved for
      // an estate with a non-terminal case lacking an approved vault stage —
      // making access HARDER while a death claim is unproven (docs/03 §6a).
      expect(answered).toEqual({ permitted: true, caseId: null });
    });

    it('drives a legal hold over the live wire: approval freezes the estate, rejection releases it (M9 PR2)', async () => {
      // The M4 zero-callers gap, closed and OBSERVED: the generator minted
      // settlement's documents credential from the graph edge, settlement
      // presents it inside the review-approve transaction, documents' guard
      // accepts it, and the hold then defeats a real step-up-authorized
      // deletion. No assertion here touches the database for the hold itself —
      // only behavior over HTTP proves it.
      const decedent = await registerAndLogin();
      const reporter = await registerAndLogin();
      const operator = await registerAndLogin();
      // Fixtures for the realities intake and review require, not the flow
      // under test: reporters must be linked contacts (M7 anti-enumeration)
      // and operators live on the CLI-managed allowlist.
      const core = new Client({ connectionString: CORE_DB });
      await core.connect();
      try {
        await core.query(
          `INSERT INTO contacts (id, owner_user_id, name_ct, linked_user_id, dek_id)
           VALUES ($1, $2, $3, $4, $5)`,
          [randomUUID(), decedent.userId, Buffer.from('ct'), reporter.userId, randomUUID()],
        );
        await core.query(`INSERT INTO settlement_operators (user_id) VALUES ($1)`, [
          operator.userId,
        ]);
      } finally {
        await core.end();
      }

      const upload = expectStatus(
        await api(DOCUMENTS, 'POST', '/v1/documents/upload', {
          token: decedent.token,
          body: {
            kind: 'legal',
            title: 'probate paper',
            mime: 'image/png',
            contentBase64: textPng('PROBATE CASE PAPERS').toString('base64'),
          },
        }),
        201,
        'upload before the case opens',
      ) as { documentId: string };

      const opened = expectStatus(
        await api(SETTLEMENT, 'POST', '/v1/settlement/cases', {
          token: reporter.token,
          body: { decedentUserId: decedent.userId, source: 'trusted_contact' },
        }),
        201,
        'settlement intake (dev journey)',
      ) as { caseId: string };

      await stepUp(operator);
      expectStatus(
        await api(SETTLEMENT, 'POST', `/v1/settlement/cases/${opened.caseId}/review/start`, {
          token: operator.token,
        }),
        200,
        'review start',
      );
      expectStatus(
        await api(SETTLEMENT, 'POST', `/v1/settlement/cases/${opened.caseId}/review`, {
          token: operator.token,
          body: { decision: 'approve' },
        }),
        200,
        'review approve — the account lock AND the estate-wide hold, one transaction',
      );

      // The decedent's login survives deceased_pending (the §5.1 rescue path),
      // and even their fresh step-up cannot free the document: the hold
      // answers to the case, not to any session. POLLED like the beneficiary
      // test above: the upload put a pre-step-up session into documents' 30s
      // introspection cache, so until it expires the DELETE 403s on freshness
      // rather than reaching the hold check.
      await stepUp(decedent);
      await pollUntil(
        'the held DELETE to be refused 409 by the hold, not 403 by the stale cache',
        async () => {
          const refused = await api(DOCUMENTS, 'DELETE', `/v1/documents/${upload.documentId}`, {
            token: decedent.token,
          });
          if (refused.status === 409) {
            expect((refused.body as { error: string }).error).toBe('legal_hold');
            return true;
          }
          if (refused.status === 403) {
            return null; // introspection cache not expired yet — keep polling
          }
          throw new Error(
            `held delete answered unexpectedly: ${refused.status} ${JSON.stringify(refused.body)}`,
          );
        },
        45_000,
      );

      // The evidence falls apart: one reject transition restores the account
      // and lifts the hold, and the owner's deletion goes through.
      expectStatus(
        await api(SETTLEMENT, 'POST', `/v1/settlement/cases/${opened.caseId}/review`, {
          token: operator.token,
          body: { decision: 'reject', reason: 'insufficient_evidence' },
        }),
        200,
        'review reject — restore + hold lifted in one transition',
      );
      expectStatus(
        await api(DOCUMENTS, 'DELETE', `/v1/documents/${upload.documentId}`, {
          token: decedent.token,
        }),
        200,
        'delete after the hold lifted',
      );
    });

    it('keeps the two notification surfaces on two credentials, live (M9 review)', async () => {
      // The M9 security review's load-bearing finding, pinned against the
      // running stack: one credential used to open BOTH send and
      // recipient-upsert, so vault's copy — the Zone A service, deliberately
      // holding no key material — could silently repoint any owner's address
      // and silence SETTLEMENT's §5.1 death-case alerts. Each credential must
      // now open exactly its own surface, and be REFUSED on the other.
      if (!existsSync(ENV_FILE)) {
        throw new Error(`stack env file not found at ${ENV_FILE}`);
      }
      const stackEnv = parseEnvFile(readFileSync(ENV_FILE, 'utf8'));
      const vaultSend = stackEnv.get('VAULT_NOTIFICATIONS_INTERNAL_TOKEN');
      const identityRecipients = stackEnv.get('IDENTITY_NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN');
      if (!vaultSend || !identityRecipients) {
        throw new Error('notification credentials missing from the stack env');
      }
      // The generator must never mint one value for both surfaces.
      expect(vaultSend).not.toBe(identityRecipients);

      const NOTIFICATIONS = process.env['STACK_NOTIFICATIONS_URL'] ?? 'http://localhost:3008';
      const recipientsPath = '/internal/v1/notifications/recipients';
      const sendPath = '/internal/v1/notifications/send';
      const asService = (credential: string): Record<string, string> => ({
        'x-estate-service-credential': credential,
      });

      // THE FIX: the send credential is refused on the recipient route.
      const hijack = await api(NOTIFICATIONS, 'PUT', recipientsPath, {
        headers: asService(vaultSend),
        body: { userId: owner.userId, email: 'attacker@evil.test' },
      });
      expect(hijack.status).toBe(401);

      // ...and the recipient credential is refused on the send route, so the
      // split constrains identity too rather than just widening its reach.
      const speak = await api(NOTIFICATIONS, 'POST', sendPath, {
        headers: asService(identityRecipients),
        body: { userId: owner.userId, kind: 'vault.reset', channel: 'email' },
      });
      expect(speak.status).toBe(401);

      // Each still works on its own surface — otherwise the two assertions
      // above would pass just as well against a service that refuses
      // everything (the vacuity failure this repo keeps catching).
      expect(
        (
          await api(NOTIFICATIONS, 'POST', sendPath, {
            headers: asService(vaultSend),
            body: { userId: owner.userId, kind: 'vault.reset', channel: 'email' },
          })
        ).status,
      ).toBe(200);
      expect(
        (
          await api(NOTIFICATIONS, 'PUT', recipientsPath, {
            headers: asService(identityRecipients),
            body: { userId: owner.userId, email: owner.email },
          })
        ).status,
      ).toBe(200);
    });

    it('computes an estate analysis over the live services, gated by the master switch (M10 PR3)', async () => {
      // The analysers are deterministic code, not a model, so this asserts real
      // arithmetic over the real ledger — and it runs with LLM_MODE=stub, which
      // is the point: nothing on this path reaches a model provider.

      // Deny by default: consent is the PRESENCE of an unrevoked row, so a user
      // who has never answered is refused exactly like one who revoked.
      expect(
        (await api(ASSISTANT, 'GET', '/v1/analysis/funding', { token: owner.token })).status,
      ).toBe(403);

      // Granting is step-up gated (widening third-party egress is export-class,
      // docs/01 §5). The session was elevated earlier in this journey; the
      // assistant sees that through introspection, so POLL for the cache TTL
      // rather than assuming it is immediate — the same documented propagation
      // delay the beneficiary designation above waits on.
      await pollUntil(
        'step-up to propagate to the assistant',
        async () => {
          const attempt = await api(ASSISTANT, 'PUT', '/v1/consents/assistant.enabled', {
            token: owner.token,
          });
          if (attempt.status === 200 || attempt.status === 204) {
            return true;
          }
          if (attempt.status === 403) {
            return null;
          }
          throw new Error(
            `consent grant failed: ${attempt.status} ${JSON.stringify(attempt.body)}`,
          );
        },
        45_000,
      );

      const funding = expectStatus(
        await api(ASSISTANT, 'GET', '/v1/analysis/funding', { token: owner.token }),
        200,
        'funding analysis',
      ) as { status: string; findings: { code: string }[]; disclaimer: string };

      // This owner has assets and no trust on file, so the analyser must say
      // that funding is not the gap rather than manufacturing one.
      expect(funding.status).toBe('ok');
      expect(funding.findings.map((f) => f.code)).toContain('no_trust_on_file');
      // docs/01 §2.8: education/analysis only, watermarked as non-legal-advice.
      expect(funding.disclaimer).toMatch(/not legal or tax advice/i);

      // The reference-data gate is environment-scoped, and this stack is not
      // production, so the tax analyser RUNS here — docs/05 says plainly that
      // a green analyser in the stack is not evidence of a reviewed tax table.
      const tax = expectStatus(
        await api(ASSISTANT, 'GET', '/v1/analysis/estate-tax', { token: owner.token }),
        200,
        'estate tax analysis',
      ) as { status: string; findings: { code: string }[]; summary: { grossEstate: string } };
      expect(tax.status).toBe('ok');
      // Money crosses the wire as a decimal STRING, end to end.
      expect(tax.summary.grossEstate).toMatch(/^\d+\.\d{2}$/);
      // This owner never created a profile row, and THIS EXACT CASE was the
      // first live run's failure: profile's `404 not_found` read as an outage
      // and the analysis answered 503. The true answer is "state unknown" —
      // asserted here so the no-profile path stays a real answer over the wire.
      expect(tax.findings.map((f) => f.code)).toContain('state_of_residence_unknown');

      // Revoking is NOT step-up gated (the protective action must never be
      // harder than the permissive one), and it switches the routes off again.
      expectStatus(
        await api(ASSISTANT, 'DELETE', '/v1/consents/assistant.enabled', { token: owner.token }),
        200,
        'revoke consent',
      );
      expect(
        (await api(ASSISTANT, 'GET', '/v1/analysis/funding', { token: owner.token })).status,
      ).toBe(403);
    });

    it('assembled every event into a VERIFIED hash chain across the real broker', async () => {
      const db = new Client({ connectionString: AUDIT_DB });
      await db.connect();
      try {
        // The journey above emitted these through seven different services'
        // producers, across Redpanda, into the one consumer. Poll until the
        // tail of the trail has landed; the broker hop is asynchronous.
        for (const action of [
          'asset.beneficiary.designated',
          'document.uploaded',
          'document.scan.rejected',
          'vault.item.created',
          // M9: identity fed the recipient store at registration, so the
          // notifications service's audit producer crossed the broker too.
          'notification.recipient.updated',
          // M9 PR2: settlement drove documents' legal hold inside the
          // review-approve transaction; documents audited it as the service.
          'document.legal_hold.set',
          // M10 PR3: an analysis run with no conversation and no model — the
          // audit event is the whole record that it happened.
          'assistant.analysis.completed',
        ] as const) {
          await pollUntil(`audit event ${action}`, async () => {
            const { rows } = await db.query(
              'SELECT 1 FROM audit_events WHERE action = $1 LIMIT 1',
              [action],
            );
            return rows.length > 0 ? true : null;
          });
        }
        const result = await new ChainVerifier(db).verify();
        if (!result.ok) {
          throw new Error(`chain broken at seq ${result.firstBadSeq}: ${result.reason}`);
        }
        expect(result.count).toBeGreaterThanOrEqual(10);
      } finally {
        await db.end();
      }
    });
  });

  describeProd('production rehearsal: the fail-fast posture, live', () => {
    it('boots, registers and logs in under full production config', async () => {
      const session = await registerAndLogin();
      expect(session.token.length).toBeGreaterThan(10);
    });

    it('opens a settlement case AND the owner is really told — the M9 carrier path, live', async () => {
      // Until M9 this route answered 503 notifications_unavailable here: a
      // waiting period nobody can be told about is not a control. Now the
      // FULL chain runs under production config: identity fed the recipient
      // store at registration, intake notifies through the notifications
      // service, and the message comes back out of LocalStack's SES store —
      // the same SendEmail API real AWS serves.
      const decedent = await registerAndLogin();
      const reporter = await registerAndLogin();
      // Seed the linked-contact reality intake requires (fixture, not the
      // flow under test — reporters must be linked contacts, the M7
      // anti-enumeration rule).
      const core = new Client({ connectionString: CORE_DB });
      await core.connect();
      try {
        await core.query(
          `INSERT INTO contacts (id, owner_user_id, name_ct, linked_user_id, dek_id)
           VALUES ($1, $2, $3, $4, $5)`,
          [randomUUID(), decedent.userId, Buffer.from('ct'), reporter.userId, randomUUID()],
        );
      } finally {
        await core.end();
      }
      expectStatus(
        await api(SETTLEMENT, 'POST', '/v1/settlement/cases', {
          token: reporter.token,
          body: { decedentUserId: decedent.userId, source: 'trusted_contact' },
        }),
        201,
        'settlement intake (prod, M9 — the retired 503)',
      );
      const message = await awaitSesMessage('the case_opened email in LocalStack SES', (m) =>
        (m.Destination?.ToAddresses ?? []).includes(decedent.email),
      );
      // Content-free doctrine, proven on the live wire: uniform subject, a
      // pointer into the app, and NO links of any kind (docs/03 §5.4, risk #10).
      expect(message.Subject).toBe('Estate — action needed');
      const body = message.Body?.text_part ?? '';
      expect(body).toContain('verify your identity');
      expect(body).not.toMatch(/https?:\/\//i);
      expect(body).not.toContain(reporter.email);
    });

    it('arms an emergency-access escrow, and reconfiguration notifies the owner (M9)', async () => {
      // The other retired 503. Real Zone A enrollment first — configure locks
      // the keyset — then two configures: the second retires the first's
      // grantees, which is exactly the silent transition the M6 review flagged
      // and M9 makes audible.
      const owner = await registerAndLogin();
      await stepUp(owner);
      const password = `Vault-${randomBytes(12).toString('base64url')}`;
      const enrolled = await createVaultEnrollment({
        userId: owner.userId,
        password,
        iterations: MIN_ITERATIONS,
      });
      expectStatus(
        await api(VAULT, 'POST', '/v1/vault/keyset', {
          token: owner.token,
          body: enrolled.enrollment.payload,
        }),
        201,
        'vault enroll (prod)',
      );
      const configureBody = (): unknown => ({
        threshold: 1,
        platformPart: randomBytes(32).toString('base64'),
        wrappedMasterKeyRecovery: randomBytes(64).toString('base64'),
        grantees: [
          {
            granteeContactId: randomUUID(),
            granteeUserId: randomUUID(),
            keyShare: randomBytes(48).toString('base64'),
            granteePublicKeySha256: randomBytes(32).toString('base64'),
            waitingPeriodHours: 24,
          },
        ],
      });
      expectStatus(
        await api(VAULT, 'POST', '/v1/vault/emergency-access', {
          token: owner.token,
          body: configureBody(),
        }),
        201,
        'first escrow configure (prod, M9 — the retired 503)',
      );
      expectStatus(
        await api(VAULT, 'POST', '/v1/vault/emergency-access', {
          token: owner.token,
          body: configureBody(),
        }),
        201,
        'reconfigure (retires the previous grantees)',
      );
      const message = await awaitSesMessage(
        'the grantees_changed email in LocalStack SES',
        (m) =>
          (m.Destination?.ToAddresses ?? []).includes(owner.email) &&
          (m.Body?.text_part ?? '').includes('emergency contacts'),
      );
      expect(message.Subject).toBe('Estate — action needed');
      expect(message.Body?.text_part ?? '').not.toMatch(/https?:\/\//i);
    });

    it('still enforces step-up on the wire in production mode', async () => {
      const owner = await registerAndLogin();
      const created = expectStatus(
        await api(ASSETS, 'POST', '/v1/assets', {
          token: owner.token,
          body: { category: 'cash', title: 'prod rehearsal account' },
        }),
        201,
        'create asset (prod)',
      ) as { assetId: string };
      const refused = await api(ASSETS, 'POST', `/v1/assets/${created.assetId}/beneficiaries`, {
        token: owner.token,
        body: { contactId: randomUUID(), designation: 'primary', sharePct: 50 },
      });
      expect(refused.status).toBe(403);
    });
  });
});
