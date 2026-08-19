import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { parseEnvFile } from '@estate/stack';
import { currentTotpCode } from '@estate/service-identity/dist/totp';
import { ChainVerifier } from '@estate/service-audit/dist/verifier';
import { boundFor } from '@estate/service-audit/dist/decrypt-rate-bounds';
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

/**
 * Module load, i.e. before ANY test in this file runs — the scope the M18
 * decrypt-rate gate judges. It must cover the whole journey (so a
 * journey-caused anomaly is caught) and exclude earlier runs against a
 * long-lived local stack (whose anomaly rows are permanent: audit_events
 * REVOKEs UPDATE/DELETE, and a rebuild trips a designed alarm by decision).
 * Scoping to the gate's own test would hide exactly what it exists to find.
 */
const SUITE_START = new Date();

/** 'production' runs the rehearsal assertions; anything else the full journey. */
const PROFILE = process.env['STACK_PROFILE'] === 'production' ? 'production' : 'development';
const describeDev = PROFILE === 'development' ? describe : describe.skip;
const describeProd = PROFILE === 'production' ? describe : describe.skip;

const IDENTITY = process.env['STACK_IDENTITY_URL'] ?? 'http://localhost:3001';
const PROFILE_URL = process.env['STACK_PROFILE_URL'] ?? 'http://localhost:3002';
const ASSETS = process.env['STACK_ASSETS_URL'] ?? 'http://localhost:3003';
const DOCUMENTS = process.env['STACK_DOCUMENTS_URL'] ?? 'http://localhost:3005';
const VAULT = process.env['STACK_VAULT_URL'] ?? 'http://localhost:3006';
/**
 * The ISOLATED VAULT ORIGIN (M15). A different HOST, not a different port:
 * cookie scope ignores the port, so `localhost:3010` would have received the
 * app's session on every request (measured in a browser, not assumed).
 * `*.localhost` resolves to loopback and is a potentially-trustworthy origin,
 * so its `__Host-` Secure cookie is accepted there over plain http.
 */
const VAULT_WEB = process.env['STACK_VAULT_WEB_URL'] ?? 'http://vault.localhost:3010';
/** The origin the vault edge accepts an arrival POST from, and only that one. */
const APP_ORIGIN_FOR_VAULT = process.env['STACK_WEB_URL'] ?? 'http://localhost:3000';
/**
 * The ISOLATED OPERATOR ORIGIN (M21 PR3a, docs/03 TB7). A SECOND separate host
 * for the same measured reason as the vault's — cookie scope ignores the port —
 * and deliberately a second host rather than a second path on the vault's,
 * because the two origins must not be able to read each other's cookie.
 */
const OPERATOR_WEB = process.env['STACK_OPERATOR_WEB_URL'] ?? 'http://operator.localhost:3011';
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

/**
 * Poll LocalStack for a REAL delivered email (M9).
 *
 * BOTH SELECTORS ARE REQUIRED, and that is an M14 correction rather than
 * fussiness. Every kind shares one subject by design (docs/03 §5.4), so the
 * only two things that distinguish messages here are the recipient and the
 * body — and until M14 an address received at most one message per journey, so
 * call sites keyed on the address alone. M14 mails an address-verification code
 * at first login, which means EVERY address now receives an extra message and
 * an address-only match resolves to whichever arrived first. That is exactly
 * what happened: the production rehearsal's settlement assertion found the
 * verification mail and failed on the body it expected.
 *
 * Making `bodyIncludes` a required parameter rather than fixing the three call
 * sites is the point: a future kind added to any journey cannot silently make
 * an existing assertion ambiguous again.
 */
async function awaitSesMessage(
  what: string,
  selector: { to: string; bodyIncludes: string },
): Promise<SesStoredMessage> {
  return pollUntil(what, async () => {
    const response = await fetch(`${SES_QUERY}/_aws/ses`);
    if (!response.ok) {
      return null;
    }
    const parsed = (await response.json()) as { messages?: SesStoredMessage[] };
    return (
      parsed.messages?.find(
        (message) =>
          (message.Destination?.ToAddresses ?? []).includes(selector.to) &&
          (message.Body?.text_part ?? '').includes(selector.bodyIncludes),
      ) ?? null
    );
  });
}

/**
 * Drive the M14 ceremony end to end for a session: read the code out of the
 * REAL delivered message and type it back in.
 *
 * The only honest way to prove an address here, and the only way a production
 * test can reach the ARMING gates at all — they refuse an owner nobody proved.
 */
async function proveAddress(session: Session): Promise<void> {
  const message = await awaitSesMessage(`verification code for ${session.userId}`, {
    to: session.email,
    bodyIncludes: 'Confirm this email address',
  });
  const code = /EV1-[0-9A-Z-]+/.exec(message.Body?.text_part ?? '')?.[0];
  if (!code) {
    throw new Error('no verification code in the delivered message');
  }
  expectStatus(
    await api(IDENTITY, 'POST', '/v1/auth/email/verification/verify', {
      token: session.token,
      body: { code },
    }),
    200,
    'verify address',
  );
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

    /**
     * M14 — ADDRESS OWNERSHIP, end to end over the real carrier.
     *
     * Three shipped fail-closed gates (M6 §5.2, M7 §5.1, M13 §6g) rested on
     * `deliversToRealChannels`, a hardcoded literal on an adapter class that
     * asks whether SES is wired and never whether the stored address belongs to
     * the owner. This is the ceremony that makes the second question
     * answerable, driven the only way it can be honestly proved: by reading the
     * code out of a REAL delivered message and typing it back in.
     *
     * `owner` registered and logged in during beforeAll, so by the time this
     * runs the login hook has already fired.
     */
    it('proves an address over the real carrier: mailed code in, verified bit out (M14)', async () => {
      const status = (): Promise<ApiResponse> =>
        api(IDENTITY, 'GET', '/v1/auth/email/verification', { token: owner.token });
      expect(await status()).toMatchObject({ status: 200, body: { status: 'unverified' } });

      const message = await awaitSesMessage('address-verification email', {
        to: owner.email,
        bodyIncludes: 'Confirm this email address',
      });
      const body = message.Body?.text_part ?? '';
      // The approved deviation is a CODE and nothing else: no link, and the
      // same subject every other notification carries.
      expect(message.Subject).toBe('Estate — action needed');
      expect(body).not.toMatch(/https?:\/\//i);
      const code = /EV1-[0-9A-Z-]+/.exec(body)?.[0];
      if (!code) {
        throw new Error(`no verification code in the delivered message: ${body}`);
      }
      // 160 bits, measured on the live artifact — the M6/M13 lesson that the
      // width is the security parameter and is checked where it is produced.
      expect(code.replace(/^EV1-/, '').replace(/-/g, '')).toHaveLength(32);

      // A wrong code of the right shape is refused, uniformly.
      expect(
        await api(IDENTITY, 'POST', '/v1/auth/email/verification/verify', {
          token: owner.token,
          body: { code: `EV1-${'K7MN-'.repeat(8).slice(0, -1)}` },
        }),
      ).toMatchObject({ status: 400, body: { error: 'invalid_code' } });
      expect(await status()).toMatchObject({ body: { status: 'unverified' } });

      // Retyped the way a human actually retypes it — lowercase, dashes
      // dropped — because the canonical fold is the half M13 shipped missing.
      expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/email/verification/verify', {
          token: owner.token,
          body: { code: code.toLowerCase().replace(/-/g, '') },
        }),
        200,
        'verify mailed code',
      );
      expect(await status()).toMatchObject({ body: { status: 'verified' } });

      // One-shot, and a resend on a proved address says so rather than mailing.
      expect(
        await api(IDENTITY, 'POST', '/v1/auth/email/verification/verify', {
          token: owner.token,
          body: { code },
        }),
      ).toMatchObject({ status: 400, body: { error: 'invalid_code' } });
      expect(
        await api(IDENTITY, 'POST', '/v1/auth/email/verification/resend', { token: owner.token }),
      ).toMatchObject({ status: 200, body: { outcome: 'already_verified' } });

      // The send is LOGGED under its own kind — the shape M13's link claim was
      // missing, which is what let a delivered mail record itself as a failure.
      const core = new Client({ connectionString: CORE_DB });
      await core.connect();
      try {
        const { rows } = await core.query<{ outcome: string; verified: boolean }>(
          `SELECT s.outcome, (r.verified_at IS NOT NULL) AS verified
             FROM notification_sends s
             JOIN notification_recipients r ON r.user_id = s.user_id
            WHERE s.user_id = $1 AND s.kind = 'identity.address_verification'`,
          [owner.userId],
        );
        // `sent_unverified` (M14 PR2) — and it could not be anything else: the
        // code is mailed to an address that is by definition not yet proved.
        // The row is the send log's own evidence, in the store that knows.
        // The verified bit is now set, because the ceremony above just set it.
        expect(rows).toEqual([{ outcome: 'sent_unverified', verified: true }]);
        // And the code itself is nowhere in the delivery store.
        const leak = await core.query(
          `SELECT 1 FROM notification_sends WHERE user_id = $1 AND provider_message_id = $2`,
          [owner.userId, code],
        );
        expect(leak.rowCount).toBe(0);
      } finally {
        await core.end();
      }
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
        await api(DOCUMENTS, 'POST', '/v1/documents/search', {
          token: owner.token,
          body: { query: 'probe' },
        }),
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

    it('keeps the four notification surfaces on four credentials, live (M9 review, M14)', async () => {
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

      // M14 added two more surfaces on the same callee, each with its own
      // secret, and the property is n-way rather than pairwise: no credential
      // opens any route but its own. The one that matters most is that the
      // BROADLY-HELD send credential — vault, settlement and profile all hold
      // it — cannot mail a verification code, and cannot read whether an
      // address is verified. Both are identity's, and the second is the answer
      // three arming gates will act on in PR2.
      const identityVerify = stackEnv.get('IDENTITY_NOTIFICATIONS_VERIFY_INTERNAL_TOKEN');
      const identityStatus = stackEnv.get('IDENTITY_NOTIFICATIONS_STATUS_INTERNAL_TOKEN');
      if (!identityVerify || !identityStatus) {
        throw new Error('M14 notification credentials missing from the stack env');
      }
      const verificationPath = '/internal/v1/notifications/verification';
      // A code of the SHAPE identity actually mints. The M14 review tightened
      // this wire field from `/^[0-9A-Z-]+$/` (which took 64 characters of
      // readable English straight into a real message) to the shared
      // VERIFICATION_CODE_PATTERN, so a placeholder probe is now correctly
      // refused — which is the point.
      const probeCode = 'EV1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';
      const statusPath = `/internal/v1/notifications/recipients/${owner.userId}/status`;
      const surfaces = [
        {
          name: 'send',
          credential: vaultSend,
          probe: (): Promise<ApiResponse> =>
            api(NOTIFICATIONS, 'POST', sendPath, {
              headers: asService(vaultSend),
              body: { userId: owner.userId, kind: 'vault.reset', channel: 'email' },
            }),
        },
        {
          name: 'recipients',
          credential: identityRecipients,
          probe: (): Promise<ApiResponse> =>
            api(NOTIFICATIONS, 'PUT', recipientsPath, {
              headers: asService(identityRecipients),
              body: { userId: owner.userId, email: owner.email },
            }),
        },
        {
          name: 'verification',
          credential: identityVerify,
          probe: (): Promise<ApiResponse> =>
            api(NOTIFICATIONS, 'POST', verificationPath, {
              headers: asService(identityVerify),
              body: { userId: owner.userId, code: probeCode },
            }),
        },
        {
          name: 'status',
          credential: identityStatus,
          probe: (): Promise<ApiResponse> =>
            api(NOTIFICATIONS, 'GET', statusPath, { headers: asService(identityStatus) }),
        },
      ];
      // Four DISTINCT values, minted per EDGE by the generator: the provisioning
      // drift the credential graph records as unenforced is closed for
      // GENERATED environments by construction, and this is where that is
      // observed rather than assumed.
      expect(new Set(surfaces.map((s) => s.credential)).size).toBe(4);

      // Every credential on every OTHER surface: refused.
      const routes = [
        {
          path: sendPath,
          method: 'POST' as const,
          body: { userId: owner.userId, kind: 'vault.reset', channel: 'email' },
          owner: 'send',
        },
        {
          path: recipientsPath,
          method: 'PUT' as const,
          body: { userId: owner.userId, email: 'attacker@evil.test' },
          owner: 'recipients',
        },
        {
          path: verificationPath,
          method: 'POST' as const,
          body: { userId: owner.userId, code: probeCode },
          owner: 'verification',
        },
        { path: statusPath, method: 'GET' as const, body: undefined, owner: 'status' },
      ];
      for (const route of routes) {
        for (const surface of surfaces) {
          if (surface.name === route.owner) continue;
          const refused = await api(NOTIFICATIONS, route.method, route.path, {
            headers: asService(surface.credential),
            ...(route.body ? { body: route.body } : {}),
          });
          expect({ route: route.path, credential: surface.name, status: refused.status }).toEqual({
            route: route.path,
            credential: surface.name,
            status: 401,
          });
        }
      }
      // ...and each still works on its own, so the loop above is not vacuous.
      for (const surface of surfaces) {
        expect({ surface: surface.name, status: (await surface.probe()).status }).toEqual({
          surface: surface.name,
          status: 200,
        });
      }
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

      // A CONVERSATION OVER THE REAL WIRE (M11), while consent is live. The
      // gateway is the deterministic stub here — no provider credential exists
      // in this project — so what this proves is the PLATFORM half: the turn
      // route, its consent gate, the encrypted transcript, and the audit event.
      const conversation = expectStatus(
        await api(ASSISTANT, 'POST', '/v1/conversations', { token: owner.token, body: {} }),
        201,
        'start conversation',
      ) as { conversationId: string };

      const turn = expectStatus(
        await api(ASSISTANT, 'POST', `/v1/conversations/${conversation.conversationId}/turns`, {
          token: owner.token,
          body: { text: 'what should I look at first?' },
        }),
        200,
        'take a turn',
      ) as { text: string };
      expect(turn.text.length).toBeGreaterThan(0);

      // The transcript is stored ENCRYPTED and read back decrypted, so this
      // asserts the round trip rather than an echo: both turns are present, in
      // order, with the roles the service recorded.
      const transcript = expectStatus(
        await api(ASSISTANT, 'GET', `/v1/conversations/${conversation.conversationId}`, {
          token: owner.token,
        }),
        200,
        'read transcript',
      ) as { messages: { role: string; text: string }[] };
      expect(transcript.messages.map((m) => m.role)).toEqual(['user', 'assistant']);
      expect(transcript.messages[0]?.text).toBe('what should I look at first?');

      // Revoking is NOT step-up gated (the protective action must never be
      // harder than the permissive one), and it switches the routes off again.
      expectStatus(
        await api(ASSISTANT, 'DELETE', '/v1/consents/assistant.enabled', { token: owner.token }),
        200,
        'revoke consent',
      );

      // …INCLUDING THE TURN ROUTE. The M10 security review found the master
      // switch gating the analyses but not the conversation, so a revoked user
      // could still drive a provider call. Asserted live, because that is the
      // one control whose absence looked exactly like its presence.
      expect(
        (
          await api(ASSISTANT, 'POST', `/v1/conversations/${conversation.conversationId}/turns`, {
            token: owner.token,
            body: { text: 'are you still there?' },
          })
        ).status,
      ).toBe(403);
      expect(
        (await api(ASSISTANT, 'GET', '/v1/analysis/funding', { token: owner.token })).status,
      ).toBe(403);
    });

    it('runs the people surface live: step-up on a role, and a profile edit that keeps the SSN (M13)', async () => {
      // The two PR1 fixes, over real HTTP against a real Postgres.
      const contact = expectStatus(
        await api(PROFILE_URL, 'POST', '/v1/contacts', {
          token: owner.token,
          body: { name: 'Stack Probe Executor', email: 'probe-exec@example.com' },
        }),
        201,
        'create contact',
      ) as { id: string };

      // THE LIST IS A SUMMARY: one decrypted field per row, and no field at all
      // for the values a list does not render (docs/03 §6f).
      const list = expectStatus(
        await api(PROFILE_URL, 'GET', '/v1/contacts', { token: owner.token }),
        200,
        'list contacts',
      ) as Array<Record<string, unknown>>;
      const row = list.find((entry) => entry['id'] === contact.id);
      expect(row).toMatchObject({ name: 'Stack Probe Executor', hasEmail: true, linked: false });
      expect(row).not.toHaveProperty('email');

      // A profile with an SSN, set through the API — the UI deliberately has no
      // field for one in either direction.
      expectStatus(
        await api(PROFILE_URL, 'PUT', '/v1/profile', {
          token: owner.token,
          body: {
            legalName: 'Stack Probe Owner',
            ssn: '123456789',
            dob: '1950-04-02',
            stateOfResidence: 'CA',
          },
        }),
        200,
        'seed profile',
      );

      // Now the edit the people surface actually sends: the fields it holds, and
      // nothing about the SSN. Under the replace semantics this route shipped
      // with, this call NULLed ssn_ct and ssn_last4_ct.
      expectStatus(
        await api(PROFILE_URL, 'PUT', '/v1/profile', {
          token: owner.token,
          body: { legalName: 'Stack Probe Owner', stateOfResidence: 'AZ' },
        }),
        200,
        'edit profile',
      );
      const after = expectStatus(
        await api(PROFILE_URL, 'GET', '/v1/profile', { token: owner.token }),
        200,
        'read profile',
      ) as Record<string, unknown>;
      expect(after['stateOfResidence']).toBe('AZ');
      expect(after['ssnLast4']).toBe('6789'); // carried, as ciphertext
      expect(after['dob']).toBe('1950-04-02');
      // The full number is never on the wire, in either direction.
      expect(after).not.toHaveProperty('ssn');

      // Naming a fiduciary is step-up gated (docs/01 §5) — M2 shipped this route
      // with CallerGuard only. `owner` is already elevated by the beneficiary
      // test above, so a role grant is admitted while a FRESH session is not.
      const stranger = await registerAndLogin();
      expect(
        (
          await api(PROFILE_URL, 'POST', '/v1/role-assignments', {
            token: stranger.token,
            body: { contactId: contact.id, role: 'executor', scopeType: 'estate' },
          })
        ).status,
      ).toBe(403);

      const assignment = expectStatus(
        await api(PROFILE_URL, 'POST', '/v1/role-assignments', {
          token: owner.token,
          body: {
            contactId: contact.id,
            role: 'executor',
            scopeType: 'estate',
            effectiveCondition: 'on_death_verified',
          },
        }),
        201,
        'grant role',
      ) as { id: string };

      // Deleting a contact a live designation names is REFUSED, so retiring a
      // fiduciary cannot happen as a side effect of tidying an address book.
      const refusedDelete = await api(PROFILE_URL, 'DELETE', `/v1/contacts/${contact.id}`, {
        token: owner.token,
      });
      expect(refusedDelete.status).toBe(409);
      expect(refusedDelete.body).toEqual({ error: 'contact_in_use' });

      // THE LINK CEREMONY (PR3), over the live stack: the owner mints a code
      // (step-up-gated; `owner` is already elevated), a SECOND real user
      // redeems it on their own bearer, and the platform tells the owner
      // through the REAL carrier path. The code is the only selector — the
      // redeem body has no id in it anywhere.
      const minted = expectStatus(
        await api(PROFILE_URL, 'POST', `/v1/contacts/${contact.id}/link-invitation`, {
          token: owner.token,
        }),
        201,
        'mint link code',
      ) as { code: string };
      // 160 bits: ESL1- plus 32 base32 characters (the M6 fingerprint-width
      // lesson — the width IS the security parameter, so the live artifact is
      // where it gets checked).
      expect(minted.code.replace(/^ESL1-/, '').replace(/-/g, '')).toHaveLength(32);

      const redeemer = await registerAndLogin();
      expectStatus(
        await api(PROFILE_URL, 'POST', '/v1/contact-links/redeem', {
          token: redeemer.token,
          body: { code: minted.code },
        }),
        200,
        'redeem link code',
      );
      // One-shot: the same code answers the uniform refusal now.
      const replay = await api(PROFILE_URL, 'POST', '/v1/contact-links/redeem', {
        token: redeemer.token,
        body: { code: minted.code },
      });
      expect(replay.status).toBe(400);
      expect(replay.body).toEqual({ error: 'invalid_code' });
      // The list shows the link — the fact that decides whether designations work.
      const linkedList = expectStatus(
        await api(PROFILE_URL, 'GET', '/v1/contacts', { token: owner.token }),
        200,
        'list after link',
      ) as Array<{ id: string; linked: boolean }>;
      expect(linkedList.find((entry) => entry.id === contact.id)).toMatchObject({ linked: true });

      // AND THE OWNER WAS ACTUALLY TOLD. The comment above claimed the real
      // carrier path from the day this test was written, and it was false:
      // `notification_sends`'s kind CHECK still listed the nine M9 kinds, so
      // the mail went out and the row that records it threw, which made
      // profile record `ownerNotified: 'failed'` about an owner who HAD been
      // warned (migration 002). Nothing noticed, because the audit event this
      // suite already polls for looks identical either way. The send LOG is
      // the artifact that distinguishes them, so it is what gets asserted.
      const core = new Client({ connectionString: CORE_DB });
      await core.connect();
      try {
        await pollUntil('link-claimed notification recorded', async () => {
          const { rows } = await core.query<{ outcome: string }>(
            `SELECT outcome FROM notification_sends
              WHERE user_id = $1 AND kind = 'contact.link_claimed'`,
            [owner.userId],
          );
          // `sent`, not `sent_unverified` — and that is the OTHER half of the
          // M14 PR2 pair. This owner proved their address in the ceremony test
          // earlier in this journey, so the same code path that recorded
          // `sent_unverified` for the verification mail records `sent` here.
          // Without the pair, one token would just be a constant.
          return rows[0]?.outcome === 'sent' ? true : null;
        });
      } finally {
        await core.end();
      }

      // Grants can now be read AND withdrawn — M2 shipped only the write.
      const grant = expectStatus(
        await api(PROFILE_URL, 'POST', `/v1/role-assignments/${assignment.id}/permissions`, {
          token: owner.token,
          body: { resource: 'contact', action: 'read' },
        }),
        201,
        'grant permission',
      ) as { id: string };
      expect(
        (
          (await api(PROFILE_URL, 'GET', `/v1/role-assignments/${assignment.id}/permissions`, {
            token: owner.token,
          })) as { body: unknown }
        ).body,
      ).toEqual([expect.objectContaining({ id: grant.id, resource: 'contact', action: 'read' })]);
      expect(
        (
          await api(
            PROFILE_URL,
            'DELETE',
            `/v1/role-assignments/${assignment.id}/permissions/${grant.id}`,
            { token: owner.token },
          )
        ).status,
      ).toBe(204);
      expect(
        (await api(PROFILE_URL, 'GET', `/v1/role-assignments/${assignment.id}/permissions`, {
          token: owner.token,
        })) as { body: unknown },
      ).toMatchObject({ body: [] });
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
          // M11: a real turn crossed the platform and was recorded.
          'assistant.turn.completed',
          // M13: the withdrawal half of a permission grant, which M2 shipped
          // without — an owner could widen a role-holder's reach and never
          // narrow it, and nothing recorded the narrowing when they could.
          'permission.revoked',
          // M13 PR3: the claim, audited with the REDEEMER as actor.
          'contact.link.claimed',
          // M14: the owner proved they receive mail at the address on file.
          // Two events, from two services, for one act — identity records the
          // ceremony, notifications records that the delivery store now
          // vouches for the address. Both crossed the real broker.
          'auth.email_verification.verified',
          'notification.recipient.verified',
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

  /**
   * THE CROSS-ORIGIN HANDOFF (M15), end to end on the real deployment.
   *
   * OUTSIDE the profile split, unlike plaid and the assistant: the vault origin
   * runs in BOTH profiles because nothing about it needs a third-party
   * credential, so both should exercise it. The production rehearsal is in fact
   * where the shipped-image assertions matter most.
   *
   * These are the properties the milestone exists for, and every one of them
   * is about what a leaked credential is WORTH rather than about a happy
   * path. They were each measured by hand against this stack before being
   * written down here.
   */
  describe('the isolated vault origin', () => {
    it('serves the shell under a CSP with no unsafe-* and enforced Trusted Types', async () => {
      const response = await fetch(`${VAULT_WEB}/`);
      expect(response.status).toBe(200);
      const csp = response.headers.get('content-security-policy') ?? '';
      // The two directives the main app cannot honestly claim (M11), and the
      // reason this origin is framework-free.
      expect(csp).toContain("script-src 'self'");
      expect(csp).toContain("require-trusted-types-for 'script'");
      expect(csp).toContain("trusted-types 'none'");
      expect(csp).not.toContain('unsafe-inline');
      expect(csp).not.toContain('unsafe-eval');
      // Nothing may frame it, and no other origin may load from it.
      expect(csp).toContain("frame-ancestors 'none'");
      expect(response.headers.get('cross-origin-resource-policy')).toBe('same-origin');
    });

    it('actually SERVES its client bundle from the shipped image', async () => {
      /*
       * The 2026-08-06 web.Dockerfile lesson, applied before it can recur.
       * That image lost its vendored typeface for several milestones because
       * `output: 'standalone'` excludes `public/`, and nothing noticed: the
       * container booted, the page rendered, and only a 404 on an asset gave
       * it away. This origin's client is ALSO build output under `public/`
       * (tsconfig.client.json emits there, and it is gitignored), so its
       * absence would look identical — a shell that loads and a page that
       * never renders.
       *
       * Liveness is not the check. Fetching the module is.
       */
      const module = await fetch(`${VAULT_WEB}/app/main.js`);
      expect(module.status).toBe(200);
      expect(module.headers.get('content-type')).toContain('javascript');
      const body = await module.text();
      expect(body).toContain('render');

      // The generated config module, which is the one piece of JS this origin
      // produces at runtime rather than at build time.
      const config = await fetch(`${VAULT_WEB}/app/config.js`);
      expect(config.status).toBe(200);
      expect(await config.text()).toContain('ESTATE_APP_ORIGIN');
    });

    it('refuses an arrival POST from any origin but the app', async () => {
      const response = await fetch(`${VAULT_WEB}/open`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: 'http://attacker.example',
        },
        body: 'code=stolen',
      });
      expect(response.status).toBe(403);
    });

    it('mints, redeems, and yields a session worth ONLY the vault', async () => {
      const session = await registerAndLogin();
      await stepUp(session);

      const minted = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff', { token: session.token }),
        201,
        'mint handoff',
      ) as { code: string; expiresAt: string };
      expect(minted.code.length).toBeGreaterThan(20);

      const redeemed = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff/redeem', { body: { code: minted.code } }),
        200,
        'redeem handoff',
      ) as Record<string, unknown>;
      // NO REFRESH TOKEN. The session lives 15 minutes and cannot be
      // extended, because no credential capable of extending it was ever
      // issued — `refresh_token_h` holds the digest of a value dropped on the
      // floor at mint.
      expect(Object.keys(redeemed).sort()).toEqual(
        ['accessToken', 'expiresAt', 'sessionId', 'userId'].sort(),
      );
      const vaultToken = redeemed['accessToken'] as string;

      // THE BOUNDARY. The vault service admits it…
      expect((await api(VAULT, 'GET', '/v1/vault/keyset', { token: vaultToken })).status).toBe(200);
      // …and every other service refuses it, without any of them having
      // changed a line: `CallerGuard` admits `account` alone unless a service
      // opts in, and only vault does (AUDIENCE_ADMITTERS).
      for (const [name, base, path] of [
        ['assets', ASSETS, '/v1/assets'],
        ['documents', DOCUMENTS, '/v1/documents'],
        ['profile', PROFILE_URL, '/v1/profile'],
      ] as const) {
        const refused = await api(base, 'GET', path, { token: vaultToken });
        expect(`${name}:${refused.status}`).toBe(`${name}:401`);
      }

      // Identity's own surface is per ROUTE, because introspection must admit
      // every audience or the origin cannot exist at all.
      expect((await api(IDENTITY, 'GET', '/v1/auth/session', { token: vaultToken })).status).toBe(
        200,
      );
      expect(
        (await api(IDENTITY, 'POST', '/v1/auth/totp/enroll', { token: vaultToken })).status,
      ).toBe(401);
      // THE ONE THAT MATTERS MOST: a vault session cannot mint another
      // handoff, so a leaked one cannot chain itself forward.
      expect((await api(IDENTITY, 'POST', '/v1/auth/handoff', { token: vaultToken })).status).toBe(
        401,
      );
    });

    it('burns the code on the ATTEMPT, and answers every failure identically', async () => {
      const session = await registerAndLogin();
      await stepUp(session);
      const minted = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff', { token: session.token }),
        201,
        'mint handoff',
      ) as { code: string };

      expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff/redeem', { body: { code: minted.code } }),
        200,
        'first redemption',
      );
      const replay = await api(IDENTITY, 'POST', '/v1/auth/handoff/redeem', {
        body: { code: minted.code },
      });
      const unknown = await api(IDENTITY, 'POST', '/v1/auth/handoff/redeem', {
        body: { code: 'never-minted-code' },
      });
      // Spent and unknown are INDISTINGUISHABLE — status and body — because
      // telling them apart says a guess named something real (docs/03 §6g).
      expect(replay.status).toBe(401);
      expect(unknown.status).toBe(401);
      expect(replay.body).toEqual(unknown.body);
      expect(replay.body).toEqual({ error: 'invalid_code' });
    });

    it('records the ceremony without recording which refusal fired', async () => {
      const db = new Client({ connectionString: AUDIT_DB });
      await db.connect();
      try {
        const rows = await pollUntil('handoff audit events', async () => {
          const found = await db.query<{
            action: string;
            actor_id: string | null;
            detail: unknown;
          }>(
            `SELECT action, actor_id, detail FROM audit_events
              WHERE action LIKE 'auth.handoff%'`,
          );
          const actions = new Set(found.rows.map((r) => r.action));
          return actions.has('auth.handoff.minted') &&
            actions.has('auth.handoff.redeemed') &&
            actions.has('auth.handoff.failed')
            ? found.rows
            : null;
        });

        // A refusal carries NO actor and NO reason: an audit trail that named
        // which of unknown/expired/spent/raced applied would re-create through
        // the stream the oracle the uniform wire answer removes (M14 PR1).
        for (const row of rows.filter((r) => r.action === 'auth.handoff.failed')) {
          expect(row.actor_id).toBeNull();
          expect(row.detail ?? {}).toEqual({});
        }
        // A successful mint DOES carry the audience, which is the fact an
        // owner reviewing their trail needs.
        const minted = rows.find((r) => r.action === 'auth.handoff.minted');
        expect(minted?.detail).toMatchObject({ audience: 'vault' });
      } finally {
        await db.end();
      }
    });

    /**
     * THE ONE ZONE B READ ON THIS ORIGIN (M15 PR3).
     *
     * Emergency access needs contact NAMES so an owner can pick grantees and
     * confirm each one's key fingerprint out of band. Contact names therefore
     * cross onto the vault origin — and nothing else does, which is a claim
     * about a live edge talking to a live profile service and so belongs here
     * rather than only in a unit test against a scripted transport.
     */
    it('serves grantee candidates as a PROJECTION, and nothing else profile said', async () => {
      const owner = await registerAndLogin();
      // Minting a link code is an M14 ARMING action, so in the production
      // rehearsal it refuses an owner nobody proved. Driving the real ceremony
      // is what lets this test run in BOTH profiles rather than being a
      // development-only assertion about a Zone A boundary.
      await proveAddress(owner);
      await stepUp(owner);

      // Two contacts: one that could hold a recovery key and one that cannot.
      const linked = expectStatus(
        await api(PROFILE_URL, 'POST', '/v1/contacts', {
          token: owner.token,
          body: {
            name: 'Ada Grantee',
            email: 'ada@example.com',
            phone: '555-0111',
            relationship: 'sibling',
            notes: 'has the spare keys',
          },
        }),
        201,
        'create linked-to-be contact',
      ) as { id: string };
      expectStatus(
        await api(PROFILE_URL, 'POST', '/v1/contacts', {
          token: owner.token,
          body: { name: 'Unlinked Ursula', relationship: 'friend' },
        }),
        201,
        'create unlinked contact',
      );

      // Link the first through M13's real ceremony: the owner mints a code
      // under step-up and the contact redeems it on their OWN account. No raw
      // SQL — the link is the authorization edge behind docs/03 §6b.
      const contact = await registerAndLogin();
      const invite = expectStatus(
        await api(PROFILE_URL, 'POST', `/v1/contacts/${linked.id}/link-invitation`, {
          token: owner.token,
        }),
        201,
        'mint link code',
      ) as { code: string };
      expectStatus(
        await api(PROFILE_URL, 'POST', '/v1/contact-links/redeem', {
          token: contact.token,
          body: { code: invite.code },
        }),
        200,
        'redeem link code',
      );

      // Cross to the vault origin the way a browser does.
      const minted = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff', { token: owner.token }),
        201,
        'mint handoff',
      ) as { code: string };
      const arrival = await fetch(`${VAULT_WEB}/open`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: APP_ORIGIN_FOR_VAULT,
        },
        body: `code=${encodeURIComponent(minted.code)}`,
      });
      expect(arrival.status).toBe(303);
      const cookie = (arrival.headers.get('set-cookie') ?? '').split(';')[0] as string;
      expect(cookie).toContain('__Host-estate_vault=');

      const candidates = await fetch(`${VAULT_WEB}/api/grantee-candidates`, {
        headers: { cookie, 'x-estate-vault-csrf': '1' },
      });
      expect(candidates.status).toBe(200);
      const text = await candidates.text();
      const payload = JSON.parse(text) as {
        candidates: Array<{ contactId: string; userId: string; name: string }>;
      };

      // The linked contact, with the account id a share is sealed to.
      expect(payload.candidates).toHaveLength(1);
      expect(payload.candidates[0]).toEqual({
        contactId: linked.id,
        userId: contact.userId,
        name: 'Ada Grantee',
      });
      // AND NOTHING ELSE. Profile's summary carries relationship, professional
      // kind and four has* flags; a grantee picker needs a name and an id, so
      // the rest stays in Zone B. An unlinked contact does not cross at all —
      // it has no account, so it could never hold a recovery key.
      expect(text).not.toContain('sibling');
      expect(text).not.toContain('hasNotes');
      expect(text).not.toContain('Ursula');
      expect(text).not.toContain('ada@example.com');
      expect(text).not.toContain('555-0111');

      /*
       * AND THE BOUNDARY ITSELF, measured against profile DIRECTLY rather than
       * through the edge — because the edge's allowlist is not the control
       * here. A leaked vault handoff would be presented straight at profile,
       * so what matters is that profile refuses every route but this one.
       *
       * This is what a service-wide widening would have cost: the owner's PII,
       * every contact's decrypted detail, the family tree and the roles. The
       * per-route grant is the difference, and it is only a real difference if
       * the neighbours still say 401.
       */
      const redeemed = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff/redeem', {
          body: {
            code: (
              expectStatus(
                await api(IDENTITY, 'POST', '/v1/auth/handoff', { token: owner.token }),
                201,
                'mint second handoff',
              ) as { code: string }
            ).code,
          },
        }),
        200,
        'redeem second handoff',
      ) as { accessToken: string };
      const vaultToken = redeemed.accessToken;

      expect(
        (await api(PROFILE_URL, 'GET', '/v1/contacts/grantee-candidates', { token: vaultToken }))
          .status,
      ).toBe(200);
      for (const path of [
        '/v1/contacts',
        `/v1/contacts/${linked.id}`,
        '/v1/profile',
        '/v1/profile/family',
        '/v1/role-assignments',
      ]) {
        const refused = await api(PROFILE_URL, 'GET', path, { token: vaultToken });
        expect(`${path}:${refused.status}`).toBe(`${path}:401`);
      }
    });
  });

  /**
   * THE ISOLATED OPERATOR ORIGIN (M21 PR3a), end to end on the real deployment.
   *
   * OUTSIDE the profile split for the vault origin's reason: nothing here needs
   * a third-party credential, so both profiles should exercise it.
   *
   * WHAT THIS MILESTONE SHIPS IS A BOUNDARY AND NOTHING BEHIND IT, and these
   * assertions are chosen to say exactly that. A redeemed operator session is
   * admitted by identity's three per-route widenings and refused EVERYWHERE
   * ELSE — including by settlement, whose operator queue is the surface PR3b
   * will put here. So the ceremony is real, the origin is real, and reaching it
   * still confers nothing: the operator allowlist M21 PR1 gave a ceremony and
   * M21 PR2 gave one gate is what decides authority, and it is not consulted
   * here at all.
   */
  describe('the isolated operator origin', () => {
    it("serves the shell under a CSP at least as strict as the vault origin's", async () => {
      /*
       * THIS TEST IS NAMED FOR A COMPARISON, SO IT MAKES ONE. Its first version
       * asserted a list of fixed strings and carried a comment claiming this
       * origin was "stricter than the vault's" in `img-src` — which measurement
       * refuted: the two policies are byte-identical, twelve directives each.
       * The name promised a relation and the body checked a constant, which is
       * the shape this repo keeps finding (a test named for a property it never
       * touched), with the added harm that the false half had been copied into
       * docs/03 and docs/04 before anybody compared the two headers. (An
       * earlier draft of this comment said the PR body carried it too; it did
       * not — the claim lived in exactly these three places, and overstating
       * its spread was the same defect one layer up.)
       *
       * What is worth gating is the RELATION rather than either constant: a
       * second isolated origin must never drift WEAKER than the first, and the
       * realistic regression is somebody relaxing this one for a charting
       * library on an operator console. So both live headers are fetched and
       * compared directive by directive — for these allowlist-shaped policies,
       * "no weaker" means: omit nothing the vault names, and for each directive
       * allow no source the vault does not.
       */
      const [operator, vault] = await Promise.all([
        fetch(`${OPERATOR_WEB}/`),
        fetch(`${VAULT_WEB}/`),
      ]);
      expect(operator.status).toBe(200);
      expect(vault.status).toBe(200);
      const csp = operator.headers.get('content-security-policy') ?? '';

      const directives = (policy: string): Map<string, Set<string>> => {
        const parsed = new Map<string, Set<string>>();
        for (const part of policy.split(';')) {
          const [name, ...sources] = part.trim().split(/\s+/);
          if (name) parsed.set(name, new Set(sources));
        }
        return parsed;
      };
      const here = directives(csp);
      const there = directives(vault.headers.get('content-security-policy') ?? '');
      // Anti-vacuity: two empty maps compare equal perfectly.
      expect(there.size).toBeGreaterThanOrEqual(10);
      for (const [name, allowed] of there) {
        const ours = here.get(name);
        expect(ours).toBeDefined();
        for (const source of ours ?? []) {
          expect([...allowed]).toContain(source);
        }
      }

      // And the absolutes this origin owes on its own account, whatever the
      // vault does — the two directives the main app cannot honestly claim
      // (M11), and the reason this origin is framework-free.
      expect(csp).toContain("script-src 'self'");
      expect(csp).toContain("require-trusted-types-for 'script'");
      expect(csp).toContain("trusted-types 'none'");
      expect(csp).not.toContain('unsafe-inline');
      expect(csp).not.toContain('unsafe-eval');
      expect(csp).toContain("frame-ancestors 'none'");
      // No `data:` in `img-src` — stricter than the MAIN APP, which needs it
      // for M12's document viewer. The vault origin does not allow it either;
      // what is distinctive here is only the contrast with the app.
      expect(csp).toContain("img-src 'self'");
      expect(csp).not.toContain('data:');
      expect(operator.headers.get('cross-origin-resource-policy')).toBe('same-origin');
    });

    it('actually SERVES its client bundle from the shipped image', async () => {
      // The 2026-08-06 web.Dockerfile lesson again: this client is build output
      // under `public/` and gitignored, so its absence is a shell that loads
      // and a page that never renders. Liveness is not the check.
      const module = await fetch(`${OPERATOR_WEB}/app/main.js`);
      expect(module.status).toBe(200);
      expect(module.headers.get('content-type')).toContain('javascript');
      expect(await module.text()).toContain('render');

      const config = await fetch(`${OPERATOR_WEB}/app/config.js`);
      expect(config.status).toBe(200);
      expect(await config.text()).toContain('ESTATE_APP_ORIGIN');
    });

    it('refuses an arrival POST from any origin but the app', async () => {
      const response = await fetch(`${OPERATOR_WEB}/open`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: 'http://attacker.example',
        },
        body: 'code=stolen',
      });
      expect(response.status).toBe(403);
    });

    it("mints, redeems, and yields a session worth NOTHING but identity's three routes", async () => {
      const session = await registerAndLogin();
      await stepUp(session);

      // THE MINT IS ROLE-BLIND, and this probe user is not an operator. That
      // is the design: identity holds no settlement credential and there is no
      // dblink between the auth and core clusters, so it cannot ask. What
      // stands between this session and an operator action is the allowlist,
      // consulted by settlement — which is why every settlement probe below
      // must refuse.
      const minted = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff/operator', { token: session.token }),
        201,
        'mint operator handoff',
      ) as { code: string; expiresAt: string };
      expect(minted.code.length).toBeGreaterThan(20);

      const redeemed = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff/redeem', { body: { code: minted.code } }),
        200,
        'redeem operator handoff',
      ) as Record<string, unknown>;
      // REDEMPTION IS AUDIENCE-BLIND: one route, one response shape, and the
      // audience travels on the `auth_handoffs` row rather than on the wire.
      // No refresh token here either.
      expect(Object.keys(redeemed).sort()).toEqual(
        ['accessToken', 'expiresAt', 'sessionId', 'userId'].sort(),
      );
      const operatorToken = redeemed['accessToken'] as string;

      // Identity's per-route widenings: introspection, step-up, logout.
      expect(
        (await api(IDENTITY, 'GET', '/v1/auth/session', { token: operatorToken })).status,
      ).toBe(200);
      // …and the session says what it is, which is what lets the browser
      // client display the audience rather than the edge re-deriving it.
      expect(
        (
          (await api(IDENTITY, 'GET', '/v1/auth/session', { token: operatorToken })).body as Record<
            string,
            unknown
          >
        )['audience'],
      ).toBe('operator');

      // EVERY SERVICE REFUSES IT, without any of them having changed a line —
      // `AUDIENCE_ADMITTERS.operator` is empty, so `CallerGuard` admits
      // `account` alone. SETTLEMENT IS THE ONE THAT MATTERS: its operator queue
      // is the surface PR3b puts on this origin, and today the boundary exists
      // with nothing behind it.
      for (const [name, base, path] of [
        ['settlement-queue', SETTLEMENT, '/v1/settlement/queue'],
        ['settlement-cases', SETTLEMENT, '/v1/settlement/cases'],
        ['vault', VAULT, '/v1/vault/keyset'],
        ['assets', ASSETS, '/v1/assets'],
        ['documents', DOCUMENTS, '/v1/documents'],
        ['profile', PROFILE_URL, '/v1/profile'],
      ] as const) {
        const refused = await api(base, 'GET', path, { token: operatorToken });
        expect(`${name}:${refused.status}`).toBe(`${name}:401`);
      }

      // AND IT CANNOT CHAIN ITSELF FORWARD, in either direction: neither mint
      // route admits a non-account audience, so a leaked operator code cannot
      // become a vault session and cannot mint a second operator one.
      expect(
        (await api(IDENTITY, 'POST', '/v1/auth/handoff', { token: operatorToken })).status,
      ).toBe(401);
      expect(
        (await api(IDENTITY, 'POST', '/v1/auth/handoff/operator', { token: operatorToken })).status,
      ).toBe(401);
      // Nor enrol a factor of its own (the M17 PR6 escalation, refused here by
      // audience before `SecondFactorGate` is even reached).
      expect(
        (await api(IDENTITY, 'POST', '/v1/auth/totp/enroll', { token: operatorToken })).status,
      ).toBe(401);
    });

    it('crosses the origin the way a browser does, and sets a __Host- cookie of its own', async () => {
      const session = await registerAndLogin();
      await stepUp(session);
      const minted = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff/operator', { token: session.token }),
        201,
        'mint operator handoff',
      ) as { code: string };

      const arrival = await fetch(`${OPERATOR_WEB}/open`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: APP_ORIGIN_FOR_VAULT,
        },
        body: `code=${encodeURIComponent(minted.code)}`,
      });
      expect(arrival.status).toBe(303);
      const setCookie = arrival.headers.get('set-cookie') ?? '';
      // A DIFFERENT COOKIE NAME FROM THE VAULT'S, which is what keeps the two
      // origins' sessions apart even though both carry the `__Host-` prefix.
      expect(setCookie).toContain('__Host-estate_operator=');
      expect(setCookie).not.toContain('estate_vault');
      expect(setCookie).toContain('HttpOnly');
      expect(setCookie).toContain('Secure');
      const cookie = setCookie.split(';')[0] as string;

      // The edge proxies identity on that cookie, and REQUIRES the custom
      // header — the CSRF control, which works because this edge answers no
      // preflight, so no cross-site page can set it.
      const withHeader = await fetch(`${OPERATOR_WEB}/api/auth/session`, {
        headers: { cookie, 'x-estate-operator-csrf': '1' },
      });
      expect(withHeader.status).toBe(200);
      expect(((await withHeader.json()) as Record<string, unknown>)['audience']).toBe('operator');

      const withoutHeader = await fetch(`${OPERATOR_WEB}/api/auth/session`, {
        headers: { cookie },
      });
      expect(withoutHeader.status).toBe(403);

      // AND THE VAULT ORIGIN'S COOKIE BUYS NOTHING HERE. Two hosts, two
      // cookies, and neither is sent to the other by the browser — this is the
      // server-side half of that, which holds even for a caller that sets the
      // header by hand.
      const foreign = await fetch(`${OPERATOR_WEB}/api/auth/session`, {
        headers: {
          cookie: `__Host-estate_vault=${cookie.split('=')[1] as string}`,
          'x-estate-operator-csrf': '1',
        },
      });
      expect(foreign.status).toBe(401);

      // The proxy is an exact-match ALLOWLIST, not a prefix rewrite — a proxy
      // forwarding whatever path it is handed, carrying a live bearer, is an
      // SSRF primitive.
      for (const path of [
        '/api/auth/handoff',
        '/api/auth/logout/refresh',
        '/api/auth/totp/enroll',
        '/api/settlement/queue',
      ]) {
        const refused = await fetch(`${OPERATOR_WEB}${path}`, {
          method: 'POST',
          headers: { cookie, 'x-estate-operator-csrf': '1' },
        });
        expect(`${path}:${refused.status}`).toBe(`${path}:404`);
      }
    });

    it('records the mint with its audience, and a refusal with neither actor nor reason', async () => {
      const session = await registerAndLogin();
      await stepUp(session);
      expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff/operator', { token: session.token }),
        201,
        'mint operator handoff',
      );
      expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/handoff/redeem', {
          body: { code: 'never-minted-operator-code' },
        }),
        401,
        'unknown code',
      );

      const db = new Client({ connectionString: AUDIT_DB });
      await db.connect();
      try {
        const minted = await pollUntil('operator handoff mint event', async () => {
          const found = await db.query<{ detail: Record<string, unknown> }>(
            `SELECT detail FROM audit_events
              WHERE action = 'auth.handoff.minted' AND detail->>'audience' = 'operator'`,
          );
          return found.rows.length > 0 ? found.rows : null;
        });
        expect(minted[0]?.detail).toMatchObject({ audience: 'operator' });

        // The refusal is still ONE answer in the trail as well as on the wire:
        // an event naming which of unknown/expired/spent/raced fired would
        // re-create the oracle the uniform reply removes.
        const failed = await db.query<{ actor_id: string | null; detail: unknown }>(
          `SELECT actor_id, detail FROM audit_events WHERE action = 'auth.handoff.failed'`,
        );
        for (const row of failed.rows) {
          expect(row.actor_id).toBeNull();
          expect(row.detail ?? {}).toEqual({});
        }
      } finally {
        await db.end();
      }
    });
  });

  describeDev('the decrypt-rate baseline (M18)', () => {
    it('fires on a deliberate burst and NEVER on the journey', async () => {
      // TWO claims in one test, and the pairing is the design. A bare
      // "zero anomaly events after the journey" assertion is vacuously green
      // over a DEAD detector (the M8 dead-consumer shape — the gate this
      // repo's own doctrine forbids), so the test first proves the deployed
      // detector fires: a deliberate burst one past the smallest bound, then
      // a poll for the anomaly it must emit. That poll also gives the
      // false-positive half its ordering: a tick has demonstrably run against
      // a window that includes this burst, and the journey's traffic sits in
      // the same 300s window whenever the journey finished within it — which
      // is the ordinary case (the whole dev suite runs in ~100s) but is NOT
      // guaranteed on a degraded runner, so this gate is a strong check on
      // journey traffic rather than a proof about it (M18 review; docs/03
      // §6q records the bound). Then the assertion: every anomaly since this
      // suite started is this burst's own, by bound AND by principal.
      //
      // The burst rides mfa_methods_user because it is the cheapest bound to
      // reach honestly, NOT because it is the smallest (users_user and
      // doc_operator are 60 against its 100 — the M18 review corrected an
      // earlier comment claiming otherwise): identity's TOTP validation has
      // no replay ledger, so repeated step-ups with the current code are
      // cheap, fast, and side-effect-free beyond the ledger rows they
      // legitimately write (step-up SUCCESSES are uncounted by the M16 cap,
      // and no settlement case exists for a fresh probe user). The two
      // smaller bounds are unreachable without either an email-change
      // ceremony per decrypt or a settlement operator.
      const bound = boundFor('mfa_methods', 'user').maxPerWindow;
      const probe = await registerAndLogin();
      const enroll = expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/totp/enroll', { token: probe.token }),
        201,
        'burst totp enroll',
      ) as { otpauthUri: string };
      const secret = new URL(enroll.otpauthUri).searchParams.get('secret');
      if (!secret) {
        throw new Error('totp enroll returned no secret');
      }
      expectStatus(
        await api(IDENTITY, 'POST', '/v1/auth/totp/verify', {
          token: probe.token,
          body: { code: currentTotpCode(secret) },
        }),
        200,
        'burst totp verify',
      );
      for (let i = 0; i < bound + 1; i++) {
        expectStatus(
          await api(IDENTITY, 'POST', '/v1/auth/stepup', {
            token: probe.token,
            body: { code: currentTotpCode(secret) },
          }),
          200,
          `burst stepup ${i}`,
        );
      }

      const db = new Client({ connectionString: AUDIT_DB });
      await db.connect();
      try {
        const hit = await pollUntil(
          'decrypt-rate anomaly for the burst principal',
          async () => {
            const { rows } = await db.query<{ detail: Record<string, unknown> }>(
              `SELECT detail FROM audit_events
                WHERE action = 'crypto.decrypt_rate.exceeded' AND resource_id = $1
                LIMIT 1`,
              [probe.userId],
            );
            return rows.length > 0 ? (rows[0] ?? null) : null;
          },
          150_000,
          2_000,
        );
        expect(hit.detail['boundName']).toBe('mfa_methods_user');
        expect(hit.detail['principal']).toBe('user');

        // The false-positive gate: nothing the journey did — contacts,
        // profile, documents, assets, sends, rebuild-free reads — ever
        // produced an anomaly. Every anomaly SINCE THIS SUITE STARTED must be
        // this test's own burst, identified by its PRINCIPAL and not merely by
        // its bound name: every journey user drives the same
        // (mfa_methods x user) class through stepUp(), so a boundName-only
        // assertion would wave through a regression that made ordinary
        // step-ups breach — the exact false positive this gate exists to
        // catch (M18 review). Time-scoped for the mirror reason: the store is
        // append-only and a designed alarm (a projection rebuild) would
        // otherwise red every later run against the same stack forever.
        const { rows: all } = await db.query<{
          detail: Record<string, unknown>;
          resource_id: string | null;
        }>(
          `SELECT detail, resource_id FROM audit_events
            WHERE action = 'crypto.decrypt_rate.exceeded' AND occurred_at >= $1`,
          [SUITE_START],
        );
        expect(all.length).toBeGreaterThanOrEqual(1);
        for (const row of all) {
          expect({ bound: row.detail['boundName'], principal: row.resource_id }).toEqual({
            bound: 'mfa_methods_user',
            principal: probe.userId,
          });
        }
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
      const message = await awaitSesMessage('the case_opened email in LocalStack SES', {
        to: decedent.email,
        // M14: this address also receives a verification code at first login,
        // so the body is what names WHICH message this assertion is about.
        bodyIncludes: 'A report was filed',
      });
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
      // M14, THE ARMING GATE, live and both ways round. An escrow is what a
      // grantee later starts the §5.2 clock against, and the owner's only way
      // to interrupt that clock is a notification — so before M14 this could
      // arm while the alert went to an address nobody had ever confirmed. It
      // refuses now, with its own token, distinct from the adapter refusal.
      const beforeProof = await api(VAULT, 'POST', '/v1/vault/emergency-access', {
        token: owner.token,
        body: configureBody(),
      });
      expect(beforeProof.status).toBe(503);
      expect(beforeProof.body).toEqual({ error: 'recipient_unverified' });

      // Prove the address through the real ceremony — a code read out of a
      // real SES message — and the same request is admitted. Without this half
      // the refusal above would pass just as well against a gate that refuses
      // everything.
      await proveAddress(owner);
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
      const message = await awaitSesMessage('the grantees_changed email in LocalStack SES', {
        to: owner.email,
        bodyIncludes: 'emergency contacts',
      });
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
