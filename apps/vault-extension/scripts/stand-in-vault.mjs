/**
 * A STAND-IN VAULT, spoken well enough for the real extension to open one.
 *
 * `test/vault-host.spec.ts` has driven a genuine SRP-6a exchange in-process
 * since PR2b, against the server half `@estate/vault-crypto` also ships. What
 * it cannot do is run in a browser: jsdom has no `Worker`, no `chrome`, no
 * extension origin and no offscreen document, so every claim about those rests
 * on a hand-written API double. This serves the same protocol over real HTTP so
 * the browser smoke test can drive the SHIPPED artifact end to end.
 *
 * IT IS NOT A MOCK OF THE VAULT SERVICE. The exchange is real: a real
 * enrollment, a real verifier, a real server ephemeral, and a real check of the
 * client's proof. A client that got the maths wrong fails here exactly as it
 * would against the service. What it does NOT implement is everything the real
 * service is actually for — sessions, audiences, step-up, guards, audit,
 * persistence — because none of that is what a browser run is placed to prove.
 * The service's own suites cover it, and PR2a proved the transport live at the
 * edge.
 *
 * WHY IT RECORDS EVERY REQUEST. The extension's central claim is that nothing
 * derived from the vault password or the Secret Key leaves the device.
 * `vault-host.spec.ts` asserts that against a recording transport in Node; this
 * lets the same assertion be made about bytes that crossed a real socket out of
 * a real browser, which is a materially stronger statement about the same
 * property.
 *
 * Prints one JSON line of state to stdout on `--emit`, so the harness can read
 * the Secret Key it must type and the requests it must inspect.
 */
import { createServer } from 'node:http';
import {
  createServerEphemeral,
  createVaultEnrollment,
  decodeGroupElement,
  encodeGroupElement,
  encryptItem,
  fromBase64,
  toBase64,
  verifyClientSession,
} from '@estate/vault-crypto';

const PORT = Number(process.env.VAULT_PORT ?? 3010);
const USER_ID = process.env.VAULT_USER ?? '11111111-2222-4333-8444-555555555555';
const PASSWORD = process.env.VAULT_PASSWORD ?? 'a vault password nobody else knows';
/** The plaintext that must never appear on the wire. */
const ITEM_SECRET = process.env.VAULT_ITEM_SECRET ?? 'the-item-secret-that-must-not-leak';
const ITEM_TITLE = 'Bank login';

const { enrollment, masterKey } = await createVaultEnrollment({
  userId: USER_ID,
  password: PASSWORD,
});
const keyset = enrollment.payload;
const verifier = decodeGroupElement(keyset.srpVerifier, 'verifier');

const ITEM_ID = '05555555-0000-4000-8000-000000000000';
const rows = [
  {
    id: ITEM_ID,
    itemType: 'password',
    blob: toBase64(
      await encryptItem(
        masterKey,
        { userId: USER_ID, itemId: ITEM_ID, blobVersion: 1 },
        new TextEncoder().encode(
          JSON.stringify({
            title: ITEM_TITLE,
            username: 'someone@example.test',
            secret: ITEM_SECRET,
            url: 'https://bank.test/login',
          }),
        ),
      ),
    ),
    blobVersion: 1,
    updatedAt: '2026-08-12T00:00:00Z',
  },
];

/** Every request, verbatim, for the egress assertion. */
const seen = [];
let ephemeral = null;

const read = (req) =>
  new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => resolve(body));
  });

/** Flipped by `/__expire`: `smoke-access` ages out, `smoke-access-2` replaces it. */
let expired = false;

const server = createServer(async (req, res) => {
  const body = await read(req);
  seen.push({ url: req.url, method: req.method, headers: req.headers, body });
  const json = (status, payload) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payload));
  };

  // THE HARNESS'S OWN INTROSPECTION ROUTE, exempt and deliberately checked
  // FIRST. It was behind the CSRF check on the first run, so it answered 403
  // and the egress assertion searched an error object for secrets and found
  // none — a vacuous pass on the single most important claim in the file. The
  // anti-vacuity check caught it, which is the whole reason that check exists.
  if (req.url === '/__requests') return json(200, seen);

  // The edge requires it on every `/api/` route; asserting it here means the
  // shipped client is shown to send it rather than assumed to.
  if (req.headers['x-estate-vault-csrf'] !== '1') return json(403, { error: 'forbidden' });

  /*
   * AN EXPIRED ACCESS TOKEN, ANSWERED THE WAY IDENTITY ANSWERS ONE (M44 PR2).
   *
   * `smoke-access-stale` stands for a token past its fifteen minutes: every
   * vault route refuses it 401, and `/api/auth/refresh` trades the matching
   * refresh token for a live pair. That is the whole shape of the defect PR2
   * closed — a popup that could not refresh answered every action with "This
   * device is no longer connected to your account" about a live pairing — and
   * without these two arms it is not reachable in a browser at all.
   *
   * `smoke-access` stays valid so every step written before this one keeps
   * asserting exactly what it did.
   */
  /*
   * AN ACCESS TOKEN AGEING OUT MID-SESSION, WHICH IS THE ONLY WAY THE M44 PR2
   * DEFECT IS REACHABLE.
   *
   * It is deliberately a TRANSITION, not a token that was stale to begin with.
   * The first draft of this made `/__expire` unnecessary by seeding the popup
   * with an already-dead bearer — and that check could not fail, because
   * `refreshStatus` runs at mount, refreshes, stores, and only THEN is the
   * vault half mounted, so the snapshot it took was fresh. The mutation
   * survived in Chrome and said 13/13.
   *
   * The real defect needs a popup that mounted on a LIVE token which later
   * expires: `vaultMounted` guards the remount, so the vault half goes on
   * holding the value it captured while everything around it rotates.
   */
  if (req.url === '/__expire') {
    expired = true;
    return json(200, { expired });
  }
  if (req.url === '/api/auth/refresh') {
    const parsed = JSON.parse(body || '{}');
    if (parsed.refreshToken !== 'smoke-refresh') return json(401, { error: 'invalid_token' });
    return json(200, {
      accessToken: 'smoke-access-2',
      refreshToken: 'smoke-refresh-2',
      userId: USER_ID,
      sessionId: 'smoke-session',
    });
  }
  if (expired && req.headers['authorization'] === 'Bearer smoke-access') {
    // The token identity's SessionGuard refuses an aged bearer with.
    return json(401, { error: 'unauthorized' });
  }

  if (req.url === '/api/vault/keyset') {
    return json(200, { enrolled: true });
  }
  if (req.url === '/api/vault/srp/start') {
    ephemeral = await createServerEphemeral(verifier);
    return json(201, {
      handshakeId: '00000000-0000-4000-8000-000000000000',
      srpSalt: keyset.srpSalt,
      kdfParams: keyset.kdfParams,
      serverPublic: encodeGroupElement(ephemeral.B),
    });
  }
  if (req.url === '/api/vault/srp/verify') {
    const parsed = JSON.parse(body);
    const verified = await verifyClientSession({
      userId: USER_ID,
      salt: fromBase64(keyset.srpSalt),
      verifier,
      ephemeral,
      A: decodeGroupElement(parsed.clientPublic, 'client public value'),
      M1: fromBase64(parsed.clientProof),
    });
    // A WRONG PASSWORD OR SECRET KEY FAILS HERE, for real. The 401 is the
    // server refusing a proof it cannot verify, not a fixture choosing to.
    if (!verified) return json(401, { error: 'srp_failed' });
    return json(200, {
      serverProof: toBase64(verified.M2),
      wrappedMasterKey: keyset.wrappedMasterKey,
      vaultSession: {
        id: '66666666-0000-4000-8000-000000000000',
        token: 'opaque-vault-session-token',
        expiresAt: '2099-01-01T00:00:00.000Z',
      },
    });
  }
  if (req.url?.startsWith('/api/vault/items')) return json(200, { items: rows });
  if (req.url === '/api/vault/lock') return json(204, {});
  return json(404, { error: 'not_found' });
});

server.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(
    `${JSON.stringify({
      ready: true,
      port: PORT,
      userId: USER_ID,
      password: PASSWORD,
      secretKey: enrollment.secretKey,
      itemSecret: ITEM_SECRET,
      itemTitle: ITEM_TITLE,
    })}\n`,
  );
});
