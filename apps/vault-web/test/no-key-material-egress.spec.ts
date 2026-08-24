/**
 * @jest-environment jsdom
 */

/**
 * THE CENTRAL CLAIM OF THE MILESTONE, driven rather than argued.
 *
 * "Nothing derived from the vault password or the Secret Key ever leaves the
 * device" is the sentence M15 exists to make true. `fences.spec.ts` proves the
 * structural half — one network call site, no logger, no HTML sink. This proves
 * the BEHAVIOURAL half: a full enrollment, unlock, create and update runs
 * against a RECORDING transport, and every byte the client tried to send is
 * searched for the secrets it holds.
 *
 * The crypto is real — jest resolves `/lib/vault-crypto/index.js` to the package
 * sources — so this exercises PBKDF2, SRP-6a and AES-GCM exactly as the browser
 * will. A version that stubbed the crypto could not distinguish "the password
 * is absent" from "the password was never computed with".
 *
 * The passwords below are DISTINCTIVE STRINGS rather than realistic ones, so a
 * substring search over the recorded bodies is exact: a realistic password
 * could appear by coincidence inside base64 and prove nothing.
 */
import {
  createServerEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  fromBase64,
  toBase64,
  verifyClientSession,
} from '@estate/vault-crypto';
import { VaultSession } from '../src/client/vault-session';

const USER = '11111111-2222-4333-8444-555555555555';
const PASSWORD = 'CANARY-vault-password-must-never-transit-9f3a';
const ITEM_SECRET = 'CANARY-item-secret-value-must-never-transit-7b2c';
const ITEM_TITLE = 'CANARY-item-title-must-never-transit-4d1e';

interface Recorded {
  path: string;
  method: string;
  body: string;
  headers: Record<string, string>;
}

/**
 * A stand-in vault service that speaks the REAL protocol.
 *
 * vault-crypto ships both roles (the service imports the server half), so this
 * completes a genuine SRP-6a exchange against the verifier the enrollment just
 * produced — which is what lets the test drive unlock, create and update rather
 * than stopping at enrollment. A fake that returned canned values could not
 * distinguish "the plaintext is absent from the wire" from "the encryption
 * never ran".
 */
function recordingTransport(): { calls: Recorded[] } {
  const calls: Recorded[] = [];
  let keyset: Record<string, string> | null = null;
  let ephemeral: Awaited<ReturnType<typeof createServerEphemeral>> | null = null;

  globalThis.fetch = ((path: string, init: RequestInit = {}) => {
    const body = typeof init.body === 'string' ? init.body : '';
    const method = init.method ?? 'GET';
    calls.push({ path, method, body, headers: (init.headers ?? {}) as Record<string, string> });

    const reply = (status: number, payload: unknown): unknown => ({
      ok: status >= 200 && status < 300,
      status,
      text: () => Promise.resolve(JSON.stringify(payload)),
    });

    if (path === '/api/vault/keyset' && method === 'POST') {
      keyset = JSON.parse(body) as Record<string, string>;
      return Promise.resolve(reply(201, { enrolled: true, updatedAt: null }));
    }
    if (path === '/api/vault/srp/start') {
      if (!keyset) return Promise.resolve(reply(404, { error: 'keyset_not_found' }));
      const verifier = decodeGroupElement(keyset['srpVerifier'] as string, 'verifier');
      return createServerEphemeral(verifier).then((made) => {
        ephemeral = made;
        return reply(201, {
          handshakeId: '00000000-0000-4000-8000-000000000000',
          srpSalt: keyset?.['srpSalt'],
          kdfParams: keyset?.['kdfParams'],
          serverPublic: encodeGroupElement(made.B),
        });
      });
    }
    if (path === '/api/vault/srp/verify') {
      if (!keyset || !ephemeral) return Promise.resolve(reply(401, { error: 'srp_failed' }));
      const parsed = JSON.parse(body) as Record<string, string>;
      return verifyClientSession({
        userId: USER,
        salt: fromBase64(keyset['srpSalt'] as string),
        verifier: decodeGroupElement(keyset['srpVerifier'] as string, 'verifier'),
        ephemeral,
        A: decodeGroupElement(parsed['clientPublic'] as string, 'client public value'),
        M1: fromBase64(parsed['clientProof'] as string),
      }).then((verified) =>
        verified
          ? reply(200, {
              serverProof: toBase64(verified.M2),
              wrappedMasterKey: keyset?.['wrappedMasterKey'],
              vaultSession: {
                id: '11111111-0000-4000-8000-000000000000',
                token: 'opaque-vault-session-token',
                expiresAt: '2099-01-01T00:00:00.000Z',
              },
            })
          : reply(401, { error: 'srp_failed' }),
      );
    }
    // THE RESTORE VERBS, BEFORE THE CREATE ARM (M27 PR2). `undelete` sends no
    // body at all, so falling into the arm below would `JSON.parse('')`, reject
    // the transport, and surface through api.ts's catch as an invented NETWORK
    // failure — a double lying about an outage rather than about a shape.
    if (path.endsWith('/undelete') && method === 'POST') {
      return Promise.resolve(
        reply(200, {
          id: 'x',
          itemType: 'password',
          blob: '',
          blobVersion: 1,
          revision: 43,
          createdAt: 'now',
          updatedAt: 'now',
        }),
      );
    }
    if (path.endsWith('/restore') && method === 'POST') {
      return Promise.resolve(
        reply(200, {
          id: 'x',
          itemType: 'password',
          blob: '',
          blobVersion: 1,
          revision: 44,
          createdAt: 'now',
          updatedAt: 'now',
        }),
      );
    }
    if (path.startsWith('/api/vault/items') && method === 'POST') {
      const parsed = JSON.parse(body) as Record<string, unknown>;
      return Promise.resolve(
        reply(201, { ...parsed, blobVersion: 1, createdAt: 'now', updatedAt: 'now' }),
      );
    }
    if (path.startsWith('/api/vault/items') && method === 'PUT') {
      const parsed = JSON.parse(body) as Record<string, unknown>;
      return Promise.resolve(
        reply(200, { ...parsed, id: 'x', blobVersion: 2, createdAt: 'now', updatedAt: 'now' }),
      );
    }
    return Promise.resolve(reply(200, {}));
  }) as unknown as typeof fetch;

  return { calls };
}

describe('no key material reaches the network', () => {
  jest.setTimeout(60_000); // real PBKDF2 at 650k iterations is not instant

  it('enrolls without ever transmitting the password or the Secret Key', async () => {
    const { calls } = recordingTransport();
    const session = new VaultSession();

    const enrolled = await session.enroll(USER, PASSWORD);
    expect(enrolled.ok).toBe(true);
    if (!enrolled.ok) return;

    const secretKey = enrolled.data.secretKey;
    expect(secretKey).toMatch(/^ES1-/);

    const sent = calls.map((c) => `${c.method} ${c.path} ${c.body} ${JSON.stringify(c.headers)}`);
    const wire = sent.join('\n');

    // THE ASSERTIONS THE MILESTONE TURNS ON.
    expect(wire).not.toContain(PASSWORD);
    expect(wire).not.toContain(secretKey);
    // Also its parts: the Secret Key is grouped with dashes for reading, so a
    // client that stripped them before sending would evade a whole-string
    // search while leaking exactly the same entropy.
    for (const group of secretKey.split('-').filter((g) => g.length > 3)) {
      expect(wire).not.toContain(group);
    }

    // And something DID go out — otherwise this passes because nothing happened.
    expect(calls.some((c) => c.path === '/api/vault/keyset' && c.method === 'POST')).toBe(true);
    expect(wire).toContain('srpVerifier');
  });

  it('never transmits item plaintext — the blob is opaque on the wire', async () => {
    const { calls } = recordingTransport();
    const session = new VaultSession();

    const enrolled = await session.enroll(USER, PASSWORD);
    if (!enrolled.ok) throw new Error('enrollment failed');

    // A REAL unlock against the verifier enrollment just produced.
    const opened = await session.unlock(USER, PASSWORD, enrolled.data.secretKey);
    expect(opened.ok).toBe(true);
    expect(session.isUnlocked).toBe(true);

    calls.length = 0;
    const created = await session.create('password', {
      title: ITEM_TITLE,
      secret: ITEM_SECRET,
      username: 'someone@example.test',
    });
    expect(created.ok).toBe(true);

    const wire = calls.map((c) => `${c.path} ${c.body}`).join('\n');
    // The blob went out…
    expect(wire).toContain('/api/vault/items');
    expect(wire).toMatch(/"blob":"[A-Za-z0-9+/=]+"/);
    // …and none of its contents did.
    expect(wire).not.toContain(ITEM_SECRET);
    expect(wire).not.toContain(ITEM_TITLE);
    expect(wire).not.toContain('someone@example.test');
    expect(wire).not.toContain(PASSWORD);
    expect(wire).not.toContain(enrolled.data.secretKey);
  });

  it('restores a version without sending ciphertext or key material (M27 PR2)', async () => {
    // THE FOURTH CANARY. A restore is the one verb that WRITES content the
    // client did not encrypt in that request — the server copies `blob_ct` and
    // `blob_version` forward itself. So the wire should carry a revision and
    // nothing else, and this states that in the suite that exists to state it
    // rather than in a comment beside the call site.
    const { calls } = recordingTransport();
    const session = new VaultSession();

    const enrolled = await session.enroll(USER, PASSWORD);
    if (!enrolled.ok) throw new Error('enrollment failed');
    const opened = await session.unlock(USER, PASSWORD, enrolled.data.secretKey);
    expect(opened.ok).toBe(true);

    await session.create('password', { title: ITEM_TITLE, secret: ITEM_SECRET });
    calls.length = 0;

    const restored = await session.restoreVersion('x', 41, 42);
    expect(restored.ok).toBe(true);
    const undeleted = await session.undelete('x');
    expect(undeleted.ok).toBe(true);

    const wire = calls.map((c) => `${c.path} ${c.body}`).join('\n');
    // ANTI-VACUITY: both calls really went out, or the absences below are free.
    expect(wire).toContain('/restore');
    expect(wire).toContain('/undelete');
    // The restore names a revision and carries NOTHING else…
    expect(JSON.parse(calls.find((c) => c.path.endsWith('/restore'))?.body ?? '{}')).toEqual({
      revision: 41,
    });
    // …the undelete carries no body at all…
    expect(calls.find((c) => c.path.endsWith('/undelete'))?.body ?? '').toBe('');
    // …and neither leaks anything the device holds.
    expect(wire).not.toContain(ITEM_SECRET);
    expect(wire).not.toContain(ITEM_TITLE);
    expect(wire).not.toContain(PASSWORD);
    expect(wire).not.toContain(enrolled.data.secretKey);
    expect(wire).not.toMatch(/"blob":/);
  });

  it('round-trips an item through real encryption — so the blob is not just noise', async () => {
    // Without this, the assertions above would pass for a client that encrypted
    // garbage. The point is that the ciphertext is BOTH opaque on the wire and
    // openable by the key this device holds.
    const { calls } = recordingTransport();
    const session = new VaultSession();
    const enrolled = await session.enroll(USER, PASSWORD);
    if (!enrolled.ok) throw new Error('enrollment failed');
    await session.unlock(USER, PASSWORD, enrolled.data.secretKey);

    const created = await session.create('password', { title: ITEM_TITLE, secret: ITEM_SECRET });
    if (!created.ok) throw new Error('create failed');

    // Feed the stored row back through the list path, which decrypts.
    const sent = calls.find((c) => c.path.startsWith('/api/vault/items') && c.method === 'POST');
    const row = JSON.parse(sent?.body ?? '{}') as { id: string; blob: string };
    globalThis.fetch = (() =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () =>
          Promise.resolve(
            JSON.stringify({
              items: [
                {
                  id: row.id,
                  itemType: 'password',
                  blob: row.blob,
                  blobVersion: 1,
                  createdAt: 'now',
                  updatedAt: 'now',
                },
              ],
              nextCursor: null,
            }),
          ),
      })) as unknown as typeof fetch;

    const listed = await session.list();
    expect(listed.ok).toBe(true);
    if (!listed.ok) return;
    expect(listed.data[0]?.unreadable).toBeUndefined();
    expect(listed.data[0]?.content.title).toBe(ITEM_TITLE);
    expect(listed.data[0]?.content.secret).toBe(ITEM_SECRET);
  });
});
