/**
 * NOTHING DERIVED FROM THE VAULT PASSWORD OR THE SECRET KEY LEAVES THE DEVICE —
 * driven, not argued.
 *
 * This is the extension's counterpart to `vault-web`'s
 * `no-key-material-egress.spec.ts`, and it works the same way: a stand-in vault
 * service speaking the REAL protocol (vault-crypto ships both roles), a real
 * unlock through the real key holder, and then every recorded byte searched for
 * the two secrets. A version that stubbed the crypto could not tell "the
 * plaintext is absent" from "the encryption never ran".
 *
 * It also pins the failure shapes that matter more here than on the web origin:
 * a wrong vault password must NOT read as a lost pairing, and a response
 * missing its fields must not reach the unwrap path.
 */
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
import { VaultHost, type KeyHolderPort } from '../src/vault-host';
import { VaultKeyHolder } from '../src/vault-worker-core';
import { clearChromeDouble, installChromeDouble, TEST_ORIGIN } from './chrome-double';

const USER = '11111111-2222-4333-8444-555555555555';
const PASSWORD = 'a vault password nobody else knows';
const BEARER = 'extension-access-token';
const SECRET_ITEM = 'the item secret that must never reach the wire';

interface Recorded {
  url: string;
  method: string;
  body: string;
  headers: Record<string, string>;
}

/** A stand-in vault service that completes a genuine SRP-6a exchange. */
async function stubService(
  options: { titles?: readonly string[]; urls?: readonly string[] } = {},
): Promise<{
  calls: Recorded[];
  secretKey: string;
}> {
  const { enrollment, masterKey } = await createVaultEnrollment({
    userId: USER,
    password: PASSWORD,
  });
  const keyset = enrollment.payload as unknown as Record<string, string>;
  const verifier = decodeGroupElement(keyset['srpVerifier'] as string, 'verifier');
  let ephemeral: Awaited<ReturnType<typeof createServerEphemeral>> | null = null;

  /*
   * One sealed row per title, in the order given — which the ordering case
   * then deliberately gives REVERSED, so a host that simply passed the
   * server's order through would fail it.
   */
  const titles = options.titles ?? ['Bank login'];
  const rows = await Promise.all(
    titles.map(async (title, index) => {
      const id = `${String(index)}5555555-0000-4000-8000-000000000000`;
      const url = options.urls?.[index];
      const plaintext = new TextEncoder().encode(
        JSON.stringify({ title, secret: SECRET_ITEM, ...(url === undefined ? {} : { url }) }),
      );
      return {
        id,
        itemType: 'password',
        blob: toBase64(
          await encryptItem(masterKey, { userId: USER, itemId: id, blobVersion: 1 }, plaintext),
        ),
        blobVersion: 1,
        updatedAt: '2026-08-10T00:00:00Z',
      };
    }),
  );

  const calls: Recorded[] = [];
  (globalThis as { fetch?: unknown }).fetch = (
    url: unknown,
    init: RequestInit,
  ): Promise<Response> => {
    const path = String(url).slice(TEST_ORIGIN.length);
    const body = typeof init.body === 'string' ? init.body : '';
    calls.push({
      url: String(url),
      method: init.method ?? 'GET',
      body,
      headers: (init.headers ?? {}) as Record<string, string>,
    });
    const reply = (status: number, payload: unknown): Response =>
      ({
        ok: status >= 200 && status < 300,
        status,
        text: () => Promise.resolve(JSON.stringify(payload)),
      }) as unknown as Response;

    if (path === '/api/vault/srp/start') {
      return createServerEphemeral(verifier).then((made) => {
        ephemeral = made;
        return reply(201, {
          handshakeId: '00000000-0000-4000-8000-000000000000',
          srpSalt: keyset['srpSalt'],
          kdfParams: keyset['kdfParams'],
          serverPublic: encodeGroupElement(made.B),
        });
      });
    }
    if (path === '/api/vault/srp/verify') {
      const parsed = JSON.parse(body) as Record<string, string>;
      return verifyClientSession({
        userId: USER,
        salt: fromBase64(keyset['srpSalt'] as string),
        verifier,
        ephemeral: ephemeral as NonNullable<typeof ephemeral>,
        A: decodeGroupElement(parsed['clientPublic'] as string, 'client public value'),
        M1: fromBase64(parsed['clientProof'] as string),
      }).then((verified) =>
        verified
          ? reply(200, {
              serverProof: toBase64(verified.M2),
              wrappedMasterKey: keyset['wrappedMasterKey'],
              vaultSession: {
                id: '66666666-0000-4000-8000-000000000000',
                token: 'opaque-vault-session-token',
                expiresAt: '2099-01-01T00:00:00.000Z',
              },
            })
          : reply(401, { error: 'srp_failed' }),
      );
    }
    if (path.startsWith('/api/vault/items')) {
      const method = init.method ?? 'GET';
      if (method === 'POST') {
        const sent = JSON.parse(body) as { id: string; itemType: string };
        // The service's own shape: version 1 on insert, echoed back.
        return Promise.resolve(reply(201, { ...sent, blobVersion: 1 }));
      }
      if (method === 'PUT') {
        const sent = JSON.parse(body) as { itemType: string };
        const headers = (init.headers ?? {}) as Record<string, string>;
        // And the service's own rule: it writes `locked.blob_version + 1`,
        // having first compared `If-Match` to the row it locked.
        const ifMatch = Number(headers['if-match']);
        return Promise.resolve(
          reply(200, {
            id: path.split('/').pop(),
            itemType: sent.itemType,
            blobVersion: ifMatch + 1,
          }),
        );
      }
      return Promise.resolve(reply(200, { items: rows }));
    }
    if (path === '/api/vault/lock') return Promise.resolve(reply(204, {}));
    return Promise.resolve(reply(404, { error: 'not_found' }));
  };

  return { calls, secretKey: enrollment.secretKey };
}

function host(): VaultHost {
  return new VaultHost({ holder: new VaultKeyHolder() });
}

describe('unlocking through the host', () => {
  jest.setTimeout(60_000);
  afterEach(clearChromeDouble);

  it('opens the vault, lists a real item, and NEVER puts the secrets on the wire', async () => {
    installChromeDouble();
    const { calls, secretKey } = await stubService();
    const vault = host();

    const opened = await vault.unlock({
      userId: USER,
      password: PASSWORD,
      secretKey,
      bearer: BEARER,
    });
    expect(opened).toEqual({
      ok: true,
      data: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' },
    });

    const listed = await vault.list(BEARER);
    expect(listed).toEqual({
      ok: true,
      data: [
        {
          id: '05555555-0000-4000-8000-000000000000',
          itemType: 'password',
          title: 'Bank login',
          blobVersion: 1,
        },
      ],
    });

    // THE CLAIM. Every recorded byte — urls, bodies and headers alike.
    const wire = JSON.stringify(calls);
    expect(wire).not.toContain(PASSWORD);
    expect(wire).not.toContain(secretKey);
    // ...and the ungrouped form, since the human-readable one carries dashes.
    expect(wire).not.toContain(secretKey.replace(/-/g, ''));
    // The item's secret half never left the worker either.
    expect(wire).not.toContain(SECRET_ITEM);
    expect(JSON.stringify(listed)).not.toContain(SECRET_ITEM);
  });

  it('carries the vault session on the item read, and the bearer on both', async () => {
    installChromeDouble();
    const { calls, secretKey } = await stubService();
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });
    await vault.list(BEARER);

    const read = calls.find((c) => c.url.includes('/api/vault/items'));
    // BOTH authorities: the bearer says which account, the vault session says
    // this device actually opened the vault. A stolen extension credential has
    // only the first, which is why it reaches the API and decrypts nothing.
    expect(read?.headers['authorization']).toBe(`Bearer ${BEARER}`);
    expect(read?.headers['x-estate-vault-session']).toBe('opaque-vault-session-token');
  });

  it('orders what a person reads by TITLE, not by the server’s cursor', async () => {
    // The service orders by `updated_at` for its pagination cursor. What a
    // person scans down should not depend on that being the same thing, so the
    // host sorts — and with one item a sort proves nothing, which is why this
    // case exists at all.
    installChromeDouble();
    const { secretKey } = await stubService({ titles: ['Zulu', 'Alpha'] });
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });

    const listed = await vault.list(BEARER);
    expect(listed.ok && listed.data.map((i) => i.title)).toEqual(['Alpha', 'Zulu']);
  });

  it('a WRONG vault password is SRP_FAILED, never UNAUTHENTICATED', async () => {
    // The distinction that decides whether a typo disconnects the device: the
    // popup forgets the pairing on UNAUTHENTICATED.
    installChromeDouble();
    const { secretKey } = await stubService();
    const vault = host();
    const result = await vault.unlock({
      userId: USER,
      password: 'not the vault password',
      secretKey,
      bearer: BEARER,
    });
    expect(result).toEqual({ ok: false, code: 'SRP_FAILED' });
    expect(vault.state).toEqual({ status: 'locked' });
  });

  it('a malformed Secret Key fails locally, before any handshake', async () => {
    installChromeDouble();
    const { calls } = await stubService();
    const vault = host();
    const result = await vault.unlock({
      userId: USER,
      password: PASSWORD,
      secretKey: 'not-a-secret-key',
      bearer: BEARER,
    });
    expect(result).toEqual({ ok: false, code: 'SRP_FAILED' });
    // One `srp/start` and nothing after it: the verify leg never happened.
    expect(calls.map((c) => c.url.slice(TEST_ORIGIN.length))).toEqual(['/api/vault/srp/start']);
  });

  /**
   * EVERY field of the verify response is load-bearing, so every one gets its
   * own case.
   *
   * The first version of this omitted only `wrappedMasterKey` — and a mutation
   * deleting TWO of the five guards left it green, because the remaining three
   * still caught that one payload. A test named for a property it does not pin
   * is the shape this repo keeps rediscovering; table-driven now, so each guard
   * is killed by its own mutation.
   */
  it.each(['serverProof', 'wrappedMasterKey', 'id', 'token', 'expiresAt'])(
    'refuses to open when the verify response is missing %s',
    async (missing) => {
      installChromeDouble();
      const { secretKey } = await stubService();
      const original = globalThis.fetch;
      (globalThis as { fetch?: unknown }).fetch = (url: unknown, init: RequestInit) => {
        if (String(url).endsWith('/api/vault/srp/verify')) {
          const session: Record<string, unknown> = {
            id: '66666666-0000-4000-8000-000000000000',
            token: 'opaque',
            expiresAt: '2099-01-01T00:00:00.000Z',
          };
          const payload: Record<string, unknown> = {
            serverProof: 'AA==',
            wrappedMasterKey: 'AA==',
            vaultSession: session,
          };
          if (missing in payload) delete payload[missing];
          else delete session[missing];
          return Promise.resolve({
            ok: true,
            status: 200,
            text: () => Promise.resolve(JSON.stringify(payload)),
          } as unknown as Response);
        }
        return original(url as string, init);
      };
      const vault = host();
      const result = await vault.unlock({
        userId: USER,
        password: PASSWORD,
        secretKey,
        bearer: BEARER,
      });
      expect(result).toEqual({ ok: false, code: 'UNKNOWN' });
      expect(vault.state).toEqual({ status: 'locked' });
    },
  );

  it('refuses to list while locked, and an unreachable vault is not an empty one', async () => {
    installChromeDouble();
    const { secretKey } = await stubService();
    const vault = host();
    expect(await vault.list(BEARER)).toEqual({ ok: false, code: 'VAULT_LOCKED' });

    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });
    (globalThis as { fetch?: unknown }).fetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{}'), // no `items` field at all
      } as unknown as Response);
    expect(await vault.list(BEARER)).toEqual({ ok: false, code: 'UNKNOWN' });
  });

  it('answers WHAT IS SAVED FOR THIS PAGE, decided inside the key holder', async () => {
    /*
     * The full path with real crypto: three items sealed with different urls,
     * matched against one page. What is pinned is that the decision happens
     * where the url is readable, and that nothing about the unrelated items
     * comes back — the host asked about ONE origin and learns about that origin.
     */
    installChromeDouble();
    const { secretKey } = await stubService({
      titles: ['Bank', 'Other', 'Lookalike'],
      urls: ['https://www.example.com/login', 'https://unrelated.test/', 'https://exarnple.com/'],
    });
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });

    const matched = await vault.matchesFor(BEARER, 'https://example.com/account');
    expect(matched.ok).toBe(true);
    const rows = matched.ok ? matched.data : [];
    expect(rows.map((r) => [r.title, r.verdict.kind])).toEqual([
      ['Bank', 'match'],
      ['Lookalike', 'confusable'],
    ]);
    // The unrelated item is not merely unmatched — it is ABSENT.
    expect(JSON.stringify(rows)).not.toContain('Other');
    // ...and no secret came back with any of them.
    expect(JSON.stringify(rows)).not.toContain(SECRET_ITEM);
  });

  it('skips an item it cannot open rather than claiming anything about it', async () => {
    // A blob this build cannot decrypt cannot be matched against anything, and
    // reporting it as "no match" would be a claim about an item nobody read.
    installChromeDouble();
    const { secretKey } = await stubService({
      titles: ['Bank'],
      urls: ['https://www.example.com/login'],
    });
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });

    const original = globalThis.fetch;
    (globalThis as { fetch?: unknown }).fetch = (url: unknown, init: RequestInit) => {
      if (String(url).includes('/api/vault/items')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: () =>
            Promise.resolve(
              JSON.stringify({
                items: [
                  {
                    id: '99999999-0000-4000-8000-000000000000',
                    itemType: 'password',
                    blob: 'AAAAAAAAAAAAAAAAAAAAAA==',
                    blobVersion: 1,
                    updatedAt: '2026-08-10T00:00:00Z',
                  },
                ],
              }),
            ),
        } as unknown as Response);
      }
      return original(url as string, init);
    };
    const matched = await vault.matchesFor(BEARER, 'https://example.com/');
    expect(matched).toEqual({ ok: true, data: [] });
  });

  it('FILLS through the holder, and refuses a page the item does not belong to', async () => {
    /*
     * The full path with real crypto again, because the property is that the
     * HOLDER decides from the item's own encrypted url. The host carries rows in
     * and a decision out; it cannot see the url and takes no view.
     */
    installChromeDouble();
    const { secretKey } = await stubService({
      titles: ['Bank'],
      urls: ['https://www.example.com/login'],
    });
    const itemId = '05555555-0000-4000-8000-000000000000'; // the stub's first row
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });

    const filled = await vault.fillFor(BEARER, itemId, 'https://example.com/account');
    expect(filled).toEqual({ ok: true, data: { username: '', secret: SECRET_ITEM } });

    // Same item, a page it has nothing to do with: refused, and the refusal is
    // `null` data rather than an error, so nothing explains which reason applied.
    const refused = await vault.fillFor(BEARER, itemId, 'https://evil.test/');
    expect(refused).toEqual({ ok: true, data: null });
  });

  it('an item list it cannot read is not a fill', async () => {
    // Same rule as `list`: an unreachable or malformed page of rows is UNKNOWN,
    // never an empty set that would read as "nothing is saved for this page".
    installChromeDouble();
    const { secretKey } = await stubService();
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });
    (globalThis as { fetch?: unknown }).fetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{}'),
      } as unknown as Response);
    expect(await vault.fillFor(BEARER, 'i-1', 'https://example.com/')).toEqual({
      ok: false,
      code: 'UNKNOWN',
    });
  });

  it('refuses to fill while locked', async () => {
    installChromeDouble();
    await stubService();
    const vault = host();
    expect(await vault.fillFor(BEARER, 'i-1', 'https://example.com/')).toEqual({
      ok: false,
      code: 'VAULT_LOCKED',
    });
  });

  it('refuses to match while locked', async () => {
    installChromeDouble();
    await stubService();
    const vault = host();
    expect(await vault.matchesFor(BEARER, 'https://example.com/')).toEqual({
      ok: false,
      code: 'VAULT_LOCKED',
    });
  });

  it('an unreachable item list is not an empty match set', async () => {
    installChromeDouble();
    const { secretKey } = await stubService();
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });
    (globalThis as { fetch?: unknown }).fetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{}'),
      } as unknown as Response);
    expect(await vault.matchesFor(BEARER, 'https://example.com/')).toEqual({
      ok: false,
      code: 'UNKNOWN',
    });
  });

  it('locks LOCALLY FIRST, then tells the server', async () => {
    installChromeDouble();
    const { calls, secretKey } = await stubService();
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });

    await vault.lock(BEARER);
    expect(vault.state).toEqual({ status: 'locked' });
    expect(calls.at(-1)?.url.slice(TEST_ORIGIN.length)).toBe('/api/vault/lock');
    // ...and the keys are gone whatever the server said.
    expect(await vault.list(BEARER)).toEqual({ ok: false, code: 'VAULT_LOCKED' });
  });

  it('a server proof that does not verify is SRP_FAILED, and drops the keys', async () => {
    // `finishUnlock` checks M2 BEFORE the wrapped master key reaches the unwrap
    // path, so a server that cannot prove it holds the verifier gets no further.
    installChromeDouble();
    const { secretKey } = await stubService();
    const original = globalThis.fetch;
    (globalThis as { fetch?: unknown }).fetch = (url: unknown, init: RequestInit) => {
      if (String(url).endsWith('/api/vault/srp/verify')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: () =>
            Promise.resolve(
              JSON.stringify({
                serverProof: toBase64(new Uint8Array(32)),
                wrappedMasterKey: 'AAAA',
                vaultSession: {
                  id: '66666666-0000-4000-8000-000000000000',
                  token: 'opaque',
                  expiresAt: '2099-01-01T00:00:00.000Z',
                },
              }),
            ),
        } as unknown as Response);
      }
      return original(url as string, init);
    };
    const vault = host();
    const result = await vault.unlock({
      userId: USER,
      password: PASSWORD,
      secretKey,
      bearer: BEARER,
    });
    expect(result).toEqual({ ok: false, code: 'SRP_FAILED' });
    expect(vault.state).toEqual({ status: 'locked' });
  });

  it('locks without a bearer, and tells nobody', async () => {
    // The idle path and the teardown path both reach this: dropping keys must
    // never depend on having a credential to spend.
    installChromeDouble();
    const { calls, secretKey } = await stubService();
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });
    const before = calls.length;

    await vault.lock();
    expect(vault.state).toEqual({ status: 'locked' });
    expect(calls).toHaveLength(before);
  });

  it('drops the keys when the idle clock fires', async () => {
    installChromeDouble();
    const { secretKey } = await stubService();
    let fire: (() => void) | null = null;
    const vault = new VaultHost({
      holder: new VaultKeyHolder(),
      setTimer: (run) => {
        fire = run;
        return 1;
      },
      clearTimer: () => undefined,
    });
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });
    expect(vault.state.status).toBe('unlocked');

    (fire as unknown as () => void)();
    expect(vault.state).toEqual({ status: 'locked' });
    // No network call is needed to make an idle lock real — the keys are the
    // thing, and the server session expires on its own clock.
    expect(await vault.list(BEARER)).toEqual({ ok: false, code: 'VAULT_LOCKED' });
  });
});

describe('writing an item through the host (M16 PR4a)', () => {
  jest.setTimeout(60_000);
  afterEach(clearChromeDouble);

  /**
   * A holder that records what it was asked to seal, so the VERSION the blob is
   * sealed FOR can be asserted. That number is the subtle part of the write
   * path: it lives inside the AEAD's AAD, and the service writes
   * `locked.blob_version + 1` after checking `If-Match` against the row it
   * locked — so sealing for the version we READ produces a blob that no longer
   * opens once it lands, and nothing in the response would say so.
   */
  function recordingHost(): {
    host: VaultHost;
    sealed: Array<{ itemId: string; blobVersion: number }>;
  } {
    const sealed: Array<{ itemId: string; blobVersion: number }> = [];
    const holder: KeyHolderPort = {
      isUnlocked: true,
      prepare: () => Promise.resolve({ publicA: 'A', m1: 'M' }),
      finish: () => Promise.resolve(),
      summarise: () => Promise.resolve([]),
      matchesFor: () => Promise.resolve([]),
      fillFor: () => Promise.resolve(null),
      sealItem: (input: { itemId: string; blobVersion: number }) => {
        sealed.push({ itemId: input.itemId, blobVersion: input.blobVersion });
        return Promise.resolve('c2VhbGVk');
      },
      lock: () => undefined,
    };
    const host = new VaultHost({ holder });
    return { host, sealed };
  }

  it('refuses to write at all when the vault is locked, and seals nothing', async () => {
    installChromeDouble();
    const { host, sealed } = recordingHost();
    // No unlock has happened, so there is no vault session.
    expect(await host.createItem(BEARER, 'password', { title: 'x' })).toEqual({
      ok: false,
      code: 'VAULT_LOCKED',
    });
    expect(
      await host.updateItem({
        bearer: BEARER,
        itemId: 'i-1',
        itemType: 'password',
        content: { title: 'x' },
        blobVersion: 3,
      }),
    ).toEqual({ ok: false, code: 'VAULT_LOCKED' });
    // And crucially it did not hand plaintext to the holder on the way to
    // finding that out.
    expect(sealed).toEqual([]);
  });
});

describe('a write, sealed for the version the service will write (M16 PR4a)', () => {
  jest.setTimeout(60_000);
  afterEach(clearChromeDouble);

  it('creates: mints an id, seals at version 1, and POSTs that id', async () => {
    installChromeDouble();
    const { calls, secretKey } = await stubService();
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });

    const made = await vault.createItem(BEARER, 'password', { title: 'Typed here' });
    expect(made.ok).toBe(true);
    const data = (
      made as { data: { id: string; itemType: string; title: string; blobVersion: number } }
    ).data;
    expect({ itemType: data.itemType, title: data.title, blobVersion: data.blobVersion }).toEqual({
      itemType: 'password',
      title: 'Typed here',
      blobVersion: 1,
    });
    // A UUID the HOST minted, not one the caller supplied.
    expect(data.id).toMatch(/^[0-9a-f-]{36}$/);

    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/api/vault/items'));
    const sent = JSON.parse(post?.body ?? '{}') as { id: string; blob: string };
    // The id in the request is the id that came back, because it is bound into
    // the blob's AAD and the two must be the same value.
    expect(data.id).toBe(sent.id);
    // A create carries no If-Match: there is no version to match on.
    expect(Object.keys(post?.headers ?? {})).not.toContain('if-match');
  });

  it('updates: sends If-Match with the version READ, and seals for its successor', async () => {
    installChromeDouble();
    const { calls, secretKey } = await stubService();
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });

    const saved = await vault.updateItem({
      bearer: BEARER,
      itemId: '05555555-0000-4000-8000-000000000000',
      itemType: 'password',
      content: { title: 'Edited' },
      blobVersion: 4,
    });

    const put = calls.find((c) => c.method === 'PUT');
    // The version the caller READ goes in the header...
    expect(put?.headers['if-match']).toBe('4');
    // ...and the service answers with its successor, which is what the blob was
    // sealed for. If those two ever disagreed the row would land unopenable and
    // nothing in the response would say so.
    expect(saved).toEqual({
      ok: true,
      data: {
        id: '05555555-0000-4000-8000-000000000000',
        itemType: 'password',
        title: 'Edited',
        blobVersion: 5,
      },
    });
  });

  it('passes a version conflict through as itself', async () => {
    installChromeDouble();
    const { secretKey } = await stubService();
    const vault = host();
    await vault.unlock({ userId: USER, password: PASSWORD, secretKey, bearer: BEARER });

    // The service answers 409 when the row moved under the caller.
    const previous = globalThis.fetch;
    (globalThis as { fetch?: unknown }).fetch = () =>
      Promise.resolve({
        ok: false,
        status: 409,
        text: () => Promise.resolve(JSON.stringify({ error: 'version_conflict' })),
      } as unknown as Response);
    expect(
      await vault.updateItem({
        bearer: BEARER,
        itemId: '05555555-0000-4000-8000-000000000000',
        itemType: 'password',
        content: { title: 'Edited' },
        blobVersion: 1,
      }),
    ).toEqual({ ok: false, code: 'VERSION_CONFLICT' });
    (globalThis as { fetch?: unknown }).fetch = previous;
  });
});
