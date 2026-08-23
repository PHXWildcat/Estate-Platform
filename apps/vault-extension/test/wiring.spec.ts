/**
 * The wiring between the popup, the service worker and the offscreen document.
 *
 * None of it holds a key, and that is most of what these cases assert: the
 * router answers only messages addressed to it, the client refuses to read a
 * non-answer as an answer, the service worker's only power is the offscreen
 * document's lifecycle, and the Secret Key store fails soft in every direction
 * that could otherwise lock somebody out.
 */
import 'fake-indexeddb/auto';
import { ensureOffscreenDocument } from '../src/offscreen-lifecycle';
import { isVaultRequest, VAULT_REQUEST_REQUIRED_FIELDS, type VaultRequest } from '../src/messages';
import { installOffscreenListener } from '../src/offscreen-router';
import { forgetSecretKey, rememberSecretKey, rememberedSecretKey } from '../src/secret-key-store';
import { VaultHost, type KeyHolderPort } from '../src/vault-host';
import {
  fillFor,
  listItems,
  lockVault,
  matchesFor,
  unlockVault,
  vaultState,
} from '../src/vault-client';
import { clearChromeDouble, installChromeDouble } from './chrome-double';

const USER = '11111111-2222-4333-8444-555555555555';

/** Install a chrome double without assigning to the const global. */
function defineChrome(value: unknown): void {
  Object.defineProperty(globalThis, 'chrome', { value, writable: true, configurable: true });
}

/** A holder that is simply open, so the router's shapes can be exercised. */
function openHolder(): KeyHolderPort {
  return {
    isUnlocked: true,
    prepare: () => Promise.resolve({ publicA: 'A', m1: 'M' }),
    finish: () => Promise.resolve(),
    summarise: () =>
      Promise.resolve([
        { id: 'i-1', itemType: 'password', title: 'Zed', blobVersion: 1, revision: 41 },
      ]),
    matchesFor: () =>
      Promise.resolve([
        {
          id: 'i-1',
          itemType: 'password',
          title: 'Zed',
          blobVersion: 1,
          revision: 41,
          verdict: { kind: 'match' as const, domain: 'example.com' },
        },
      ]),
    fillFor: (_rows, itemId) =>
      Promise.resolve(itemId === 'i-1' ? { username: 'someone', secret: 's3cret' } : null),
    sealItem: () => Promise.resolve('c2VhbGVk'),
    resealItem: () => Promise.resolve('cmVzZWFsZWQ='),
    lock: () => undefined,
  };
}

describe('the offscreen router', () => {
  afterEach(clearChromeDouble);

  function wire(holder: KeyHolderPort = openHolder()): {
    deliver: (message: unknown) => Promise<unknown>;
  } {
    const host = new VaultHost({ holder, setTimer: () => 1, clearTimer: () => undefined });
    let listener: Parameters<Parameters<typeof installOffscreenListener>[1]>[0] | null = null;
    installOffscreenListener(host, (l) => {
      listener = l;
    });
    return {
      deliver: (message) =>
        new Promise((resolve) => {
          const kept = (listener as NonNullable<typeof listener>)(message, null, resolve);
          // A listener that does not keep the channel open answers nothing.
          if (kept !== true) resolve(undefined);
        }),
    };
  }

  it('ignores a message addressed to anyone else', async () => {
    const { deliver } = wire();
    expect(await deliver({ target: 'background' })).toBeUndefined();
    expect(await deliver({ kind: 'state' })).toBeUndefined();
    expect(await deliver(null)).toBeUndefined();
    expect(await deliver('state')).toBeUndefined();
  });

  it('answers state without a key, and refuses a list while locked', async () => {
    const { deliver } = wire();
    // The holder says open, but no SRP has run, so the host has no session
    // token — and a read needs both.
    expect(await deliver({ target: 'offscreen', kind: 'state' })).toEqual({
      ok: true,
      state: { status: 'locked' },
    });
    expect(await deliver({ target: 'offscreen', kind: 'list', bearer: 'b' })).toEqual({
      ok: false,
      code: 'VAULT_LOCKED',
    });
  });

  it('routes a LIST through to opened titles once the vault is unlocked', async () => {
    // The popup's main read, end to end through the router: the host is given a
    // session by a completed unlock, and the router hands back titles only.
    installChromeDouble();
    const holder = openHolder();
    const host = new VaultHost({ holder, setTimer: () => 1, clearTimer: () => undefined });
    let listener: Parameters<Parameters<typeof installOffscreenListener>[1]>[0] | null = null;
    installOffscreenListener(host, (l) => {
      listener = l;
    });
    const deliver = (message: unknown): Promise<unknown> =>
      new Promise((resolve) => {
        (listener as NonNullable<typeof listener>)(message, null, resolve);
      });

    (globalThis as { fetch?: unknown }).fetch = (url: unknown) =>
      Promise.resolve({
        ok: true,
        status: String(url).includes('srp/start') ? 201 : 200,
        text: () =>
          Promise.resolve(
            String(url).includes('srp/start')
              ? JSON.stringify({ handshakeId: 'h', srpSalt: 's', kdfParams: {}, serverPublic: 'B' })
              : String(url).includes('srp/verify')
                ? JSON.stringify({
                    serverProof: 'p',
                    wrappedMasterKey: 'w',
                    vaultSession: { id: 'i', token: 't', expiresAt: '2099-01-01T00:00:00.000Z' },
                  })
                : JSON.stringify({ items: [] }),
          ),
      } as unknown as Response);

    expect(
      await deliver({
        target: 'offscreen',
        kind: 'unlock',
        userId: USER,
        password: 'p',
        secretKey: 's',
        bearer: 'b',
      }),
    ).toEqual({ ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } });

    expect(await deliver({ target: 'offscreen', kind: 'list', bearer: 'b' })).toEqual({
      ok: true,
      items: [{ id: 'i-1', itemType: 'password', title: 'Zed', blobVersion: 1, revision: 41 }],
    });
  });

  it('routes an unlock and reports the refusal code back', async () => {
    // The host has no transport here, so the SRP start fails — what is pinned
    // is that the router carries the CODE rather than flattening it, since the
    // popup's screens branch on it.
    (globalThis as { fetch?: unknown }).fetch = () => Promise.reject(new Error('offline'));
    installChromeDouble();
    const { deliver } = wire();
    expect(
      await deliver({
        target: 'offscreen',
        kind: 'unlock',
        userId: USER,
        password: 'p',
        secretKey: 's',
        bearer: 'b',
      }),
    ).toEqual({ ok: false, code: 'NETWORK' });
  });

  it('routes a MATCHES request and returns verdicts, never secrets', async () => {
    installChromeDouble();
    (globalThis as { fetch?: unknown }).fetch = (url: unknown) =>
      Promise.resolve({
        ok: true,
        status: String(url).includes('srp/start') ? 201 : 200,
        text: () =>
          Promise.resolve(
            String(url).includes('srp/start')
              ? JSON.stringify({ handshakeId: 'h', srpSalt: 's', kdfParams: {}, serverPublic: 'B' })
              : String(url).includes('srp/verify')
                ? JSON.stringify({
                    serverProof: 'p',
                    wrappedMasterKey: 'w',
                    vaultSession: { id: 'i', token: 't', expiresAt: '2099-01-01T00:00:00.000Z' },
                  })
                : JSON.stringify({ items: [] }),
          ),
      } as unknown as Response);
    const { deliver } = wire();
    await deliver({
      target: 'offscreen',
      kind: 'unlock',
      userId: USER,
      password: 'p',
      secretKey: 's',
      bearer: 'b',
    });
    const answer = await deliver({
      target: 'offscreen',
      kind: 'matches',
      bearer: 'b',
      pageUrl: 'https://example.com/',
    });
    expect(answer).toEqual({
      ok: true,
      matched: [
        {
          id: 'i-1',
          itemType: 'password',
          title: 'Zed',
          blobVersion: 1,
          revision: 41,
          verdict: { kind: 'match', domain: 'example.com' },
        },
      ],
    });
  });

  it('carries a lock through and reports the state back', async () => {
    const { deliver } = wire();
    expect(await deliver({ target: 'offscreen', kind: 'lock' })).toEqual({
      ok: true,
      state: { status: 'locked' },
    });
  });
});

describe('the popup’s view of the vault', () => {
  afterEach(clearChromeDouble);

  function messaging(reply: (message: unknown) => unknown): { sent: unknown[] } {
    const sent: unknown[] = [];
    const double = installChromeDouble();
    // `defineProperty` rather than an assignment: `chrome` is declared as a
    // const global (src/chrome.d.ts), which is the point — nothing in the
    // artifact may reassign it.
    defineChrome({
      ...(globalThis as { chrome?: Record<string, unknown> }).chrome,
      runtime: {
        getManifest: () => ({ host_permissions: ['https://vault.estate.test/*'] }),
        getURL: (p: string) => p,
        sendMessage: (message: unknown) => {
          sent.push(message);
          return Promise.resolve(reply(message));
        },
        onMessage: { addListener: () => undefined },
      },
    });
    void double;
    return { sent };
  }

  it('wakes the service worker BEFORE addressing the offscreen document', async () => {
    const { sent } = messaging(() => ({ ok: true, state: { status: 'locked' } }));
    await vaultState();
    // Only one offscreen document may exist and it is created on demand, so a
    // popup that addressed it first would race its own creation.
    expect((sent[0] as { target?: string }).target).toBe('background');
    expect((sent[1] as { target?: string }).target).toBe('offscreen');
  });

  it('treats a context that never answered as an OUTAGE, not a locked vault', async () => {
    // Telling somebody their vault is closed because a message went nowhere
    // would be a claim about their vault made on the strength of a failure.
    const { sent } = messaging(() => undefined);
    expect(await vaultState()).toEqual({ ok: false, code: 'UNAVAILABLE' });
    expect(sent).toHaveLength(2);
  });

  it('carries a refusal code through rather than flattening it', async () => {
    messaging(() => ({ ok: false, code: 'SRP_FAILED' }));
    expect(await unlockVault({ userId: USER, password: 'p', secretKey: 's', bearer: 'b' })).toEqual(
      { ok: false, code: 'SRP_FAILED' },
    );
  });

  it('carries matches back to the popup, and a refusal as a code', async () => {
    messaging((message) =>
      (message as { kind?: string }).kind === 'matches'
        ? {
            ok: true,
            matched: [
              {
                id: 'i',
                itemType: 'password',
                title: 'A',
                verdict: { kind: 'match', domain: 'example.com' },
              },
            ],
          }
        : { ok: true, state: { status: 'locked' } },
    );
    expect(await matchesFor('b', 'https://example.com/')).toEqual({
      ok: true,
      data: [
        {
          id: 'i',
          itemType: 'password',
          title: 'A',
          verdict: { kind: 'match', domain: 'example.com' },
        },
      ],
    });

    messaging(() => ({ ok: false, code: 'VAULT_LOCKED' }));
    expect(await matchesFor('b', 'https://example.com/')).toEqual({
      ok: false,
      code: 'VAULT_LOCKED',
    });
  });

  it('asks for a fill, and reads a refusal as null rather than as a failure', async () => {
    // Three outcomes, and the client must keep them apart: a credential, a
    // holder that declined, and a vault that is shut. Only the last is worth a
    // retry, and only the middle two mean the user did nothing wrong.
    messaging((message) =>
      (message as { itemId?: string }).itemId === 'i-1'
        ? { ok: true, credential: { username: 'someone', secret: 's3cret' } }
        : { ok: true, credential: null },
    );
    expect(await fillFor('b', 'i-1', 'https://example.com/')).toEqual({
      ok: true,
      data: { username: 'someone', secret: 's3cret' },
    });
    expect(await fillFor('b', 'other', 'https://example.com/')).toEqual({ ok: true, data: null });

    messaging(() => ({ ok: false, code: 'VAULT_LOCKED' }));
    expect(await fillFor('b', 'i-1', 'https://example.com/')).toEqual({
      ok: false,
      code: 'VAULT_LOCKED',
    });
  });

  it('returns items and the state on the happy paths', async () => {
    messaging((message) =>
      (message as { kind?: string }).kind === 'list'
        ? {
            ok: true,
            items: [{ id: 'i', itemType: 'password', title: 'A', blobVersion: 1, revision: 41 }],
          }
        : { ok: true, state: { status: 'locked' } },
    );
    expect(await listItems('b')).toEqual({
      ok: true,
      data: [{ id: 'i', itemType: 'password', title: 'A', blobVersion: 1, revision: 41 }],
    });
    expect(await lockVault('b')).toEqual({ ok: true, data: { status: 'locked' } });
  });

  it('reports a messaging exception as an outage too', async () => {
    installChromeDouble();
    defineChrome({
      runtime: {
        getManifest: () => ({ host_permissions: ['https://vault.estate.test/*'] }),
        sendMessage: () => Promise.reject(new Error('no receiving end')),
        onMessage: { addListener: () => undefined },
      },
    });
    expect(await vaultState()).toEqual({ ok: false, code: 'UNAVAILABLE' });
  });
});

describe('the service worker’s only power', () => {
  function offscreenDouble(exists: boolean, createFails = false) {
    const created: unknown[] = [];
    return {
      created,
      api: {
        offscreen: {
          hasDocument: () => Promise.resolve(exists),
          createDocument: (options: unknown) => {
            created.push(options);
            return createFails ? Promise.reject(new Error('already exists')) : Promise.resolve();
          },
          closeDocument: () => Promise.resolve(),
        },
      } as unknown as typeof chrome,
    };
  }

  it('creates the document once, declaring WORKERS', async () => {
    const { created, api } = offscreenDouble(false);
    await ensureOffscreenDocument(api);
    expect(created).toHaveLength(1);
    // The reason is TRUE: the document's whole job is to host the worker the
    // key lives in.
    expect((created[0] as { reasons: string[] }).reasons).toEqual(['WORKERS']);
    expect((created[0] as { url: string }).url).toBe('offscreen.html');
  });

  it('does nothing when one already exists', async () => {
    const { created, api } = offscreenDouble(true);
    await ensureOffscreenDocument(api);
    expect(created).toHaveLength(0);
  });

  it('tolerates losing the race to another context', async () => {
    // Two popups opening at once would otherwise both try, and only one
    // offscreen document may exist. A create that fails because one is already
    // there is success for this function's purpose.
    const { api } = offscreenDouble(false, true);
    await expect(ensureOffscreenDocument(api)).resolves.toBeUndefined();
  });
});

describe('the Secret Key store', () => {
  it('remembers and forgets, per account', async () => {
    const other = '22222222-2222-4333-8444-555555555555';
    await rememberSecretKey(USER, 'ES1-AAAA');
    await rememberSecretKey(other, 'ES1-BBBB');
    expect(await rememberedSecretKey(USER)).toBe('ES1-AAAA');
    expect(await rememberedSecretKey(other)).toBe('ES1-BBBB');

    await forgetSecretKey(USER);
    expect(await rememberedSecretKey(USER)).toBeNull();
    // A shared browser profile holds one key per account, so forgetting one
    // must not disturb another.
    expect(await rememberedSecretKey(other)).toBe('ES1-BBBB');
  });

  it('answers null for an account it has never seen', async () => {
    expect(await rememberedSecretKey('33333333-2222-4333-8444-555555555555')).toBeNull();
  });

  it('fails SOFT when the store itself is unavailable', async () => {
    // The failure this must never produce is a user locked out by a storage
    // quirk: a device that cannot reach its store should ask for the key, not
    // refuse to open the vault.
    const real = globalThis.indexedDB;
    (globalThis as { indexedDB?: unknown }).indexedDB = {
      open: () => {
        throw new Error('storage unavailable');
      },
    };
    try {
      expect(await rememberedSecretKey(USER)).toBeNull();
      await expect(rememberSecretKey(USER, 'ES1-CCCC')).resolves.toBeUndefined();
      await expect(forgetSecretKey(USER)).resolves.toBeUndefined();
    } finally {
      (globalThis as { indexedDB?: unknown }).indexedDB = real;
    }
  });
});

describe('the fill message', () => {
  afterEach(clearChromeDouble);

  /**
   * A stand-in HOST, not a stand-in holder.
   *
   * What is under test here is the ROUTER's mapping — that a credential crosses
   * as `credential` and that a refusal crosses as `null` rather than becoming an
   * error. The real host's own fill path (fetch the rows, ask the holder, and
   * refuse while locked) is exercised against real crypto in `vault-host.spec`,
   * so reproducing its unlock ceremony here would test that a second time and
   * this mapping not at all.
   */
  function routerOver(fillFor: VaultHost['fillFor']): (message: unknown) => Promise<unknown> {
    let listener: Parameters<Parameters<typeof installOffscreenListener>[1]>[0] | null = null;
    installOffscreenListener({ fillFor } as unknown as VaultHost, (l) => {
      listener = l;
    });
    return (message) =>
      new Promise((resolve) => {
        const kept = (listener as NonNullable<typeof listener>)(message, null, resolve);
        if (kept !== true) resolve(undefined);
      });
  }

  const FILL = {
    target: 'offscreen',
    kind: 'fill',
    bearer: 'b',
    itemId: 'i-1',
    pageUrl: 'https://example.com/',
  };

  it('carries a credential across as `credential`', async () => {
    const deliver = routerOver(() =>
      Promise.resolve({ ok: true, data: { username: 'someone', secret: 's3cret' } }),
    );
    expect(await deliver(FILL)).toEqual({
      ok: true,
      credential: { username: 'someone', secret: 's3cret' },
    });
  });

  it('carries a REFUSAL across as null, not as a failure', async () => {
    // The distinction the popup needs: "the holder declined" and "the vault is
    // shut" are different sentences, and only one of them is worth retrying.
    const deliver = routerOver(() => Promise.resolve({ ok: true, data: null }));
    expect(await deliver(FILL)).toEqual({ ok: true, credential: null });
  });

  it('carries a failure across as a code, with no credential field at all', async () => {
    const deliver = routerOver(() => Promise.resolve({ ok: false, code: 'VAULT_LOCKED' }));
    const answer = await deliver(FILL);
    expect(answer).toEqual({ ok: false, code: 'VAULT_LOCKED' });
    expect(Object.keys(answer as object)).not.toContain('credential');
  });

  it('is a kind the narrowing gate admits, so the router can ever see it', () => {
    // `isVaultRequest` carries a hardcoded list of kinds; a variant added to the
    // union and forgotten here is silently ignored rather than answered.
    expect(isVaultRequest(FILL)).toBe(true);
  });
});

describe('the popup to offscreen union is closed, exhaustively', () => {
  /**
   * THE OTHER HALF OF THE CAPABILITY SURFACE, and it had no such test.
   *
   * `worker-boundary.spec.ts` enumerates what may be asked of the KEY HOLDER;
   * this union is what may be asked of the OFFSCREEN HOST, and the same argument
   * applies to it — `messages.ts` says the union's closure is what keeps §4 TB9's
   * "the content script must be structurally unable to REQUEST a credential"
   * true. Until now only one variant was spot-checked against `isVaultRequest`.
   *
   * A `Record` keyed by the union, for the reason the worker one uses it: a
   * missing key is a compile error and an unknown key is a compile error, where
   * a literal array and a hand-counted length are both subset checks that a new
   * variant passes silently.
   *
   * `isVaultRequest` carries its OWN hardcoded list, so the two are pinned to
   * each other here — a kind in the union that the gate does not admit is a
   * message the router will never answer, which presents as a dead feature
   * rather than an error.
   */
  /**
   * A minimally VALID message of one kind, filled from the gate's own
   * required-field table. Built rather than hand-written so a newly required
   * field cannot leave this test asserting something weaker than it reads.
   */
  const sampleFor = (kind: string): Record<string, unknown> => {
    const message: Record<string, unknown> = { target: 'offscreen', kind };
    for (const [field, type] of Object.entries(VAULT_REQUEST_REQUIRED_FIELDS[kind] ?? {})) {
      message[field] = type === 'string' ? 'x' : type === 'number' ? 1 : {};
    }
    return message;
  };

  const KINDS: Record<VaultRequest['kind'], true> = {
    state: true,
    unlock: true,
    list: true,
    matches: true,
    fill: true,
    // ADDED IN PR4a. The same compile error that named `seal` at the worker
    // boundary named these here — two fences, one widening, both loud.
    create: true,
    update: true,
    lock: true,
  };

  it('names every kind, and the narrowing gate admits every one it names', () => {
    expect(Object.keys(KINDS).sort()).toEqual([
      'create',
      'fill',
      'list',
      'lock',
      'matches',
      'state',
      'unlock',
      'update',
    ]);
    for (const kind of Object.keys(KINDS)) {
      // Shape DOES matter to the gate as of M27 PR1a — it validates every
      // field the union requires, which is what makes `value is VaultRequest`
      // an honest claim rather than a promise about two properties. So the
      // sample is built from the gate's own required-field table, which
      // `messages-contract.spec.ts` independently proves equal to the union.
      expect({ kind, admitted: isVaultRequest(sampleFor(kind)) }).toEqual({
        kind,
        admitted: true,
      });
      // And the envelope ALONE is no longer enough, for every kind that
      // requires anything — the property the old version of this test could
      // not tell apart from the one above.
      const bare = isVaultRequest({ target: 'offscreen', kind });
      const requiresNothing = Object.keys(VAULT_REQUEST_REQUIRED_FIELDS[kind] ?? {}).length === 0;
      expect({ kind, bare }).toEqual({ kind, bare: requiresNothing });
    }
  });

  it('refuses a kind that is not in the union, and anything not addressed here', () => {
    expect(isVaultRequest({ target: 'offscreen', kind: 'getKey' })).toBe(false);
    expect(isVaultRequest({ target: 'background', kind: 'list' })).toBe(false);
  });
});

describe('the router answers a write (M16 PR4a)', () => {
  /** A router over a host stubbed for whichever write is under test. */
  function routerFor(host: Partial<VaultHost>): (message: unknown) => Promise<unknown> {
    let listener: Parameters<Parameters<typeof installOffscreenListener>[1]>[0] | null = null;
    installOffscreenListener(host as VaultHost, (l) => {
      listener = l;
    });
    return (message) =>
      new Promise((resolve) => {
        const kept = (listener as NonNullable<typeof listener>)(message, null, resolve);
        if (kept !== true) resolve(undefined);
      });
  }

  const CREATE = {
    target: 'offscreen' as const,
    kind: 'create' as const,
    bearer: 'b',
    itemType: 'password',
    content: { title: 'Typed' },
  };
  const UPDATE = {
    target: 'offscreen' as const,
    kind: 'update' as const,
    bearer: 'b',
    itemId: 'i-1',
    itemType: 'password',
    // `changes`, NOT `content` — this fixture said `content` until M27 PR1a,
    // and the router has always read `message.changes`. It went unnoticed
    // because the narrowing gate checked `target` and `kind` and vouched for
    // the rest, so an update whose payload the real popup never sends passed
    // through it. The gate validates fields now, and this is what it caught.
    changes: { title: 'Edited' },
    blobVersion: 2,
    revision: 42,
  };

  it('carries a created item back, and a refusal back as a code', async () => {
    const made = { id: 'i-9', itemType: 'password', title: 'Typed', blobVersion: 1, revision: 41 };
    const ok = routerFor({ createItem: () => Promise.resolve({ ok: true, data: made }) });
    expect(await ok(CREATE)).toEqual({ ok: true, item: made });

    const refused = routerFor({
      createItem: () => Promise.resolve({ ok: false, code: 'VAULT_LOCKED' }),
    });
    expect(await refused(CREATE)).toEqual({ ok: false, code: 'VAULT_LOCKED' });
  });

  it('carries an updated item back, and a version conflict as its own code', async () => {
    const saved = {
      id: 'i-1',
      itemType: 'password',
      title: 'Edited',
      blobVersion: 3,
      revision: 43,
    };
    const ok = routerFor({ updateItem: () => Promise.resolve({ ok: true, data: saved }) });
    expect(await ok(UPDATE)).toEqual({ ok: true, item: saved });

    const stale = routerFor({
      updateItem: () => Promise.resolve({ ok: false, code: 'VERSION_CONFLICT' }),
    });
    expect(await stale(UPDATE)).toEqual({ ok: false, code: 'VERSION_CONFLICT' });
  });

  it('admits both kinds at the narrowing gate', () => {
    expect(isVaultRequest(CREATE)).toBe(true);
    expect(isVaultRequest(UPDATE)).toBe(true);
  });
});
