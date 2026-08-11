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
import { installOffscreenListener } from '../src/offscreen-router';
import { forgetSecretKey, rememberSecretKey, rememberedSecretKey } from '../src/secret-key-store';
import { VaultHost, type KeyHolderPort } from '../src/vault-host';
import { listItems, lockVault, unlockVault, vaultState } from '../src/vault-client';
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
    summarise: () => Promise.resolve([{ id: 'i-1', itemType: 'login', title: 'Zed' }]),
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
      items: [{ id: 'i-1', itemType: 'login', title: 'Zed' }],
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

  it('returns items and the state on the happy paths', async () => {
    messaging((message) =>
      (message as { kind?: string }).kind === 'list'
        ? { ok: true, items: [{ id: 'i', itemType: 'login', title: 'A' }] }
        : { ok: true, state: { status: 'locked' } },
    );
    expect(await listItems('b')).toEqual({
      ok: true,
      data: [{ id: 'i', itemType: 'login', title: 'A' }],
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
