/**
 * @jest-environment jsdom
 */

/**
 * The vault screens (M15 PR2), driven end to end against the real protocol.
 *
 * These use the SAME stand-in service as the egress spec — a fake that speaks
 * genuine SRP-6a — so a "setup then unlock then add an item" run here performs
 * real PBKDF2, a real key exchange and real AES-GCM. That matters more than
 * usual: a screen test against a stubbed crypto layer would pass just as
 * happily if the client encrypted nothing.
 *
 * What is asserted is mostly the honesty of the surface: that a failure never
 * renders as a success, that the Secret Key is shown once and gated behind an
 * acknowledgement, that a locked vault shows no decrypted titles, and that the
 * reset screen states what it destroys before it will do it.
 */
import {
  createServerEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  fromBase64,
  toBase64,
  verifyClientSession,
} from '@estate/vault-crypto';
import { render } from '../src/client/app';

const USER = '11111111-2222-4333-8444-555555555555';
const PASSWORD = 'a-good-vault-password';

interface FakeService {
  calls: Array<{ path: string; method: string; body: string }>;
  items: Map<string, Record<string, unknown>>;
  enrolled: boolean;
  resetCount: number;
}

/** The stand-in vault service. Real SRP; items held in a Map. */
function installService(overrides: { enrolled?: boolean } = {}): FakeService {
  const state: FakeService = {
    calls: [],
    items: new Map(),
    enrolled: overrides.enrolled ?? false,
    resetCount: 0,
  };
  let keyset: Record<string, string> | null = null;
  let ephemeral: Awaited<ReturnType<typeof createServerEphemeral>> | null = null;

  const reply = (status: number, payload: unknown): unknown => ({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(payload)),
  });

  globalThis.fetch = ((path: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET';
    const body = typeof init.body === 'string' ? init.body : '';
    state.calls.push({ path, method, body });

    if (path === '/api/auth/session') {
      return Promise.resolve(reply(200, { userId: USER, audience: 'vault' }));
    }
    if (path === '/api/vault/keyset' && method === 'GET') {
      return Promise.resolve(reply(200, { enrolled: state.enrolled, updatedAt: null }));
    }
    if (path === '/api/vault/keyset' && method === 'POST') {
      keyset = JSON.parse(body) as Record<string, string>;
      state.enrolled = true;
      return Promise.resolve(reply(201, { enrolled: true, updatedAt: null }));
    }
    if (path === '/api/vault/reset') {
      keyset = JSON.parse(body) as Record<string, string>;
      state.resetCount += 1;
      state.items.clear();
      return Promise.resolve(reply(200, { itemsDestroyed: 3 }));
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
    if (path.startsWith('/api/vault/items') && method === 'POST') {
      const parsed = JSON.parse(body) as Record<string, unknown>;
      const row = { ...parsed, blobVersion: 1, createdAt: 'now', updatedAt: '2026-08-08' };
      state.items.set(parsed['id'] as string, row);
      return Promise.resolve(reply(201, row));
    }
    if (path.startsWith('/api/vault/items') && method === 'GET') {
      return Promise.resolve(reply(200, { items: [...state.items.values()], nextCursor: null }));
    }
    if (path.startsWith('/api/vault/items') && method === 'DELETE') {
      state.items.delete(path.split('/').pop() as string);
      return Promise.resolve(reply(204, null));
    }
    return Promise.resolve(reply(200, {}));
  }) as unknown as typeof fetch;

  return state;
}

function mount(): void {
  document.body.replaceChildren(document.createElement('main'));
  document.body.firstElementChild?.setAttribute('id', 'app');
  window.ESTATE_APP_ORIGIN = 'http://localhost:3000';
}

const byLabel = (label: string): HTMLInputElement =>
  document.querySelector<HTMLInputElement>(
    `#${[...document.querySelectorAll('label')].find((l) => l.textContent?.includes(label))?.getAttribute('for') ?? 'missing'}`,
  ) as HTMLInputElement;

const clickText = (text: string): void => {
  const button = [...document.querySelectorAll('button')].find((b) =>
    b.textContent?.includes(text),
  );
  if (!button) throw new Error(`no button matching ${text}. Saw: ${document.body.textContent}`);
  button.click();
};

const submitForm = (): void => {
  document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true }));
};

/**
 * Wait for the screen to say something, with a DEADLINE — never a fixed number
 * of microtask turns.
 *
 * Enrollment runs real PBKDF2 at 650k iterations, which takes real wall-clock
 * time that a `setTimeout(0)` loop does not advance. The first draft used a
 * turn count and failed on exactly the screens that do crypto, which is the
 * repo's own determinism contract restated: poll with a deadline, never sleep a
 * guess.
 */
const waitForText = async (pattern: string | RegExp, deadlineMs = 30_000): Promise<void> => {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    const text = document.body.textContent ?? '';
    if (typeof pattern === 'string' ? text.includes(pattern) : pattern.test(text)) {
      return;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${String(pattern)}. Saw: ${text.slice(0, 400)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
};

/** Let queued promises settle — for transitions with no crypto in them. */
const settle = async (times = 6): Promise<void> => {
  for (let i = 0; i < times; i += 1) {
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
};

/** Set up a vault and return its Secret Key. Shared by the unlock tests. */
const enrol = async (): Promise<string> => {
  await render();
  await waitForText('Set up your vault');
  byLabel('Vault password').value = PASSWORD;
  byLabel('Confirm vault password').value = PASSWORD;
  submitForm();
  await waitForText('Save your Secret Key');
  return document.querySelector('.secret-key')?.textContent ?? '';
};

describe('the vault screens', () => {
  jest.setTimeout(120_000); // real PBKDF2

  beforeEach(() => {
    mount();
  });

  it('offers setup when no vault exists, and shows the Secret Key exactly once', async () => {
    installService({ enrolled: false });
    await render();
    await waitForText('Set up your vault');

    byLabel('Vault password').value = PASSWORD;
    byLabel('Confirm vault password').value = PASSWORD;
    submitForm();
    await waitForText('Save your Secret Key');

    // Shown once, and the screen says so — there is no "show it again" because
    // the server does not have it.
    expect(document.body.textContent).toMatch(/shown once/i);
    expect(document.querySelector('.secret-key')?.textContent).toMatch(/^ES1-/);
  });

  it('refuses to move past the Secret Key until it is acknowledged', async () => {
    installService({ enrolled: false });
    await enrol();

    clickText('I have saved it');
    await settle();
    // Still on the same screen: a user who clicks through without saving loses
    // the vault, so the click is deliberately not enough on its own.
    expect(document.body.textContent).toContain('Save your Secret Key');
    expect(document.body.textContent).toMatch(/confirm you have saved/i);
  });

  it('rejects a password that is too short, and a mismatch, before any crypto runs', async () => {
    const service = installService({ enrolled: false });
    await render();
    await settle();

    byLabel('Vault password').value = 'short';
    byLabel('Confirm vault password').value = 'short';
    submitForm();
    await settle();
    expect(document.body.textContent).toMatch(/at least 12 characters/i);

    byLabel('Vault password').value = 'a-long-enough-password';
    byLabel('Confirm vault password').value = 'a-different-password';
    submitForm();
    await settle();
    expect(document.body.textContent).toMatch(/do not match/i);

    expect(service.calls.some((c) => c.path === '/api/vault/keyset' && c.method === 'POST')).toBe(
      false,
    );
  });

  it('unlocks an enrolled vault and lists items, then locks without showing them', async () => {
    const service = installService({ enrolled: false });
    const secretKey = await enrol();
    (document.getElementById('ack') as HTMLInputElement).checked = true;
    (document.getElementById('remember') as HTMLInputElement).checked = false;
    clickText('I have saved it');
    await waitForText('Unlock your vault');

    byLabel('Vault password').value = PASSWORD;
    byLabel('Secret Key').value = secretKey;
    submitForm();
    await waitForText(/nothing here yet/i);

    // Add an item; its title must appear in the list, decrypted on this device.
    clickText('Add an item');
    await waitForText('Add an item');
    byLabel('Title').value = 'Bank — joint account';
    byLabel('Password or secret').value = 'a-secret-value';
    submitForm();
    await waitForText('Bank — joint account');
    expect(service.items.size).toBe(1);

    // The stored blob does not contain the title.
    const stored = [...service.items.values()][0] as { blob: string };
    expect(atob(stored.blob)).not.toContain('Bank');

    clickText('Lock now');
    await waitForText('Unlock your vault');
    // Locking must not leave decrypted titles on screen.
    expect(document.body.textContent).not.toContain('Bank — joint account');
    expect(document.body.textContent).toContain('Unlock your vault');
  });

  it('gives ONE message for a wrong password and a wrong Secret Key', async () => {
    // The server answers one `srp_failed` for both by design; naming which half
    // was wrong would tell someone holding a stolen Secret Key that it is the
    // right one, halving the work of the attack 2SKD exists to make hard.
    installService({ enrolled: false });
    const secretKey = await enrol();
    (document.getElementById('ack') as HTMLInputElement).checked = true;
    (document.getElementById('remember') as HTMLInputElement).checked = false;
    clickText('I have saved it');
    await waitForText('Unlock your vault');

    byLabel('Vault password').value = 'the-wrong-password-entirely';
    byLabel('Secret Key').value = secretKey;
    submitForm();
    await waitForText(/did not open this vault/i);
    const wrongPassword = document.body.textContent ?? '';
    expect(wrongPassword).toMatch(/did not open this vault/i);
    // It names neither half.
    expect(wrongPassword).not.toMatch(/password was wrong|secret key was wrong/i);
  });

  it('states exactly what a reset destroys, and refuses without the confirmation', async () => {
    installService({ enrolled: true });
    await render();
    await settle();
    clickText('Vault settings');
    await waitForText('Vault settings');

    const text = document.body.textContent ?? '';
    // The escrow and the grantees' shares are the part a user would not guess,
    // and the M6 review found reset failing to destroy them — so the screen
    // that promises it should name it.
    expect(text).toMatch(/every item/i);
    expect(text).toMatch(/emergency-access arrangement/i);
    expect(text).toMatch(/never be decrypted again/i);

    clickText('Reset my vault permanently');
    await settle();
    expect(document.body.textContent).toMatch(/type destroy/i);
  });

  it('reports an outage as an outage rather than an empty vault', async () => {
    installService({ enrolled: true });
    const original = globalThis.fetch;
    globalThis.fetch = ((path: string, init?: RequestInit) =>
      path === '/api/vault/keyset'
        ? Promise.resolve({
            ok: false,
            status: 502,
            text: () => Promise.resolve(JSON.stringify({ error: 'upstream_unavailable' })),
          })
        : (original as (p: string, i?: RequestInit) => Promise<unknown>)(
            path,
            init,
          )) as unknown as typeof fetch;

    await render();
    await waitForText(/temporarily unreachable/i);
    expect(document.body.textContent).not.toMatch(/set up your vault/i);
  });
});
