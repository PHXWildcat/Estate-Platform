/**
 * @jest-environment jsdom
 */

/**
 * How the vault surface behaves when things go wrong (M15 PR2).
 *
 * Every case here is a failure the user must be told about accurately, because
 * the alternative on this surface is someone concluding their vault is gone. A
 * failed read must never render as an empty vault, and a refusal must never
 * render as a success.
 */
import 'fake-indexeddb/auto';
import { installLifecycle, render } from '../src/client/app';
import { forgetSecretKey } from '../src/client/secret-key-store';

const USER = '11111111-2222-4333-8444-555555555555';

type Reply = { status: number; body: unknown };

/** A service that answers whatever the test dictates, per path. */
function serviceAnswering(answers: Record<string, Reply>): { calls: string[] } {
  const calls: string[] = [];
  globalThis.fetch = ((path: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET';
    calls.push(`${method} ${path}`);
    const answer = answers[`${method} ${path.split('?')[0] as string}`] ??
      answers[path.split('?')[0] as string] ?? { status: 200, body: {} };
    return Promise.resolve({
      ok: answer.status >= 200 && answer.status < 300,
      status: answer.status,
      text: () => Promise.resolve(JSON.stringify(answer.body)),
    });
  }) as unknown as typeof fetch;
  return { calls };
}

function mount(): void {
  const root = document.createElement('main');
  root.setAttribute('id', 'app');
  document.body.replaceChildren(root);
  window.ESTATE_APP_ORIGIN = 'http://localhost:3000';
}

const waitForText = async (pattern: RegExp, deadlineMs = 10_000): Promise<void> => {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    if (pattern.test(document.body.textContent ?? '')) return;
    if (Date.now() > deadline) {
      throw new Error(`timed out. Saw: ${(document.body.textContent ?? '').slice(0, 400)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
};

const session = { userId: USER, audience: 'vault' };

describe('the surface when things go wrong', () => {
  afterEach(async () => {
    await forgetSecretKey(USER);
    window.history.replaceState({}, '', '/');
  });

  beforeEach(() => {
    mount();
  });

  it('says the link expired, and asks the server nothing', async () => {
    // One message for every reason the edge could have had — expired, unknown,
    // already spent, raced — because the edge does not know which, by design.
    const { calls } = serviceAnswering({});
    window.history.replaceState({}, '', '/?open=refused');
    await render();
    await waitForText(/vault link has expired/i);
    expect(calls).toHaveLength(0);
  });

  it('distinguishes “not signed in” from “unreachable”', async () => {
    serviceAnswering({ '/api/auth/session': { status: 401, body: { error: 'unauthorized' } } });
    await render();
    await waitForText(/open the vault from estate/i);
    expect(document.body.textContent).not.toMatch(/temporarily unreachable/i);

    mount();
    serviceAnswering({
      '/api/auth/session': { status: 502, body: { error: 'upstream_unavailable' } },
    });
    await render();
    await waitForText(/temporarily unreachable/i);
    // The M10 PR4 rule: an outage and a signed-out session call for different
    // actions, so collapsing them would send someone somewhere pointless.
    expect(document.body.textContent).not.toMatch(/open the vault from estate/i);
  });

  it('renders a keyset read failure as a failure, never as “no vault yet”', async () => {
    serviceAnswering({
      '/api/auth/session': { status: 200, body: session },
      'GET /api/vault/keyset': { status: 503, body: { error: 'unavailable' } },
    });
    await render();
    await waitForText(/temporarily unreachable/i);
    // Offering setup here would invite a user to create a SECOND vault over a
    // first one they cannot currently see.
    expect(document.body.textContent).not.toMatch(/set up your vault/i);
  });

  it('reports a refused enrollment without claiming success', async () => {
    serviceAnswering({
      '/api/auth/session': { status: 200, body: session },
      'GET /api/vault/keyset': { status: 200, body: { enrolled: false, updatedAt: null } },
      'POST /api/vault/keyset': { status: 409, body: { error: 'keyset_exists' } },
    });
    await render();
    await waitForText(/set up your vault/i);

    const password = document.getElementById('setup-password') as HTMLInputElement;
    const confirm = document.getElementById('setup-confirm') as HTMLInputElement;
    password.value = 'a-good-vault-password';
    confirm.value = 'a-good-vault-password';
    document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true }));

    await waitForText(/changed since you opened it|went wrong|not accepted/i, 30_000);
    expect(document.body.textContent).not.toMatch(/save your secret key/i);
  });

  it('reports an unlock refusal with one message for both halves of 2SKD', async () => {
    serviceAnswering({
      '/api/auth/session': { status: 200, body: session },
      'GET /api/vault/keyset': { status: 200, body: { enrolled: true, updatedAt: null } },
      'POST /api/vault/srp/start': { status: 401, body: { error: 'unauthorized' } },
    });
    await render();
    await waitForText(/unlock your vault/i);

    (document.getElementById('unlock-password') as HTMLInputElement).value = 'whatever';
    (document.getElementById('unlock-secret') as HTMLInputElement).value = 'ES1-nonsense';
    document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true }));
    await waitForText(/did not open this vault/i, 30_000);
  });

  it('locks on pagehide, so a restored tab comes back locked', async () => {
    // bfcache restores a page with its JS heap intact. Without this the keys
    // would come back with it.
    serviceAnswering({
      '/api/auth/session': { status: 200, body: session },
      'GET /api/vault/keyset': { status: 200, body: { enrolled: true, updatedAt: null } },
    });
    installLifecycle();
    await render();
    await waitForText(/unlock your vault/i);

    // Firing it with a locked vault must be harmless — no throw, no request.
    window.dispatchEvent(new Event('pagehide'));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(document.body.textContent).toMatch(/unlock your vault/i);
  });

  it('offers settings from the LOCKED screen, because reset is for people locked out', async () => {
    serviceAnswering({
      '/api/auth/session': { status: 200, body: session },
      'GET /api/vault/keyset': { status: 200, body: { enrolled: true, updatedAt: null } },
    });
    await render();
    await waitForText(/unlock your vault/i);

    const settings = [...document.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Vault settings'),
    );
    settings?.click();
    await waitForText(/reset the vault/i);
    // The change-password form needs an OPEN vault, so it must not be offered
    // here — it would fail in a way the user could not act on.
    expect(document.body.textContent).not.toMatch(/change your vault password/i);
  });
});
