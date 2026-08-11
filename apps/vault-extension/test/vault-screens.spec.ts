/**
 * The vault half of the popup.
 *
 * What is worth pinning is which SCREEN a given outcome produces — the step-up
 * is an expected step rather than an error, a wrong password must not read as a
 * lost pairing, and the Secret Key is remembered only after one has actually
 * opened the vault.
 */
import 'fake-indexeddb/auto';
import { messages } from '../src/copy';
import { rememberedSecretKey, rememberSecretKey } from '../src/secret-key-store';
import { mountVaultScreens } from '../src/vault-screens';
import { TEST_ORIGIN } from './chrome-double';

const USER = '11111111-2222-4333-8444-555555555555';
const BEARER = 'extension-access-token';

interface Wired {
  sent: unknown[];
  fetched: { url: string; body: string }[];
}

/**
 * A chrome double whose `sendMessage` is scripted per message kind, plus a
 * `fetch` for the one call this module makes directly (the step-up).
 */
function wire(
  reply: (message: { kind?: string }) => unknown,
  fetchStatus: { status: number; body?: unknown } = { status: 200 },
): Wired {
  const sent: unknown[] = [];
  const fetched: { url: string; body: string }[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: {
      getManifest: () => ({ host_permissions: [`${TEST_ORIGIN}/*`] }),
      getURL: (p: string) => p,
      sendMessage: (message: unknown) => {
        sent.push(message);
        return Promise.resolve(reply(message as { kind?: string }));
      },
      onMessage: { addListener: () => undefined },
    },
  };
  (globalThis as { fetch?: unknown }).fetch = (url: unknown, init: RequestInit) => {
    fetched.push({ url: String(url), body: typeof init.body === 'string' ? init.body : '' });
    return Promise.resolve({
      ok: fetchStatus.status >= 200 && fetchStatus.status < 300,
      status: fetchStatus.status,
      text: () => Promise.resolve(JSON.stringify(fetchStatus.body ?? {})),
    } as unknown as Response);
  };
  return { sent, fetched };
}

function host(): HTMLElement {
  document.body.replaceChildren();
  const node = document.createElement('div');
  document.body.append(node);
  return node;
}

/**
 * WAIT FOR THE CONDITION, DO NOT RACE IT.
 *
 * A fixed tick was enough until the unlock path grew an IndexedDB write between
 * the reply and the redraw, and then it was intermittently one macrotask short
 * — the same shape as the `StepUpPrompt` flake earlier in this milestone, where
 * a test assumed a teardown had happened instead of waiting for it. Polling to
 * a deadline states the precondition rather than assuming it.
 */
async function until(predicate: () => boolean, what: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(`timed out waiting for ${what}; screen was: ${text()}`);
}

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));
const text = (): string => document.body.textContent ?? '';
const button = (name: RegExp): HTMLButtonElement => {
  const found = [...document.querySelectorAll('button')].find((b) =>
    name.test(b.textContent ?? ''),
  );
  if (!found) throw new Error(`no button matching ${String(name)} in: ${text()}`);
  return found;
};

const LOCKED = { ok: true, state: { status: 'locked' } };

describe('the vault screens', () => {
  afterEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  it('offers an unlock form when the vault is locked', async () => {
    wire(() => LOCKED);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });

    expect(text()).toContain('Vault locked');
    expect(document.querySelector('#vault-password')).not.toBeNull();
    expect(document.querySelector('#secret-key')).not.toBeNull();
    // The cost of remembering is stated next to the choice, not implied.
    expect(text()).toContain('can read a remembered Secret Key');
  });

  it('opens, lists what is inside, and remembers the Secret Key only after it worked', async () => {
    wire((message) =>
      message.kind === 'unlock'
        ? { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } }
        : message.kind === 'list'
          ? { ok: true, items: [{ id: 'i-1', itemType: 'login', title: 'Bank login' }] }
          : LOCKED,
    );
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });

    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    (document.querySelector('#remember') as HTMLInputElement).checked = true;
    button(/Open vault/).click();
    await until(() => text().includes('Vault open'), 'the vault to open');

    expect(text()).toContain('Bank login');
    expect(await rememberedSecretKey(USER)).toBe('ES1-GOOD');
  });

  it('does NOT remember a Secret Key that failed to open the vault', async () => {
    // A typo persisted as the device's key would break every later unlock and
    // look like a corrupted device rather than a mistake.
    await rememberSecretKey(USER, 'ES1-PREVIOUS');
    wire((message) => (message.kind === 'unlock' ? { ok: false, code: 'SRP_FAILED' } : LOCKED));
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });

    (document.querySelector('#vault-password') as HTMLInputElement).value = 'wrong';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-TYPO';
    button(/Open vault/).click();
    await until(() => text().includes(messages.SRP_FAILED), 'the refusal');

    expect(await rememberedSecretKey(USER)).toBe('ES1-PREVIOUS');
  });

  it('treats a required step-up as a STEP, not a failure', async () => {
    // Both SRP legs are step-up gated, so this is the expected path — and it is
    // answered in place rather than by sending the user back to Estate, which
    // would mean re-pairing.
    const { fetched } = wire(
      (message) => (message.kind === 'unlock' ? { ok: false, code: 'STEPUP_REQUIRED' } : LOCKED),
      { status: 200 },
    );
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    button(/Open vault/).click();
    await settle();

    expect(text()).toContain('Confirm it’s you');
    (document.querySelector('#stepup-code') as HTMLInputElement).value = '123456';
    button(/Confirm/).click();
    await settle();

    expect(fetched[0]?.url).toBe(`${TEST_ORIGIN}/api/auth/stepup`);
    expect(JSON.parse(fetched[0]?.body ?? '{}')).toEqual({ code: '123456' });
    // Back to the unlock form, ready to retry.
    expect(text()).toContain('Vault locked');
  });

  it('refuses a malformed code before spending an attempt', async () => {
    const { fetched } = wire((message) =>
      message.kind === 'unlock' ? { ok: false, code: 'STEPUP_REQUIRED' } : LOCKED,
    );
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    button(/Open vault/).click();
    await settle();

    (document.querySelector('#stepup-code') as HTMLInputElement).value = '12ab';
    button(/Confirm/).click();
    await settle();

    expect(text()).toContain('Enter the six digits.');
    expect(fetched).toHaveLength(0);
  });

  it('names the CODE when a step-up is refused, never a password', async () => {
    // identity answers `invalid_credentials` for a rejected TOTP code exactly
    // as for a rejected password — the M12 defect, on a form with neither.
    const { fetched } = wire(
      (message) => (message.kind === 'unlock' ? { ok: false, code: 'STEPUP_REQUIRED' } : LOCKED),
      { status: 401, body: { error: 'unauthorized' } },
    );
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    button(/Open vault/).click();
    await settle();
    (document.querySelector('#stepup-code') as HTMLInputElement).value = '123456';
    button(/Confirm/).click();
    await settle();

    expect(fetched).toHaveLength(1);
    expect(text()).toContain('Codes last about 30 seconds');
    expect(text()).not.toContain('email and password');
  });

  it('locks on request, and comes back to the unlock form', async () => {
    wire((message) =>
      message.kind === 'list'
        ? { ok: true, items: [] }
        : message.kind === 'lock'
          ? LOCKED
          : { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } },
    );
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    expect(text()).toContain('Vault open');
    expect(text()).toContain('No items in this vault yet.');

    button(/Lock/).click();
    await settle();
    expect(text()).toContain('Vault locked');
  });

  it('shows an unreadable item as present rather than hiding it', async () => {
    wire((message) =>
      message.kind === 'list'
        ? { ok: true, items: [{ id: 'i', itemType: 'login', title: '', unreadable: true }] }
        : { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } },
    );
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    expect(text()).toContain('could not be read');
  });

  it('renders an item title as TEXT, whatever it contains', async () => {
    wire((message) =>
      message.kind === 'list'
        ? { ok: true, items: [{ id: 'i', itemType: 'login', title: '<img src=x onerror=1>' }] }
        : { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } },
    );
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    expect(document.querySelector('img')).toBeNull();
    expect(text()).toContain('<img src=x onerror=1>');
  });

  it('an unreachable offscreen document offers the unlock form, with the reason', async () => {
    // Not a dead end: the only thing this screen can offer is an unlock, so it
    // shows the form and attaches why the state read failed.
    wire(() => undefined);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    expect(text()).toContain('Vault locked');
    expect(text()).toContain(messages.UNAVAILABLE);
  });
});
