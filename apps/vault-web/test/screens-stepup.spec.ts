/**
 * @jest-environment jsdom
 */

/**
 * PROVING A FACTOR ON THIS ORIGIN, THROUGH THE REAL SCREENS (M15 review).
 *
 * Its OWN FILE, for two reasons that turned out to be the same reason. These
 * specs drive the real client, so every enrollment is a genuine PBKDF2 at 650k
 * iterations — the shipped parameter, deliberately not lowered, because a
 * test-only iteration count would put a seam into the one derivation Zone A
 * rests on. Adding two more full enrollments to `screens-actions.spec.ts`
 * roughly doubled that file\'s real crypto work.
 *
 * A separate file is also a separate module registry, so the vault session, the
 * device store and the rendered tree do not carry between these tests and those.
 * Both concerns, one move.
 *
 * CORRECTED, because this header previously claimed a cause it had not proved.
 * It said the CI failure was the advancing click "not arriving inside the
 * harness deadline" under contention, and that splitting the file cured it by
 * halving the work. Splitting did reduce the failure RATE; it did not remove the
 * cause, and the failure went on appearing on `main`. The real mechanism was a
 * stray THIRD enrollment started by this file\'s own step-up submission — see
 * `submitStepUp` below. Contention was what made it visible, not what made
 * it happen, and a deadline can never fix a screen that is being repainted.
 */
import 'fake-indexeddb/auto';
import {
  createServerEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  fromBase64,
  toBase64,
  verifyClientSession,
} from '@estate/vault-crypto';
import { render } from '../src/client/app';
import { forgetSecretKey } from '../src/client/secret-key-store';

const USER = '11111111-2222-4333-8444-555555555555';
const PASSWORD = 'a-good-vault-password';

interface Service {
  calls: Array<{ path: string; method: string; body: string; headers: Record<string, string> }>;
  items: Map<string, Record<string, unknown>>;
  fail: Map<string, { status: number; error: string }>;
  resets: number;
  keysetPuts: number;
}

function installService(): Service {
  const state: Service = {
    calls: [],
    items: new Map(),
    fail: new Map(),
    resets: 0,
    keysetPuts: 0,
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
    const headers = (init.headers ?? {}) as Record<string, string>;
    state.calls.push({ path, method, body, headers });

    const forced = state.fail.get(`${method} ${path.split('?')[0] as string}`);
    if (forced) {
      return Promise.resolve(reply(forced.status, { error: forced.error }));
    }

    if (path === '/api/auth/session') {
      return Promise.resolve(reply(200, { userId: USER, audience: 'vault' }));
    }
    if (path === '/api/auth/logout') return Promise.resolve(reply(200, { status: 'ok' }));
    if (path === '/api/vault/keyset' && method === 'GET') {
      return Promise.resolve(reply(200, { enrolled: keyset !== null, updatedAt: null }));
    }
    if (path === '/api/vault/keyset' && method === 'POST') {
      keyset = JSON.parse(body) as Record<string, string>;
      return Promise.resolve(reply(201, { enrolled: true, updatedAt: null }));
    }
    if (path === '/api/vault/keyset' && method === 'PUT') {
      state.keysetPuts += 1;
      keyset = JSON.parse(body) as Record<string, string>;
      return Promise.resolve(reply(200, { enrolled: true, updatedAt: null }));
    }
    if (path === '/api/vault/reset') {
      state.resets += 1;
      keyset = JSON.parse(body) as Record<string, string>;
      state.items.clear();
      return Promise.resolve(reply(200, { itemsDestroyed: 2 }));
    }
    if (path === '/api/vault/lock') return Promise.resolve(reply(204, null));
    if (path === '/api/vault/srp/start') {
      if (!keyset) return Promise.resolve(reply(404, { error: 'keyset_not_found' }));
      return createServerEphemeral(
        decodeGroupElement(keyset['srpVerifier'] as string, 'verifier'),
      ).then((made) => {
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
    if (path.startsWith('/api/vault/items') && method === 'PUT') {
      const id = path.split('/').pop() as string;
      const parsed = JSON.parse(body) as Record<string, unknown>;
      const existing = state.items.get(id) ?? {};
      const row = {
        ...existing,
        ...parsed,
        id,
        blobVersion: ((existing['blobVersion'] as number) ?? 1) + 1,
        updatedAt: '2026-08-09',
      };
      state.items.set(id, row);
      return Promise.resolve(reply(200, row));
    }
    if (path.startsWith('/api/vault/items') && method === 'DELETE') {
      state.items.delete(path.split('/').pop() as string);
      return Promise.resolve(reply(204, null));
    }
    if (path.startsWith('/api/vault/items') && method === 'GET') {
      return Promise.resolve(reply(200, { items: [...state.items.values()], nextCursor: null }));
    }
    return Promise.resolve(reply(200, {}));
  }) as unknown as typeof fetch;

  return state;
}

function mount(): void {
  const root = document.createElement('main');
  root.setAttribute('id', 'app');
  document.body.replaceChildren(root);
  window.ESTATE_APP_ORIGIN = 'http://localhost:3000';
}

const byLabel = (label: string): HTMLInputElement => {
  const id = [...document.querySelectorAll('label')]
    .find((l) => l.textContent?.includes(label))
    ?.getAttribute('for');
  const node = id ? document.getElementById(id) : null;
  if (!node) throw new Error(`no field labelled ${label}. Saw: ${document.body.textContent}`);
  return node as HTMLInputElement;
};

const clickText = (text: string): void => {
  const button = [...document.querySelectorAll('button')].find((b) =>
    b.textContent?.includes(text),
  );
  if (!button) throw new Error(`no button "${text}". Saw: ${document.body.textContent}`);
  button.click();
};

const submitForm = (index = 0): void => {
  const forms = document.querySelectorAll('form');
  forms[index]?.dispatchEvent(new Event('submit', { cancelable: true }));
};

/**
 * SUBMIT THE STEP-UP PROMPT BY THE FORM THAT OWNS ITS FIELD.
 *
 * The prompt renders into a `<div>` inside the form of the action it guards, so
 * the step-up form is NESTED — and the ancestor's `querySelector('#stepup-code')`
 * finds it too. Selecting "every form CONTAINING the field" therefore matched
 * both and submitted the guarded action a second time. In the setup case that
 * silently started a THIRD enrollment: a full PBKDF2 at 650k that nothing
 * awaits, whose `renderSecretKey` continuation repaints "Save your Secret Key"
 * over whatever screen is showing whenever it lands.
 *
 * On a fast machine it landed inside its own test and merely repainted a screen
 * already showing. On a loaded CI runner it outlived the test and repainted the
 * NEXT one's unlock screen, so `openVaultWithItem` waited out its full deadline
 * looking at the save screen it had already clicked past.
 *
 * `input.form` is the HTML form owner — the nearest ancestor form, which is the
 * prompt's own. One dispatch, one submission.
 */
const submitStepUp = (code = '123456'): void => {
  const input = document.getElementById('stepup-code') as HTMLInputElement | null;
  if (!input) throw new Error(`no step-up prompt. Saw: ${document.body.textContent}`);
  input.value = code;
  input.form?.dispatchEvent(new Event('submit', { cancelable: true }));
};

const waitForText = async (pattern: string | RegExp, deadlineMs = 30_000): Promise<void> => {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    const text = document.body.textContent ?? '';
    if (typeof pattern === 'string' ? text.includes(pattern) : pattern.test(text)) return;
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${String(pattern)}. Saw: ${text.slice(0, 500)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
};

/** Setup → acknowledge → unlock → an open vault with one item. */
async function openVaultWithItem(title = 'Bank — joint'): Promise<void> {
  await render();
  await waitForText('Set up your vault');
  byLabel('Vault password').value = PASSWORD;
  byLabel('Confirm vault password').value = PASSWORD;
  submitForm();
  await waitForText('Save your Secret Key');
  (document.getElementById('ack') as HTMLInputElement).checked = true;
  // Remembered, so the unlock screen needs only the password — which is also
  // the path most users take.
  clickText('I have saved it');
  await waitForText('Unlock your vault');

  byLabel('Vault password').value = PASSWORD;
  submitForm();
  await waitForText(/nothing here yet/i);

  clickText('Add an item');
  await waitForText('Add an item');
  byLabel('Title').value = title;
  byLabel('Password or secret').value = 'the-original-secret';
  submitForm();
  await waitForText(title);
}

describe('proving a factor on this origin', () => {
  jest.setTimeout(180_000);

  beforeEach(() => {
    mount();
  });

  afterEach(async () => {
    await forgetSecretKey(USER);
  });

  it('prompts for a factor on SETUP, the first gated action a new user meets', async () => {
    /*
     * Found by driving the live stack after removing the auto-granted step-up:
     * `POST /v1/vault/keyset` is step-up gated, so enrollment became the FIRST
     * place a factor must be proved on this origin — and it was not wired, so a
     * brand-new user was told "that action needs a fresh identity check" with no
     * way to give one. The fix is only complete if every gated action can ask.
     */
    const service = installService();
    service.fail.set('POST /api/vault/keyset', { status: 403, error: 'stepup_required' });
    await render();
    await waitForText('Set up your vault');
    byLabel('Vault password').value = PASSWORD;
    byLabel('Confirm vault password').value = PASSWORD;
    submitForm();

    await waitForText(/setting up your vault needs a fresh identity check/i);
    service.fail.delete('POST /api/vault/keyset');
    submitStepUp();
    await waitForText('Save your Secret Key');
    expect(service.calls.some((c) => c.path === '/api/auth/stepup')).toBe(true);
    /*
     * And the count is asserted, because that is what makes the trap above fail
     * DETERMINISTICALLY. A stray enrollment is invisible on a fast machine and
     * intermittent on a slow one; the number never varies. Two POSTs: the one
     * step-up refused, and the one the retry made.
     */
    expect(
      service.calls.filter((c) => c.path === '/api/vault/keyset' && c.method === 'POST'),
    ).toHaveLength(2);

    // Finish the flow. A test that stops mid-ceremony leaves this module — and
    // the device store behind it — in a state the NEXT test inherits, and these
    // specs share one module registry per file. Landing on the unlock screen is
    // where every other test here ends.
    (document.getElementById('ack') as HTMLInputElement).checked = true;
    clickText('I have saved it');
    await waitForText('Unlock your vault');
  });

  it('proves a factor ON THIS ORIGIN when reset is refused, then retries (M15 review)', async () => {
    /*
     * Redemption used to hand every vault session a step-up, which is what let
     * a stolen 60-second handoff code reach `POST /v1/vault/reset` — gated on
     * step-up alone, because a lost vault password cannot be proven. It grants
     * none now, so the gated action has to ask here. The old copy sent the user
     * back to Estate to re-open the vault, which would MINT A FRESH HANDOFF —
     * the credential the change exists to devalue.
     */
    const service = installService();
    await openVaultWithItem();
    clickText('Settings');
    await waitForText('Reset the vault');

    service.fail.set('POST /api/vault/reset', { status: 403, error: 'stepup_required' });
    byLabel('Password for the new empty vault').value = 'a-brand-new-vault-password';
    byLabel('Type DESTROY to confirm').value = 'DESTROY';
    clickText('Reset my vault permanently');

    await waitForText(/resetting the vault needs a fresh identity check/i);
    expect(document.body.textContent).not.toMatch(/open the vault again from estate/i);

    // Elevate, and the refused action runs again without being re-typed.
    service.fail.delete('POST /api/vault/reset');
    submitStepUp();
    await waitForText(/save your secret key/i);
    expect(service.resets).toBe(1);
    expect(service.calls.some((c) => c.method === 'POST' && c.path === '/api/auth/stepup')).toBe(
      true,
    );
  });
});
