/**
 * @jest-environment jsdom
 */

/**
 * The vault's destructive and key-changing actions (M15 PR2).
 *
 * Split from `screens.spec.ts` because these are the ones where a mistake costs
 * a user their data rather than a page render: editing under optimistic
 * concurrency, deleting behind step-up, changing the password (which needs the
 * SRP-derived proof), and the reset that is a crypto-shred.
 */
import 'fake-indexeddb/auto';
import {
  createServerEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  fromBase64,
  formatSecretKey,
  generateSecretKey,
  toBase64,
  verifyClientSession,
} from '@estate/vault-crypto';
import { render } from '../src/client/app';
import { forgetSecretKey, recallSecretKey } from '../src/client/secret-key-store';

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

describe('the vault’s actions', () => {
  jest.setTimeout(180_000);

  beforeEach(() => {
    mount();
  });

  afterEach(async () => {
    await forgetSecretKey(USER);
  });

  it('remembers the Secret Key when asked, so unlock needs only the password', async () => {
    installService();
    await openVaultWithItem();
    expect(await recallSecretKey(USER)).not.toBeNull();
  });

  it('edits an item and sends If-Match with the version it read', async () => {
    // Optimistic concurrency: the new blob is bound by AAD to version N+1 and
    // If-Match carries N, so a server storing it anywhere else produces an item
    // that no longer decrypts. That is the anti-rollback property.
    const service = installService();
    await openVaultWithItem();

    clickText('Bank — joint');
    await waitForText('Edit item');
    byLabel('Title').value = 'Bank — renamed';
    submitForm();
    await waitForText('Bank — renamed');

    const put = service.calls.find((c) => c.method === 'PUT' && c.path.includes('/items/'));
    expect(put?.headers['if-match']).toBe('1');
    // And the ciphertext still carries none of the title.
    const payload = JSON.parse(put?.body ?? '{}') as { blob?: string };
    expect(payload.blob).toEqual(expect.any(String));
    expect(atob(payload.blob ?? '')).not.toContain('renamed');
  });

  it('deletes an item, and says what to do when step-up is required', async () => {
    const service = installService();
    await openVaultWithItem();

    clickText('Bank — joint');
    await waitForText('Edit item');
    service.fail.set('DELETE /api/vault/items/' + [...service.items.keys()][0], {
      status: 403,
      error: 'stepup_required',
    });
    clickText('Delete this item');
    await waitForText(/fresh identity check/i);
    // Still there — the refusal did not pretend to succeed.
    expect(service.items.size).toBe(1);
    // The prompt is a `<form>` and it is hosted next to the item form, never
    // inside it: nested forms are invalid HTML, and while this one WAS nested
    // it made `querySelectorAll('form')` ambiguous about which form holds the
    // code field — see `screens-stepup.spec.ts` for what that cost.
    expect(document.querySelectorAll('form form')).toHaveLength(0);
    expect((document.getElementById('stepup-code') as HTMLInputElement).form).not.toBe(
      document.querySelectorAll('form')[0],
    );

    service.fail.clear();
    clickText('Delete this item');
    await waitForText(/nothing here yet/i);
    expect(service.items.size).toBe(0);
  });

  it('generates a password into the field, and copies with a stated auto-clear', async () => {
    const written: string[] = [];
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: (t: string) => {
          written.push(t);
          return Promise.resolve();
        },
      },
      configurable: true,
    });
    installService();
    await openVaultWithItem();

    clickText('Add an item');
    await waitForText('Add an item');
    clickText('Generate');
    await waitForText(/bits of entropy/i);
    const generated = byLabel('Password or secret').value;
    expect(generated.length).toBeGreaterThanOrEqual(20);

    clickText('Copy');
    await waitForText(/clipboard clears in/i);
    expect(written).toEqual([generated]);
    // The copy message is honest about what it cannot reach.
    expect(document.body.textContent).toMatch(/cannot reach a clipboard manager/i);
  });

  /**
   * THE PASSWORD-CHANGE PATH (M15 review rewrote these).
   *
   * The single test that used to cover this asserted nothing: it waited on
   * `/password has changed|does not match this vault/i` — an alternation that
   * passes on FAILURE — and put every real assertion behind `if (put)`, so a
   * run where no request was ever made was a green run. Both defects it was
   * meant to cover were live underneath it.
   */
  describe('changing the vault password', () => {
    /** The Secret Key this device actually holds, in its ES1 text form. */
    async function currentSecretKey(): Promise<string> {
      const entropy = await recallSecretKey(USER);
      if (!entropy) throw new Error('the device should have remembered the Secret Key');
      return formatSecretKey(entropy);
    }

    it('rebinds the keyset when the current password and Secret Key are right', async () => {
      const service = installService();
      await openVaultWithItem();
      clickText('Settings');
      await waitForText('Change your vault password');

      byLabel('Current vault password').value = PASSWORD;
      byLabel('Secret Key').value = await currentSecretKey();
      byLabel('New vault password').value = 'a-brand-new-vault-password';
      submitForm();
      await waitForText(/password has changed/i);

      const put = service.calls.find((c) => c.method === 'PUT' && c.path === '/api/vault/keyset');
      expect(put).toBeDefined();
      const payload = JSON.parse((put as { body: string }).body) as Record<string, unknown>;
      // The proof is what makes replacement require the CURRENT password —
      // without it, exfiltrated tokens could destroy every item.
      expect(payload['proof']).toEqual(expect.any(String));
      expect(payload['srpVerifier']).toEqual(expect.any(String));
      expect(JSON.stringify(payload)).not.toContain('a-brand-new-vault-password');
      expect(JSON.stringify(payload)).not.toContain(PASSWORD);
    });

    it('REFUSES a well-formed Secret Key that is not this vault’s, and sends nothing', async () => {
      /*
       * The defect: nothing compared the typed key to the vault's own, so a key
       * from another kit re-derived the AUK and the SRP verifier from itself,
       * the server accepted the replacement (its proof authorizes the change
       * and, being zero-knowledge, cannot see what the new payload was built
       * from), and the screen said "Your vault password has changed."
       */
      const service = installService();
      await openVaultWithItem();
      clickText('Settings');
      await waitForText('Change your vault password');

      byLabel('Current vault password').value = PASSWORD;
      byLabel('Secret Key').value = await generateSecretKey(); // valid, and not ours
      byLabel('New vault password').value = 'a-brand-new-vault-password';
      submitForm();
      await waitForText(/did not open this vault, so nothing was changed/i);

      expect(
        service.calls.filter((c) => c.method === 'PUT' && c.path === '/api/vault/keyset'),
      ).toHaveLength(0);
      expect(service.keysetPuts).toBe(0);
    });

    it('REFUSES a wrong current password, and sends nothing', async () => {
      // The same local check catches this half: `open()` is an AEAD decrypt, so
      // either wrong input fails authentication rather than returning garbage.
      const service = installService();
      await openVaultWithItem();
      clickText('Settings');
      await waitForText('Change your vault password');

      byLabel('Current vault password').value = 'not-the-vault-password';
      byLabel('Secret Key').value = await currentSecretKey();
      byLabel('New vault password').value = 'a-brand-new-vault-password';
      submitForm();
      await waitForText(/did not open this vault, so nothing was changed/i);
      expect(service.keysetPuts).toBe(0);
    });

    it('says the same thing for both halves, so neither is confirmed', async () => {
      // The 2SKD rule the unlock screen already follows: naming which half was
      // wrong tells someone holding a stolen Secret Key that it is the right one.
      const service = installService();
      await openVaultWithItem();
      clickText('Settings');
      await waitForText('Change your vault password');

      byLabel('Current vault password').value = 'not-the-vault-password';
      byLabel('Secret Key').value = await generateSecretKey();
      byLabel('New vault password').value = 'a-brand-new-vault-password';
      submitForm();
      await waitForText(/did not open this vault, so nothing was changed/i);
      expect(document.body.textContent).not.toMatch(/secret key is wrong|password is wrong/i);
      expect(service.keysetPuts).toBe(0);
    });
  });

  it('resets only after DESTROY, then shows a NEW Secret Key', async () => {
    const service = installService();
    await openVaultWithItem();

    clickText('Settings');
    await waitForText('Reset the vault');

    // Without the confirmation, nothing happens.
    clickText('Reset my vault permanently');
    await waitForText(/type destroy/i);
    expect(service.resets).toBe(0);

    byLabel('Password for the new empty vault').value = 'a-replacement-vault-password';
    byLabel('Type DESTROY to confirm').value = 'DESTROY';
    clickText('Reset my vault permanently');
    await waitForText('Save your Secret Key');

    expect(service.resets).toBe(1);
    // The old Secret Key opens nothing now, so this device must have forgotten
    // it — otherwise the next unlock would silently use a dead key.
    expect(await recallSecretKey(USER)).toBeNull();
  });

  it('signs out of the origin only when the revocation succeeded', async () => {
    const service = installService();
    await openVaultWithItem();
    clickText('Settings');
    await waitForText('This device');

    service.fail.set('POST /api/auth/logout', { status: 502, error: 'upstream_unavailable' });
    clickText('Sign out of the vault');
    await waitForText(/could not sign out/i);
    // A "signed out" screen over a live session is the worse outcome (M8 PR5).
    expect(document.body.textContent).toMatch(/still open/i);
  });

  it('reveals and re-hides the secret, and cancels an edit without saving', async () => {
    const service = installService();
    await openVaultWithItem();

    clickText('Bank — joint');
    await waitForText('Edit item');
    const secret = byLabel('Password or secret');
    expect(secret.getAttribute('type')).toBe('password');
    clickText('Show');
    expect(secret.getAttribute('type')).toBe('text');
    clickText('Show');
    expect(secret.getAttribute('type')).toBe('password');

    byLabel('Title').value = 'a title nobody asked to save';
    clickText('Cancel');
    await waitForText('Bank — joint');
    // Cancel wrote nothing: still one item, still the original version.
    expect(service.items.size).toBe(1);
    expect([...service.items.values()][0]?.['blobVersion']).toBe(1);
  });

  it('refuses to save an item with no title', async () => {
    // A vault of untitled rows is a vault nobody can navigate, and the title is
    // the only field the list can show.
    installService();
    await openVaultWithItem();
    clickText('Add an item');
    await waitForText('Add an item');
    byLabel('Password or secret').value = 'orphan';
    submitForm();
    await waitForText(/give it a title/i);
  });

  it('forgets the Secret Key on request, so the next unlock asks for it', async () => {
    installService();
    await openVaultWithItem();
    expect(await recallSecretKey(USER)).not.toBeNull();

    clickText('Settings');
    await waitForText('This device');
    clickText('Forget my Secret Key on this device');
    await waitForText(/will ask for your Secret Key/i);
    expect(await recallSecretKey(USER)).toBeNull();
  });

  it('shows an unreadable item as a row rather than hiding it', async () => {
    // A blob that will not decrypt (a foreign key, or a version the AAD
    // rejects) must still appear: hiding it leaves the user unable to see that
    // something is there, and offering to overwrite it would be worse.
    const service = installService();
    await openVaultWithItem();
    const id = [...service.items.keys()][0] as string;
    service.items.set(id, {
      ...(service.items.get(id) as Record<string, unknown>),
      blob: btoa('not a valid envelope at all'),
    });

    clickText('Lock now');
    await waitForText('Unlock your vault');
    byLabel('Vault password').value = PASSWORD;
    submitForm();
    await waitForText(/could not be read/i);
  });
});
