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
  injected: unknown[];
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
  // `null` means "no active tab we may see". NOT `undefined`, because passing
  // `undefined` explicitly SELECTS a default parameter — which silently gave
  // the no-tab case the default URL and made it pass for the wrong reason.
  pageUrl: string | null = 'https://example.com/login',
): Wired {
  const sent: unknown[] = [];
  const fetched: { url: string; body: string }[] = [];
  const injected: unknown[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    tabs: {
      query: () => Promise.resolve(pageUrl === null ? [] : [{ id: 1, url: pageUrl }]),
    },
    scripting: {
      executeScript: (injection: unknown) => {
        injected.push(injection);
        return Promise.resolve([
          { frameId: 0, result: { filledUsername: true, filledSecret: true } },
        ]);
      },
    },
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
  return { sent, fetched, injected };
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
          ? { ok: true, items: [{ id: 'i-1', itemType: 'password', title: 'Bank login' }] }
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
        ? { ok: true, items: [{ id: 'i', itemType: 'password', title: '', unreadable: true }] }
        : { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } },
    );
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    expect(text()).toContain('could not be read');
  });

  it('renders an item title as TEXT, whatever it contains', async () => {
    wire((message) =>
      message.kind === 'list'
        ? { ok: true, items: [{ id: 'i', itemType: 'password', title: '<img src=x onerror=1>' }] }
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

describe('what is saved for the page you are on', () => {
  afterEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  const unlocked = {
    ok: true,
    state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' },
  };

  function openWith(
    matched: unknown,
    pageUrl: string | null = 'https://example.com/login',
    fill: unknown = { ok: true, credential: { username: 'someone', secret: 's3cret' } },
  ): Wired {
    return wire(
      (message) =>
        message.kind === 'list'
          ? { ok: true, items: [] }
          : message.kind === 'matches'
            ? { ok: true, matched }
            : message.kind === 'fill'
              ? fill
              : unlocked,
      { status: 200 },
      pageUrl,
    );
  }

  it('names the site and lists what matches it', async () => {
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'match', domain: 'example.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('For example.com'), 'the per-page section');
    expect(text()).toContain('Bank login — saved for this site');
  });

  it('SHOWS a confusable refusal rather than hiding it', async () => {
    // §4 TB9 refuses rather than warns — but a refusal the user cannot see is
    // indistinguishable from having nothing saved, which is the moment worth
    // telling them about.
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'confusable', savedDomain: 'example.com', pageDomain: 'exarnple.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('only looks like the saved one'), 'the refusal');
    expect(text()).not.toContain('saved for this site');
  });

  it('says why a downgrade is refused', async () => {
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'scheme-downgrade', domain: 'example.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('this page is not secure'), 'the downgrade refusal');
  });

  it('says plainly that nothing is saved here', async () => {
    openWith([]);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('Nothing saved for this site'), 'the empty state');
  });

  it('offers a fill button on a MATCH, and on nothing else', async () => {
    /*
     * REWRITTEN IN PR3b, not deleted. This case was named "offers no fill button
     * anywhere — that is PR3b", and PR3b makes that false; deleting it would
     * leave the one screen that decides what is offered with no test of what it
     * offers. What it asserts now is the property that replaced the absence:
     * `isFillable` is the only predicate, so a refusal gets no control at all —
     * not even a disabled one, because a greyed-out button invites "how do I
     * enable it" and the answer is "you cannot, on purpose".
     */
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'match', domain: 'example.com' },
      },
      {
        id: 'j',
        itemType: 'password',
        title: 'Lookalike',
        verdict: { kind: 'confusable', savedDomain: 'example.com', pageDomain: 'exarnple.com' },
      },
      {
        id: 'k',
        itemType: 'password',
        title: 'Insecure',
        verdict: { kind: 'scheme-downgrade', domain: 'example.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('For example.com'), 'the per-page section');

    const fills = [...document.querySelectorAll('button')].filter((b) =>
      /^fill$/i.test(b.textContent ?? ''),
    );
    // Exactly one, for exactly the matching row.
    expect(fills).toHaveLength(1);
    expect(fills[0]?.closest('li')?.textContent).toContain('Bank login');
    // And no disabled control smuggled onto the refusals.
    expect([...document.querySelectorAll('button')].some((b) => b.hasAttribute('disabled'))).toBe(
      false,
    );
  });

  it('says on screen that filling does not make a site genuine', async () => {
    // docs/04 records this as a residual "*on screen*". This is the screen, and
    // the sentence is asserted rather than left to whoever writes the copy next.
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'match', domain: 'example.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('For example.com'), 'the per-page section');
    expect(text()).toContain('gives this page the password');
    expect(text()).toContain('cannot tell whether the site itself is genuine');
  });

  const MATCH = [
    {
      id: 'i',
      itemType: 'password',
      title: 'Bank login',
      verdict: { kind: 'match', domain: 'example.com' },
    },
  ];

  const pressFill = async (): Promise<void> => {
    await until(() => text().includes('For example.com'), 'the per-page section');
    const button = [...document.querySelectorAll('button')].find((b) =>
      /^fill$/i.test(b.textContent ?? ''),
    );
    if (!button) throw new Error(`no Fill button. Saw: ${text()}`);
    button.click();
  };

  it('fills, and says plainly that nothing was submitted', async () => {
    const wired = openWith(MATCH);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await pressFill();
    await until(() => text().includes('Filled'), 'the outcome');

    // The credential reached the page exactly once, as an argument.
    expect(wired.injected).toHaveLength(1);
    expect(JSON.stringify(wired.injected[0])).toContain('s3cret');
    // And the user is told the thing that matters most about an autofill.
    expect(text()).toContain('Nothing was submitted');
  });

  it('asks for a FILL, naming the item and the page, never for a secret', async () => {
    const wired = openWith(MATCH);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await pressFill();
    await until(() => text().includes('Filled'), 'the outcome');

    const ask = wired.sent.find((m) => (m as { kind?: string }).kind === 'fill');
    expect(ask).toEqual({
      target: 'offscreen',
      kind: 'fill',
      bearer: BEARER,
      itemId: 'i',
      pageUrl: 'https://example.com/login',
    });
  });

  it('says the holder declined WITHOUT calling it an error, and injects nothing', async () => {
    // `credential: null` is the key holder refusing — the item does not belong
    // to this page, or could not be opened. The user did nothing wrong and there
    // is nothing to retry, so it must not read as a failure (the M9 rule).
    const wired = openWith(MATCH, 'https://example.com/login', { ok: true, credential: null });
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await pressFill();
    await until(() => text().includes('not offered for this page'), 'the refusal');

    expect(wired.injected).toEqual([]);
    expect(document.querySelector('.error')).toBeNull();
  });

  it('shows a locked vault as an ERROR, because that one is worth retrying', async () => {
    const wired = openWith(MATCH, 'https://example.com/login', {
      ok: false,
      code: 'VAULT_LOCKED',
    });
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await pressFill();
    await until(() => document.querySelector('.error') !== null, 'the error');
    expect(wired.injected).toEqual([]);
  });

  it('renders the whole vault normally when the page cannot be seen', async () => {
    // A chrome:// tab, or a window with nothing active. Not a failure of the
    // vault, so the list is still there and the per-page section simply is not.
    openWith([], null);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('Vault open'), 'the unlocked view');
    expect(text()).not.toContain('For ');
    expect(text()).not.toContain('Nothing saved for this site');
  });
});

describe('authoring an item in the popup (M16 PR4a)', () => {
  const ITEM = {
    id: 'i-1',
    itemType: 'password',
    title: 'Bank login',
    blobVersion: 4,
  };

  function composing(reply: (m: { kind?: string }) => unknown): Wired {
    return wire(
      (message) =>
        message.kind === 'list'
          ? { ok: true, items: [ITEM] }
          : message.kind === 'matches'
            ? { ok: true, matched: [] }
            : (reply(message) ?? { ok: true, state: { status: 'unlocked', expiresAt: 'x' } }),
      { status: 200 },
      null,
    );
  }

  const typeInto = (id: string, value: string): void => {
    const input = document.getElementById(id) as HTMLInputElement | null;
    if (!input) throw new Error(`no field ${id}. Saw: ${text()}`);
    input.value = value;
  };
  const press = (label: string): void => {
    const button = [...document.querySelectorAll('button')].find(
      (b) => (b.textContent ?? '') === label,
    );
    if (!button) throw new Error(`no button ${label}. Saw: ${text()}`);
    button.click();
  };

  it('creates from what was typed, and says the address decides where it fills', async () => {
    const wired = composing((m) => (m.kind === 'create' ? { ok: true, item: ITEM } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('Vault open'), 'the vault');

    press('New item');
    await until(() => text().includes('New item'), 'the form');
    // The one sentence the form owes: the url is what governs the fill.
    expect(text()).toContain('decides where this can be filled');

    typeInto('item-title', 'Typed here');
    typeInto('item-secret', 's3cret');
    press('Add to vault');
    await until(() => wired.sent.some((m) => (m as { kind?: string }).kind === 'create'), 'create');

    const sent = wired.sent.find((m) => (m as { kind?: string }).kind === 'create');
    expect(sent).toMatchObject({
      kind: 'create',
      itemType: 'password',
      content: { title: 'Typed here', secret: 's3cret', username: '', url: '' },
    });
  });

  it('refuses a create with no title rather than saving an unfindable item', async () => {
    composing(() => undefined);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('Vault open'), 'the vault');
    press('New item');
    await until(() => text().includes('New item'), 'the form');
    press('Add to vault');
    await until(() => text().includes('Give it a title'), 'the refusal');
  });

  it('EDIT SENDS ONLY WHAT CHANGED, so a blank field cannot erase what it cannot see', async () => {
    const wired = composing((m) => (m.kind === 'update' ? { ok: true, item: ITEM } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('Bank login'), 'the list');

    press('Edit');
    await until(() => text().includes('Edit item'), 'the form');
    expect(text()).toContain('Leave a field empty to keep what is already saved');

    // Only the password is typed. Title is pre-filled and unchanged; username
    // and url are left blank — and must NOT be sent as empty strings, or the
    // holder would merge them and wipe values the user never saw.
    typeInto('item-secret', 'a-new-password');
    press('Save changes');
    await until(() => wired.sent.some((m) => (m as { kind?: string }).kind === 'update'), 'update');

    const sent = wired.sent.find((m) => (m as { kind?: string }).kind === 'update') as {
      changes: Record<string, unknown>;
      blobVersion: number;
    };
    expect(sent.changes).toEqual({ secret: 'a-new-password' });
    expect(Object.keys(sent.changes)).not.toContain('username');
    expect(Object.keys(sent.changes)).not.toContain('url');
    // And the version the popup READ travels, which is what makes If-Match mean
    // anything.
    expect(sent.blobVersion).toBe(4);
  });

  it('keeps the typed form on screen when a create is refused', async () => {
    // Losing what someone just typed because the server said no is the worst
    // possible answer on a form holding a password.
    composing((m) => (m.kind === 'create' ? { ok: false, code: 'VAULT_LOCKED' } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('Vault open'), 'the vault');
    press('New item');
    await until(() => text().includes('New item'), 'the form');
    typeInto('item-title', 'Typed here');
    press('Add to vault');
    await until(() => text().includes('Your vault is locked'), 'the refusal');
    // Still the form, not the list.
    expect(text()).toContain('New item');
  });

  it('explains a version conflict in its own words, and offers no overwrite', async () => {
    composing((m) => (m.kind === 'update' ? { ok: false, code: 'VERSION_CONFLICT' } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('Bank login'), 'the list');
    press('Edit');
    await until(() => text().includes('Edit item'), 'the form');
    typeInto('item-secret', 'x');
    press('Save changes');
    await until(() => text().includes('changed somewhere else'), 'the conflict');
    // Deliberately NO "overwrite anyway": seeing the newer value first is the
    // whole point of If-Match.
    expect(text().toLowerCase()).not.toContain('overwrite');
  });

  it('sends nothing at all when an edit changed nothing', async () => {
    const wired = composing(() => undefined);
    await mountVaultScreens({ host: host(), userId: USER, bearer: BEARER });
    await until(() => text().includes('Bank login'), 'the list');
    press('Edit');
    await until(() => text().includes('Edit item'), 'the form');
    press('Save changes');
    await until(() => text().includes('Vault open'), 'back to the list');
    expect(wired.sent.some((m) => (m as { kind?: string }).kind === 'update')).toBe(false);
  });
});
