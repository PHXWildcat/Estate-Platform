/**
 * The popup — the whole visible surface of PR2a.
 *
 * What is worth pinning here is not the layout: it is which SCREEN a given
 * failure produces. Three of the states this file exercises are ones the repo
 * has got wrong before on other surfaces — an outage rendering as an empty
 * answer (M10 PR4), a version skew rendering as data (M11/M12/M15), and a
 * transient failure rendering as a revocation (M9's rule pointed the other
 * way).
 */
import { messages } from '../src/copy';
import { mountPopup } from '../src/popup';
import { clearChromeDouble, installChromeDouble, TEST_ORIGIN } from './chrome-double';

interface Recorded {
  url: string;
  init: RequestInit;
}

function transport(replies: Array<{ status: number; body: unknown }>): { calls: Recorded[] } {
  const calls: Recorded[] = [];
  const queue = [...replies];
  (globalThis as { fetch?: unknown }).fetch = (
    url: unknown,
    init: RequestInit,
  ): Promise<Response> => {
    calls.push({ url: String(url), init });
    const next = queue.shift() ?? { status: 500, body: {} };
    return Promise.resolve({
      ok: next.status >= 200 && next.status < 300,
      status: next.status,
      text: () => Promise.resolve(JSON.stringify(next.body)),
    } as unknown as Response);
  };
  return { calls };
}

const TOKENS = {
  accessToken: 'access-1',
  refreshToken: 'refresh-1',
  userId: 'u-1',
  sessionId: 's-1',
};

function root(): HTMLElement {
  document.body.replaceChildren();
  const node = document.createElement('main');
  node.id = 'root';
  document.body.append(node);
  return node;
}

function text(): string {
  return document.body.textContent ?? '';
}

function button(name: RegExp): HTMLButtonElement {
  const found = [...document.querySelectorAll('button')].find((b) =>
    name.test(b.textContent ?? ''),
  );
  if (!found) throw new Error(`no button matching ${String(name)} in: ${text()}`);
  return found;
}

describe('the popup', () => {
  afterEach(clearChromeDouble);

  it('asks for a pairing code when this browser is not connected', async () => {
    installChromeDouble();
    transport([]);
    await mountPopup({ root: root() });

    expect(text()).toContain('Connect to Estate');
    expect(document.querySelector('#pairing-code')).not.toBeNull();
    expect(button(/Connect this browser/)).toBeTruthy();
  });

  it('pairs, then reports that the account HAS a vault', async () => {
    installChromeDouble();
    const { calls } = transport([
      { status: 200, body: TOKENS },
      { status: 200, body: { enrolled: true } },
    ]);
    await mountPopup({ root: root() });

    (document.querySelector('#pairing-code') as HTMLInputElement).value = 'EP1-ABCD';
    button(/Connect this browser/).click();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(text()).toContain('Connected to Estate');
    expect(text()).toContain('This account has a vault.');
    // The status read went through the edge on the paired credential — the
    // whole chain this PR exists to prove.
    expect(calls[1]?.url).toBe(`${TEST_ORIGIN}/api/vault/keyset`);
    expect((calls[1]?.init.headers as Record<string, string>)['authorization']).toBe(
      'Bearer access-1',
    );
  });

  it('says a vault has NOT been set up, without claiming anything else', async () => {
    installChromeDouble();
    transport([
      { status: 200, body: TOKENS },
      { status: 200, body: { enrolled: false } },
    ]);
    await mountPopup({ root: root() });
    (document.querySelector('#pairing-code') as HTMLInputElement).value = 'EP1-ABCD';
    button(/Connect this browser/).click();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(text()).toContain('no vault yet');
  });

  it('states its own boundary rather than looking half-finished', async () => {
    // A surface that looks like it should unlock and does not is worse than one
    // that says what it cannot do.
    const double = installChromeDouble();
    double.store.set('estate.session', TOKENS);
    transport([{ status: 200, body: { enrolled: true } }]);
    await mountPopup({ root: root() });

    expect(text()).toContain('cannot reset your vault');
    // The vault half mounts underneath, and says what it is doing rather than
    // rendering nothing while it asks.
    expect(text()).toContain('Checking your vault');
  });

  it('shows the uniform refusal for every way a code is rejected', async () => {
    installChromeDouble();
    transport([{ status: 401, body: { error: 'invalid_code' } }]);
    await mountPopup({ root: root() });
    (document.querySelector('#pairing-code') as HTMLInputElement).value = 'EP1-NOPE';
    button(/Connect this browser/).click();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(text()).toContain(messages.INVALID_CODE);
    // Still on the connect screen, with the field available to try again.
    expect(document.querySelector('#pairing-code')).not.toBeNull();
  });

  it('a failed status read is an OUTAGE, not a claim that there is no vault', async () => {
    // The M10 PR4 rule. Rendering "no vault" on a read that did not happen
    // would tell someone their vault does not exist.
    const double = installChromeDouble();
    double.store.set('estate.session', TOKENS);
    transport([{ status: 503, body: { error: 'upstream_unavailable' } }]);
    await mountPopup({ root: root() });

    expect(text()).toContain('couldn’t check your vault');
    expect(text()).not.toContain('no vault yet');
    // The pairing stands: an outage must not un-pair the device.
    expect(await double.store.get('estate.session')).toEqual(TOKENS);
  });

  it('a response with no `enrolled` field is not read as "no vault"', async () => {
    // A BFF-style version skew: `{"data":{}}` three milestones running.
    const double = installChromeDouble();
    double.store.set('estate.session', TOKENS);
    transport([{ status: 200, body: {} }]);
    await mountPopup({ root: root() });
    // `enrolled !== true` is the safe reading here — it says "no vault yet",
    // which is a claim about the ACCOUNT. Pinned so a future change that starts
    // treating a missing field as enrolled has to argue for it.
    expect(text()).toContain('no vault yet');
  });

  it('forgets the credential when the session is genuinely gone', async () => {
    // Revoked from the owner's paired-devices list: both the read and the
    // refresh are refused, so the pairing really is over and the honest screen
    // is the one that offers a new code.
    const double = installChromeDouble();
    double.store.set('estate.session', TOKENS);
    transport([
      { status: 401, body: { error: 'unauthorized' } },
      { status: 401, body: { error: 'unauthorized' } },
    ]);
    await mountPopup({ root: root() });

    expect(text()).toContain('Connect to Estate');
    expect(text()).toContain(messages.UNAUTHENTICATED);
    expect(double.store.size).toBe(0);
  });

  it('spends the ROTATED credential afterwards, not the one it started with', async () => {
    /*
     * THE MUTATION THAT SURVIVED (M44 PR2). Deleting `rotateSession(current)`
     * left all eleven cases in this file green, and that was a weak test rather
     * than a harmless line. A refresh rotates BOTH tokens — `toSession` requires
     * a `refreshToken` in the response — so a popup that does not take the
     * rotation goes on presenting a spent one. `disconnect` reads the resulting
     * refusal as "already gone" and forgets locally, leaving a browser that
     * looks signed out over a session still live on the server: the exact
     * outcome `disconnect`'s own comment calls the worst there is.
     *
     * The rotation is driven through the VAULT half deliberately, because that
     * is the path `callOnLiveSession` owns. `refreshStatus` re-renders through
     * `show()` and would carry the new session anyway, so a test written around
     * it would pass with the line deleted — which is how this went unnoticed.
     */
    const double = installChromeDouble();
    double.store.set('estate.session', TOKENS);
    const ROTATED = {
      accessToken: 'access-2',
      refreshToken: 'refresh-2',
      userId: 'u-1',
      sessionId: 's-1',
    };
    // The offscreen document, as a double that answers on the CREDENTIAL it is
    // handed — which is the only way a stale one is visible from out here.
    const presented: string[] = [];
    (
      globalThis as { chrome?: { runtime?: Record<string, unknown> } }
    ).chrome!.runtime!.sendMessage = (message: {
      kind?: string;
      bearer?: string;
    }): Promise<unknown> => {
      if (message.kind === undefined) return Promise.resolve({ ok: true });
      if (message.kind === 'state') {
        return Promise.resolve({ ok: true, state: { status: 'unlocked' } });
      }
      if (message.bearer !== undefined) presented.push(message.bearer);
      if (message.bearer !== ROTATED.accessToken) {
        return Promise.resolve({ ok: false, code: 'UNAUTHENTICATED' });
      }
      return Promise.resolve({ ok: true, items: [] });
    };
    const { calls } = transport([
      { status: 200, body: { enrolled: true } },
      { status: 200, body: ROTATED },
      { status: 200, body: { status: 'ok' } },
    ]);
    await mountPopup({ root: root() });
    for (let i = 0; i < 50 && !presented.includes(ROTATED.accessToken); i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }

    // ANTI-VACUITY: the rotation really happened, and it took the stale token
    // first — otherwise everything below passes for want of an expiry.
    expect(presented[0]).toBe(TOKENS.accessToken);
    expect(presented).toContain(ROTATED.accessToken);

    button(/Disconnect this browser/).click();
    for (let i = 0; i < 50 && calls.length < 3; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }

    const logout = calls.find((c) => c.url.endsWith('/api/auth/logout'));
    expect(logout).toBeDefined();
    // THE ASSERTION. With the rotation dropped this reads `Bearer access-1`.
    expect((logout?.init.headers as Record<string, string>)['authorization']).toBe(
      'Bearer access-2',
    );
  });

  it('disconnects, and returns to the connect screen', async () => {
    const double = installChromeDouble();
    double.store.set('estate.session', TOKENS);
    const { calls } = transport([
      { status: 200, body: { enrolled: true } },
      { status: 200, body: { status: 'ok' } },
    ]);
    await mountPopup({ root: root() });

    button(/Disconnect this browser/).click();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(calls[1]?.url).toBe(`${TEST_ORIGIN}/api/auth/logout`);
    expect(text()).toContain('Connect to Estate');
    expect(double.store.size).toBe(0);
  });

  it('KEEPS the pairing when disconnecting could not reach Estate', async () => {
    const double = installChromeDouble();
    double.store.set('estate.session', TOKENS);
    transport([
      { status: 200, body: { enrolled: true } },
      { status: 503, body: {} },
      { status: 503, body: {} },
    ]);
    await mountPopup({ root: root() });

    button(/Disconnect this browser/).click();
    await new Promise((resolve) => setTimeout(resolve, 0));

    // Told, not reassured: a "disconnected" screen over a live 30-day
    // credential is the M8 PR5 worst outcome.
    expect(text()).toContain('Connected to Estate');
    expect(text()).toContain(messages.UNAVAILABLE);
    expect(await double.store.get('estate.session')).toEqual(TOKENS);
  });

  it('renders user-supplied text as TEXT — the code field is never markup', async () => {
    installChromeDouble();
    transport([{ status: 401, body: { error: 'invalid_code' } }]);
    await mountPopup({ root: root() });
    (document.querySelector('#pairing-code') as HTMLInputElement).value =
      '<img src=x onerror=alert(1)>';
    button(/Connect this browser/).click();
    await new Promise((resolve) => setTimeout(resolve, 0));

    // Nothing was parsed: no element entered the tree from that string.
    expect(document.querySelector('img')).toBeNull();
  });
});
