import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { VaultLaunch } from './VaultLaunch';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';

/**
 * How many `securitypolicyviolation` registrations a spy saw. Counted rather
 * than eyeballed because every other `document` listener in the tree (React's
 * own included) shows up in the same spy.
 */
function cspListeners(spy: jest.SpyInstance): number {
  // `jest.SpyInstance` without generics types `calls` as `any[]`, which the
  // no-unsafe-member-access rule refuses. `unknown[][]` is the honest shape:
  // the only thing read here is the event name in the first argument.
  const calls = spy.mock.calls as unknown[][];
  return calls.filter((call) => call[0] === 'securitypolicyviolation').length;
}

/**
 * The vault interstitial (M15).
 *
 * What matters here is not the copy but WHERE THE CODE GOES. A handoff code in
 * a URL would land in browser history, in a `Referer` and in every intermediary
 * access log between here and the vault origin — which is the whole reason this
 * is a form POST rather than a redirect. jsdom will not perform a cross-origin
 * navigation, so `form.submit` is stubbed and the form is inspected in the state
 * it would have been submitted in.
 */
describe('VaultLaunch', () => {
  const HANDOFF = {
    code: 'single-use-handoff-code',
    expiresAt: '2026-08-08T00:01:00.000Z',
    vaultOrigin: 'http://vault.localhost:3010',
  };

  let submitted: HTMLFormElement | null;
  // Captured AT SUBMIT TIME. The field is cleared immediately afterwards, so a
  // credential that reached the body and a credential still sitting in the DOM
  // are now two different questions and each is asked separately.
  let submittedCode: string | null;

  beforeEach(() => {
    submitted = null;
    submittedCode = null;
    // jsdom will not perform a cross-origin navigation, so the submit is
    // intercepted and the form captured in the state it WOULD have been
    // submitted in — which is the only state worth asserting about.
    jest.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(function mockSubmit(
      this: void,
    ): void {
      submitted = document.querySelector('form');
      submittedCode =
        submitted?.querySelector<HTMLInputElement>('input[name="code"]')?.value ?? null;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('posts the code to the vault origin, and puts it nowhere else', async () => {
    installGraphqlFetchMock({
      StartVaultHandoff: () => jsonResponse({ data: { startVaultHandoff: HANDOFF } }),
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));

    await waitFor(() => expect(submitted).not.toBeNull());
    const form = submitted as unknown as HTMLFormElement;
    expect(form.method.toLowerCase()).toBe('post');
    // A TOP-LEVEL POST to the isolated origin's arrival route.
    expect(form.action).toBe('http://vault.localhost:3010/open');
    expect(submittedCode).toBe(HANDOFF.code);
    // …and it does not LINGER. A blocked or refused navigation leaves this page
    // in place, and the code must not still be readable in the DOM when it does.
    expect(form.querySelector<HTMLInputElement>('input[name="code"]')?.value).toBe('');

    // The code is in the body and NOWHERE ELSE: not in the action, not in the
    // page's URL, not in the rendered text.
    expect(form.action).not.toContain(HANDOFF.code);
    expect(window.location.search).not.toContain(HANDOFF.code);
    expect(document.body.textContent).not.toContain(HANDOFF.code);
  });

  it('takes the origin from the SERVER rather than a baked-in constant', async () => {
    // The M8 PR5 lesson: a value serialised at build time gets baked wrong and
    // nothing notices until production. If the deployment moves the vault, this
    // page follows without a rebuild.
    installGraphqlFetchMock({
      StartVaultHandoff: () =>
        jsonResponse({
          data: { startVaultHandoff: { ...HANDOFF, vaultOrigin: 'https://vault.example.test' } },
        }),
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));

    await waitFor(() => expect(submitted).not.toBeNull());
    expect((submitted as unknown as HTMLFormElement).action).toBe(
      'https://vault.example.test/open',
    );
  });

  it('prompts for step-up rather than failing, and submits nothing meanwhile', async () => {
    installGraphqlFetchMock({
      StartVaultHandoff: () => graphqlError('STEPUP_REQUIRED'),
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));

    expect(await screen.findByLabelText(/confirm it’s you/i)).toBeInTheDocument();
    expect(submitted).toBeNull();
  });

  it('says the platform failed, not the user, when the mint fails', async () => {
    installGraphqlFetchMock({
      StartVaultHandoff: () => graphqlError('VAULT_UNAVAILABLE'),
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));

    // "Nothing about your vault has changed" is the load-bearing half: a user
    // bounced on the way into the vault will otherwise assume the worst.
    expect(await screen.findByText(/nothing about your vault has changed/i)).toBeInTheDocument();
    expect(submitted).toBeNull();
  });

  it('never submits a form when the response carries no code', async () => {
    // A version-skewed BFF answering `{"data":{}}` is the M11 browser-only
    // defect's shape. It must not become a POST of `code=undefined`.
    installGraphqlFetchMock({ StartVaultHandoff: () => jsonResponse({ data: {} }) });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));

    await screen.findByRole('status');
    expect(submitted).toBeNull();
  });
  /*
   * CONSENT WITHDRAWN MID-CEREMONY (M21 PR4 review).
   *
   * The test above — "CANCELLING the step-up ... submits nothing" — cites the
   * M16 PR5 finding by name and CANNOT FAIL: it cancels before a code is ever
   * typed, so no retry is ever in flight and there is nothing for a withdrawal
   * to race. It asserts the property in the one state where the defect is
   * unreachable. These three drive the state where it is not.
   *
   * The window is one network round trip wide and needs no adversary: type the
   * code, press the button, change your mind. Cancel is deliberately never
   * disabled, because the protective action must not be contingent on the
   * permissive one finishing — so pressing it mid-flight is ordinary use.
   */
  async function elevate(): Promise<void> {
    const input = await screen.findByLabelText<HTMLInputElement>(/confirm it’s you/i);
    fireEvent.change(input, { target: { value: '123456' } });
    // The form OWNER, not `closest`: the M16 lesson about a selector that
    // matches an ancestor form and submits the action it was guarding.
    fireEvent.submit(input.form as HTMLFormElement);
  }

  it('CANCELLING while the retry is in flight lands nowhere — no navigation, no live code', async () => {
    // Assigned synchronously by the executor; typed non-null because TS cannot
    // narrow an assignment made inside a callback it does not know runs first.
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let mints = 0;
    installGraphqlFetchMock({
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      StartVaultHandoff: async () => {
        mints += 1;
        if (mints === 1) return graphqlError('STEPUP_REQUIRED');
        await held;
        return jsonResponse({
          data: {
            startVaultHandoff: {
              code: 'LIVE-CODE',
              expiresAt: 'x',
              vaultOrigin: 'https://vault.example.test',
            },
          },
        });
      },
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));
    await elevate();
    await waitFor(() => expect(mints).toBe(2));

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    await waitFor(() => {
      expect(screen.queryByLabelText(/confirm it’s you/i)).not.toBeInTheDocument();
    });
    // The mint the user withdrew from now answers. Before this fix it set the
    // action, wrote the code into the field and navigated.
    release();
    await new Promise((resolve) => setTimeout(resolve, 30));

    expect(submitted).toBeNull();
    expect(document.querySelector('input[type=hidden]')).toHaveValue('');
  });

  it('a withdrawn ceremony is not RE-OPENED by the request that was withdrawn', async () => {
    // Assigned synchronously by the executor; typed non-null because TS cannot
    // narrow an assignment made inside a callback it does not know runs first.
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let mints = 0;
    installGraphqlFetchMock({
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      StartVaultHandoff: async () => {
        mints += 1;
        if (mints === 1) return graphqlError('STEPUP_REQUIRED');
        await held;
        return graphqlError('STEPUP_REQUIRED');
      },
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));
    await elevate();
    await waitFor(() => expect(mints).toBe(2));

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    await waitFor(() => {
      expect(screen.queryByLabelText(/confirm it’s you/i)).not.toBeInTheDocument();
    });
    release();
    await new Promise((resolve) => setTimeout(resolve, 30));

    expect(screen.queryByLabelText(/confirm it’s you/i)).not.toBeInTheDocument();
  });

  it('a refusal a fresh check CANNOT fix puts the prompt away rather than inviting one', async () => {
    // The M20 PR5 finding, which reached `SecurityPanel` and not this. Identity's
    // step-up cap answers 429; asking for another factor cannot help, and the
    // page said both things at once.
    let mints = 0;
    installGraphqlFetchMock({
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      StartVaultHandoff: () => {
        mints += 1;
        return graphqlError(mints === 1 ? 'STEPUP_REQUIRED' : 'TOO_MANY_ATTEMPTS');
      },
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));
    await elevate();
    await screen.findByRole('status');

    expect(screen.queryByLabelText(/confirm it’s you/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/fresh identity check/i)).not.toBeInTheDocument();
    expect(submitted).toBeNull();
  });
  it('A FRESH PRESS re-arms after a withdrawal — Cancel must not disable the page', async () => {
    // The other half of the withdrawal, and the reason the flag is cleared on
    // the trigger rather than inside `open()`: a marker that only ever gets set
    // turns one Cancel into a permanently dead button.
    let mints = 0;
    installGraphqlFetchMock({
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      StartVaultHandoff: () => {
        mints += 1;
        if (mints === 1) return graphqlError('STEPUP_REQUIRED');
        return jsonResponse({
          data: {
            startVaultHandoff: {
              code: 'LIVE-CODE',
              expiresAt: 'x',
              vaultOrigin: 'https://vault.example.test',
            },
          },
        });
      },
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));
    await screen.findByLabelText(/confirm it’s you/i);
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    await waitFor(() => {
      expect(screen.queryByLabelText(/confirm it’s you/i)).not.toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));
    await waitFor(() => expect(submitted).not.toBeNull());
    expect((submitted as unknown as HTMLFormElement).action).toBe(
      'https://vault.example.test/open',
    );
  });
  it('A BLOCKED SUBMIT is reported, not silent — and leaves no code behind', async () => {
    /*
     * `form-action` is baked into this app's CSP at BUILD time while the BFF
     * serves the origin at REQUEST time, and nothing outside the compose stack
     * makes them agree. A deployment that moves the origin without rebuilding
     * gets a POST the browser refuses: no throw, no rejected promise, a button
     * that returns to idle — and, before this fix, a live single-use handoff
     * code left readable in the DOM of the weaker of the two origins.
     */
    installGraphqlFetchMock({
      StartVaultHandoff: () =>
        jsonResponse({
          data: {
            startVaultHandoff: {
              code: 'LIVE-CODE',
              expiresAt: 'x',
              vaultOrigin: 'https://vault.example.test',
            },
          },
        }),
    });
    (HTMLFormElement.prototype.submit as jest.Mock).mockImplementation(function blocked(
      this: void,
    ): void {
      /*
       * ASYNCHRONOUSLY, WHICH IS THE WHOLE POINT OF THIS DOUBLE. The first
       * version dispatched inline, and that is the only reason the original
       * read-the-flag-after-submit code passed: `document.dispatchEvent` is
       * synchronous by definition, so the double answered a question the
       * browser answers a task later. Measured in Chrome against
       * `form-action 'none'` — the submit is refused, the event arrives, and a
       * synchronous read sees `false`. A double must be faithful about TIMING,
       * not only about values; dispatching inline here makes this suite green
       * over a detector that cannot fire.
       */
      const event = new Event('securitypolicyviolation');
      // `violatedDirective` is read-only on the real interface, so it is
      // DEFINED rather than assigned — jsdom implements neither the event nor
      // the enforcement, so the browser's half is modelled here.
      Object.defineProperty(event, 'violatedDirective', { value: 'form-action' });
      setTimeout(() => document.dispatchEvent(event), 0);
    });
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));

    /*
     * AWAITED, because the violation arrives a task after the submit — which is
     * the defect this case now pins. The ERROR ITSELF is asserted, not merely
     * that a status region exists: `FormStatus` renders its node either way, so
     * asserting the region is satisfied by a page that reported nothing at all.
     */
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(/open the vault just now/i),
    );
    expect(document.querySelector<HTMLInputElement>('input[name="code"]')?.value).toBe('');
    expect(screen.getByRole('button', { name: /open the vault/i })).toBeEnabled();
  });

  /*
   * THE LISTENER OUTLIVES THE SUBMIT BY DESIGN (the violation is dispatched a
   * task later), so the two things that stop it listening are the only reason
   * that is safe. Both are asserted here rather than reasoned about, because a
   * lingering `document` listener holding a closure over `setError` is exactly
   * how this becomes a leak or a "state update on an unmounted component".
   */
  it('detaches the violation listener when the page goes away', async () => {
    installGraphqlFetchMock({
      StartVaultHandoff: () => jsonResponse({ data: { startVaultHandoff: HANDOFF } }),
    });
    const added = jest.spyOn(document, 'addEventListener');
    const removed = jest.spyOn(document, 'removeEventListener');
    const view = render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));
    // The submit double navigates nowhere and dispatches nothing, which is the
    // ALLOWED path — so the listener is still attached when the page unmounts.
    await waitFor(() => expect(cspListeners(added)).toBe(1));
    expect(cspListeners(removed)).toBe(0);

    view.unmount();
    expect(cspListeners(removed)).toBe(1);
  });

  it('re-arming replaces the listener rather than stacking a second', async () => {
    installGraphqlFetchMock({
      StartVaultHandoff: () => jsonResponse({ data: { startVaultHandoff: HANDOFF } }),
    });
    const added = jest.spyOn(document, 'addEventListener');
    const removed = jest.spyOn(document, 'removeEventListener');
    render(<VaultLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));
    await waitFor(() => expect(cspListeners(added)).toBe(1));
    fireEvent.click(screen.getByRole('button', { name: /open the vault/i }));
    await waitFor(() => expect(cspListeners(added)).toBe(2));

    // One armed, one detached: never two live listeners, which would report the
    // same refusal twice.
    expect(cspListeners(removed)).toBe(1);
  });
});
