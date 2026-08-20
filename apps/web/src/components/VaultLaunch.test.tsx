import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { VaultLaunch } from './VaultLaunch';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';

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

  beforeEach(() => {
    submitted = null;
    // jsdom will not perform a cross-origin navigation, so the submit is
    // intercepted and the form captured in the state it WOULD have been
    // submitted in — which is the only state worth asserting about.
    jest.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(function mockSubmit(
      this: void,
    ): void {
      submitted = document.querySelector('form');
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
    expect(form.querySelector<HTMLInputElement>('input[name="code"]')?.value).toBe(HANDOFF.code);

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
    const input = (await screen.findByLabelText(/confirm it’s you/i)) as HTMLInputElement;
    fireEvent.change(input, { target: { value: '123456' } });
    // The form OWNER, not `closest`: the M16 lesson about a selector that
    // matches an ancestor form and submits the action it was guarding.
    fireEvent.submit(input.form as HTMLFormElement);
  }

  it('CANCELLING while the retry is in flight lands nowhere — no navigation, no live code', async () => {
    let release: (() => void) | null = null;
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
    (release as unknown as () => void)();
    await new Promise((resolve) => setTimeout(resolve, 30));

    expect(submitted).toBeNull();
    expect(document.querySelector('input[type=hidden]')).toHaveValue('');
  });

  it('a withdrawn ceremony is not RE-OPENED by the request that was withdrawn', async () => {
    let release: (() => void) | null = null;
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
    (release as unknown as () => void)();
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
});
