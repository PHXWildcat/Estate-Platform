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
});
