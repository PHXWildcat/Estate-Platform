import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { OperatorLaunch } from './OperatorLaunch';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';

/**
 * The operator interstitial (M21 PR3a).
 *
 * Two things are worth asserting rather than reading. WHERE THE CODE GOES — a
 * handoff code in a URL would land in browser history, in a `Referer` and in
 * every intermediary access log between here and the operator origin, which is
 * the whole reason this is a form POST rather than a redirect. And WHAT THE
 * PAGE CLAIMS: minting is role-blind, so this page works for everybody, and a
 * page that implied otherwise would teach every user who reached it that
 * arriving is the permission.
 *
 * jsdom will not perform a cross-origin navigation, so `form.submit` is stubbed
 * and the form is inspected in the state it would have been submitted in.
 */
describe('OperatorLaunch', () => {
  const HANDOFF = {
    code: 'single-use-operator-code',
    expiresAt: '2026-08-08T00:01:00.000Z',
    operatorOrigin: 'http://operator.localhost:3011',
  };

  let submitted: HTMLFormElement | null;
  // Captured AT SUBMIT TIME. The field is cleared immediately afterwards, so a
  // credential that reached the body and a credential still sitting in the DOM
  // are now two different questions and each is asked separately.
  let submittedCode: string | null;

  beforeEach(() => {
    submitted = null;
    submittedCode = null;
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

  it('posts the code to the operator origin, and puts it nowhere else', async () => {
    installGraphqlFetchMock({
      StartOperatorHandoff: () => jsonResponse({ data: { startOperatorHandoff: HANDOFF } }),
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));

    await waitFor(() => expect(submitted).not.toBeNull());
    const form = submitted as unknown as HTMLFormElement;
    expect(form.method.toLowerCase()).toBe('post');
    expect(form.action).toBe('http://operator.localhost:3011/open');
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

  it('SAYS OPENING IT PROVES NOTHING, before anybody opens it', () => {
    // The sentence is the control's honesty, not decoration: `settlement_operators`
    // decides, in settlement, inside the transaction that would act — and a
    // console anybody can open is one whose users need to know that.
    installGraphqlFetchMock({});
    render(<OperatorLaunch />);
    expect(screen.getByText(/does not make you an operator/i)).toBeInTheDocument();
    expect(screen.getByText(/every action will be refused/i)).toBeInTheDocument();
    // And what the arriving credential is worth.
    // The ABSENCE is what is asserted, because the regression is a rewrite
    // back to the absolute rather than a deletion of the paragraph.
    expect(screen.queryByText(/reaches none of your own estate/i)).toBeNull();
    expect(
      screen.getByText(/cannot reach your assets, documents, people or vault/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/cannot be renewed/i)).toBeInTheDocument();
  });

  it('takes the origin from the SERVER rather than a baked-in constant', async () => {
    // The M8 PR5 lesson: a value serialised at build time gets baked wrong and
    // nothing notices until production.
    installGraphqlFetchMock({
      StartOperatorHandoff: () =>
        jsonResponse({
          data: {
            startOperatorHandoff: { ...HANDOFF, operatorOrigin: 'https://operator.example.test' },
          },
        }),
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));

    await waitFor(() => expect(submitted).not.toBeNull());
    expect((submitted as unknown as HTMLFormElement).action).toBe(
      'https://operator.example.test/open',
    );
  });

  it('prompts for step-up rather than failing, and submits nothing meanwhile', async () => {
    installGraphqlFetchMock({
      StartOperatorHandoff: () => graphqlError('STEPUP_REQUIRED'),
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));

    expect(await screen.findByLabelText(/confirm it’s you/i)).toBeInTheDocument();
    expect(submitted).toBeNull();
  });

  it('uses ITS OWN failure sentence, not the vault’s', async () => {
    // The M12 finding, third surface: `VAULT_UNAVAILABLE`'s copy reassures the
    // reader that nothing about their vault changed, on a page where nothing
    // was opening a vault.
    installGraphqlFetchMock({
      StartOperatorHandoff: () => graphqlError('OPERATOR_UNAVAILABLE'),
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));

    expect(await screen.findByText(/couldn’t open the operator console/i)).toBeInTheDocument();
    expect(screen.queryByText(/about your vault/i)).not.toBeInTheDocument();
    expect(submitted).toBeNull();
  });

  it('CANCELLING the step-up puts the prompt away and submits nothing', async () => {
    /*
     * The M16 PR5 finding, which is the reason this is asserted rather than
     * read: a step-up prompt is a CONSENT ceremony, and the one thing it must
     * never do is proceed after consent is withdrawn. `StepUpPrompt` owns the
     * abort; what this page owns is putting the prompt away when it says so,
     * and NOT submitting a form on the way past.
     */
    installGraphqlFetchMock({
      StartOperatorHandoff: () => graphqlError('STEPUP_REQUIRED'),
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));
    expect(await screen.findByLabelText(/confirm it’s you/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));

    await waitFor(() => {
      expect(screen.queryByLabelText(/confirm it’s you/i)).not.toBeInTheDocument();
    });
    expect(submitted).toBeNull();
    // And the page is usable again rather than stuck mid-ceremony.
    expect(screen.getByRole('button', { name: /open the console/i })).toBeEnabled();
  });

  it('never submits a form when the response carries no code', async () => {
    // A version-skewed BFF answering `{"data":{}}` is the M11 browser-only
    // defect's shape. It must not become a POST of `code=undefined` at an
    // isolated origin.
    installGraphqlFetchMock({ StartOperatorHandoff: () => jsonResponse({ data: {} }) });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));

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
      StartOperatorHandoff: async () => {
        mints += 1;
        if (mints === 1) return graphqlError('STEPUP_REQUIRED');
        await held;
        return jsonResponse({
          data: {
            startOperatorHandoff: {
              code: 'LIVE-CODE',
              expiresAt: 'x',
              operatorOrigin: 'https://operator.example.test',
            },
          },
        });
      },
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));
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
      StartOperatorHandoff: async () => {
        mints += 1;
        if (mints === 1) return graphqlError('STEPUP_REQUIRED');
        await held;
        return graphqlError('STEPUP_REQUIRED');
      },
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));
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
      StartOperatorHandoff: () => {
        mints += 1;
        return graphqlError(mints === 1 ? 'STEPUP_REQUIRED' : 'TOO_MANY_ATTEMPTS');
      },
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));
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
      StartOperatorHandoff: () => {
        mints += 1;
        if (mints === 1) return graphqlError('STEPUP_REQUIRED');
        return jsonResponse({
          data: {
            startOperatorHandoff: {
              code: 'LIVE-CODE',
              expiresAt: 'x',
              operatorOrigin: 'https://operator.example.test',
            },
          },
        });
      },
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));
    await screen.findByLabelText(/confirm it’s you/i);
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    await waitFor(() => {
      expect(screen.queryByLabelText(/confirm it’s you/i)).not.toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));
    await waitFor(() => expect(submitted).not.toBeNull());
    expect((submitted as unknown as HTMLFormElement).action).toBe(
      'https://operator.example.test/open',
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
      StartOperatorHandoff: () =>
        jsonResponse({
          data: {
            startOperatorHandoff: {
              code: 'LIVE-CODE',
              expiresAt: 'x',
              operatorOrigin: 'https://operator.example.test',
            },
          },
        }),
    });
    (HTMLFormElement.prototype.submit as jest.Mock).mockImplementation(function blocked(
      this: void,
    ): void {
      // What the browser does: refuse the navigation and dispatch the violation.
      const event = new Event('securitypolicyviolation');
      // `violatedDirective` is read-only on the real interface, so it is
      // DEFINED rather than assigned — jsdom implements neither the event nor
      // the enforcement, so the browser's half is modelled here.
      Object.defineProperty(event, 'violatedDirective', { value: 'form-action' });
      document.dispatchEvent(event);
    });
    render(<OperatorLaunch />);
    fireEvent.click(screen.getByRole('button', { name: /open the console/i }));

    // The ERROR ITSELF, not merely that a status region exists — `FormStatus`
    // renders its node either way, so asserting the region is satisfied by a
    // page that reported nothing at all.
    expect(await screen.findByRole('status')).toHaveTextContent(/\S/);
    expect(document.querySelector<HTMLInputElement>('input[name="code"]')?.value).toBe('');
    expect(screen.getByRole('button', { name: /open the console/i })).toBeEnabled();
  });
});
