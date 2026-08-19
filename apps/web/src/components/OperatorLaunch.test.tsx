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

  beforeEach(() => {
    submitted = null;
    jest.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(function mockSubmit(
      this: void,
    ): void {
      submitted = document.querySelector('form');
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
    expect(form.querySelector<HTMLInputElement>('input[name="code"]')?.value).toBe(HANDOFF.code);

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
    expect(screen.getByText(/reaches none of your own estate/i)).toBeInTheDocument();
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
});
