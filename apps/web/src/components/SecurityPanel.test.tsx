import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { errorCopy, passwordChangeMessageFor, stepUpMessageFor } from '../lib/copy';
import {
  SESSION_CACHE_TTL_MS,
  STEP_UP_PROPAGATION_BUDGET_MS,
  STEP_UP_RETRY_INTERVAL_MS,
} from '../lib/step-up';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { SecurityPanel } from './SecurityPanel';

const pushMock = jest.fn();
const refreshMock = jest.fn();
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: pushMock, refresh: refreshMock }),
}));

const session = {
  userId: 'a0c8f6de-0000-4000-8000-000000000001',
  mfaLevel: 'MFA',
  stepUpFresh: false,
};

function sessionHandler(): Response {
  return jsonResponse({ data: { session } });
}

/**
 * A session with NO second factor — the state every brand-new account is in,
 * and the branch no test had ever rendered before M20 PR1.
 *
 * `mfaLevel` is the BFF's GraphQL enum, so the wire carries the member NAME.
 * This app declared the union in lowercase from M2 until M20, which made
 * `session.mfaLevel === 'none'` permanently false and told a factorless account
 * it had a factor. The fixtures could not catch it because they spoke the same
 * invented vocabulary; `graphql/enum-parity.test.ts` now derives the union from
 * the BFF's SDL, and this fixture pins what the user actually sees.
 */
const factorlessSessionHandler = (): Response =>
  jsonResponse({ data: { session: { ...session, mfaLevel: 'NONE' } } });

/**
 * The live-credential rows, in identity's own vocabulary. `current` is the
 * session this browser holds — the one row whose revoke button is a sign-out.
 */
const CURRENT_BROWSER = {
  sessionId: '11111111-0000-4000-8000-000000000001',
  audience: 'ACCOUNT',
  createdAt: '2026-08-10T09:00:00.000Z',
  expiresAt: '2026-09-09T09:00:00.000Z',
  current: true,
};
const PAIRED_EXTENSION = {
  sessionId: '22222222-0000-4000-8000-000000000002',
  audience: 'EXTENSION',
  createdAt: '2026-08-10T10:00:00.000Z',
  expiresAt: '2026-09-09T10:00:00.000Z',
  current: false,
};

function sessionsHandler(rows: unknown[] = [CURRENT_BROWSER, PAIRED_EXTENSION]): OperationHandler {
  return () => jsonResponse({ data: { sessions: rows } });
}

async function rowFor(name: string): Promise<HTMLElement> {
  return (await screen.findByText(name)).closest('li') as HTMLElement;
}

describe('SecurityPanel', () => {
  it('shows a sign-in prompt when the session is unauthenticated', async () => {
    installGraphqlFetchMock({
      Session: () => graphqlError('UNAUTHENTICATED'),
      Sessions: () => graphqlError('UNAUTHENTICATED'),
    });
    render(<SecurityPanel />);

    expect(await screen.findByText('Sign in required')).toBeInTheDocument();
    expect(screen.queryByText('Export data (demo)')).not.toBeInTheDocument();
  });

  it('reveals the step-up prompt when export fails with STEPUP_REQUIRED, then succeeds after step-up', async () => {
    let exportCalls = 0;
    const exportHandler: OperationHandler = () => {
      exportCalls += 1;
      return exportCalls === 1
        ? graphqlError('STEPUP_REQUIRED')
        : jsonResponse({ data: { exportDemo: { ok: true } } });
    };
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      ExportDemo: exportHandler,
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    });
    render(<SecurityPanel />);

    // The prompt is hidden until an action is actually refused.
    const exportButton = await screen.findByRole('button', { name: 'Export data (demo)' });
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();

    fireEvent.click(exportButton);
    expect(await screen.findByText(errorCopy.STEPUP_REQUIRED)).toBeInTheDocument();
    const codeInput = screen.getByLabelText('Confirm it’s you');
    expect(screen.queryByText(/Export started/)).not.toBeInTheDocument();

    // The prompt RETRIES THE REFUSED ACTION itself — no second press.
    fireEvent.change(codeInput, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and export' }));
    expect(await screen.findByText(/Export started/)).toBeInTheDocument();
    expect(exportCalls).toBe(2);
  });

  /**
   * WHAT THIS FIXTURE CAN AND CANNOT DECIDE (M24 PR4 review).
   *
   * The test that stood here was named "tells an account with no second factor
   * that it has none" and its only input was `mfaLevel: 'NONE'` — a SESSION
   * field, byte-identical for a factorless account and for a TOTP-holding one
   * signing in with a password. So it was named for a property its fixture
   * cannot decide, and it stayed green on the arm where the wording was wrong.
   * That is why the same defect had to be found by a human signing in, twice,
   * in two milestones.
   *
   * `AuthService.login` never asks for a factor, so `mfaLevel: 'NONE'` on a
   * fresh sign-in is the NORMAL state of a well-protected account. The page can
   * therefore say only what the field measures.
   */
  it('describes the SESSION, and claims nothing about what the account has enrolled', async () => {
    installGraphqlFetchMock({ Session: factorlessSessionHandler, Sessions: sessionsHandler() });
    render(<SecurityPanel />);

    expect(await screen.findByText('Password-only session')).toBeInTheDocument();
    expect(screen.queryByText('Second factor verified')).not.toBeInTheDocument();
  });

  it('offers ONE authenticator label, because this session cannot tell which is true', async () => {
    // The label was keyed on `mfaLevel`, so a TOTP-holding owner on a
    // password-only session was offered a FIRST enrolment — and refused when
    // they took it, by `SecondFactorGate`. THE DISAGREEING ARM is the point of
    // this test: the session says NONE while the account holds a factor, which
    // is exactly what the server's refusal below reveals.
    installGraphqlFetchMock({
      Session: factorlessSessionHandler,
      Sessions: sessionsHandler(),
      TotpEnroll: () => graphqlError('STEPUP_REQUIRED'),
    });
    render(<SecurityPanel />);

    const enroll = await screen.findByRole('button', { name: 'Add an authenticator app' });
    expect(screen.queryByRole('button', { name: /Set up authenticator app/ })).toBeNull();
    fireEvent.click(enroll);

    // The refusal names the remedy AND carries the fact the page could not:
    // this account already has a factor. The generic copy states the rule and
    // stops there, which is where this arm used to dead-end.
    expect(
      await screen.findByText(/Adding a factor to an account that has one needs a fresh/),
    ).toBeInTheDocument();
    expect(screen.queryByText(errorCopy.STEPUP_REQUIRED)).not.toBeInTheDocument();
  });

  it('an ELEVATED session reads as verified — the other arm of the same field', async () => {
    installGraphqlFetchMock({ Session: sessionHandler, Sessions: sessionsHandler() });
    render(<SecurityPanel />);
    expect(await screen.findByText('Second factor verified')).toBeInTheDocument();
  });

  it('treats a MISSING session field as no data, never as a signed-in session', async () => {
    // The M20 PR5 finding: `result.data.session !== null` admits `undefined`,
    // so a BFF predating this query (`{"data":{}}`) produced
    // `{kind:'signedIn', session: undefined}` and white-screened the page on
    // the next dereference. A missing field is NO DATA — and an ERROR rather
    // than a sign-out, because a version skew says nothing whatever about
    // whether this caller is signed in.
    installGraphqlFetchMock({
      Session: () => jsonResponse({ data: {} }),
      Sessions: sessionsHandler(),
    });
    render(<SecurityPanel />);

    expect(
      await screen.findByText(
        'We couldn’t load your security settings. Please try again in a moment.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText('Sign in required')).not.toBeInTheDocument();
  });

  it('rejects a malformed step-up code client-side', async () => {
    installGraphqlFetchMock({ Session: sessionHandler, Sessions: sessionsHandler() });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Verify your identity' }));
    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '12ab' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm identity' }));

    expect(await screen.findByText('The code is 6 digits, numbers only.')).toBeInTheDocument();
  });

  it('shows the otpauth URI as copyable text after enrollment begins', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      TotpEnroll: () =>
        jsonResponse({
          data: { totpEnroll: { otpauthUri: 'otpauth://totp/Estate:demo?secret=ABC123' } },
        }),
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Add an authenticator app' }));

    const uriField = await screen.findByLabelText('Enrollment link (otpauth URI)');
    expect(uriField).toHaveValue('otpauth://totp/Estate:demo?secret=ABC123');
    expect(uriField).toHaveAttribute('readonly');
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(screen.getByLabelText('6-digit code')).toBeInTheDocument();
  });

  /**
   * The M12 finding, which had never been applied to this page: identity answers
   * `invalid_credentials` for a rejected TOTP code exactly as for a rejected
   * password, so the generic copy told someone to re-check "that email and
   * password combination" about a form with neither field on it.
   */
  it('tells an enrolling user their CODE was refused, not their password', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      TotpEnroll: () => jsonResponse({ data: { totpEnroll: { otpauthUri: 'otpauth://x' } } }),
      TotpVerify: () => graphqlError('INVALID_CREDENTIALS'),
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Add an authenticator app' }));
    fireEvent.change(await screen.findByLabelText('6-digit code'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm enrollment' }));

    expect(await screen.findByText(stepUpMessageFor('INVALID_CREDENTIALS'))).toBeInTheDocument();
    expect(screen.queryByText(errorCopy.INVALID_CREDENTIALS)).not.toBeInTheDocument();
  });

  /**
   * The M15 PR3 defect this page was one edit away from reproducing: two fields
   * on one screen carrying the same label. `StepUpPrompt` labels its input
   * "Confirm it's you" for every caller, so two prompts open at once are two
   * inputs neither a person nor a query can tell apart.
   */
  it('never has two step-up prompts open at once', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      StartExtensionPairing: () => graphqlError('STEPUP_REQUIRED'),
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Verify your identity' }));
    expect(screen.getAllByLabelText('Confirm it’s you')).toHaveLength(1);
    // Every other action that could open one is closed off while it is up.
    expect(screen.getByRole('button', { name: 'Create a pairing code' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Export data (demo)' })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => {
      expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
    });
  });
});

describe('paired devices', () => {
  it('lists each live credential with what it can reach, and marks this browser', async () => {
    installGraphqlFetchMock({ Session: sessionHandler, Sessions: sessionsHandler() });
    render(<SecurityPanel />);

    const current = await rowFor('Signed-in browser');
    expect(within(current).getByText('This browser')).toBeInTheDocument();
    expect(within(current).getByText(/revoking it signs you out of this browser/i)).toBeVisible();
    expect(within(current).getByRole('button', { name: 'Sign out of this browser' })).toBeVisible();

    const extension = await rowFor('Browser extension');
    expect(within(extension).queryByText('This browser')).not.toBeInTheDocument();
    // The row says what the credential REACHES — the boundary M16 exists to
    // create, in the one place a user reads it.
    expect(within(extension).getByText(/cannot reset your vault/i)).toBeVisible();
    expect(within(extension).getByRole('button', { name: 'Revoke' })).toBeVisible();
  });

  it('revokes another credential on one click — no step-up — and re-reads the list', async () => {
    let listCalls = 0;
    const revoked: unknown[] = [];
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: () => {
        listCalls += 1;
        return jsonResponse({
          data: {
            sessions: listCalls === 1 ? [CURRENT_BROWSER, PAIRED_EXTENSION] : [CURRENT_BROWSER],
          },
        });
      },
      RevokeSession: (variables) => {
        revoked.push(variables);
        return jsonResponse({ data: { revokeSession: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    fireEvent.click(
      within(await rowFor('Browser extension')).getByRole('button', { name: 'Revoke' }),
    );

    await waitFor(() => {
      expect(revoked).toEqual([{ sessionId: PAIRED_EXTENSION.sessionId }]);
    });
    // No prompt was ever raised: the protective action is never harder than the
    // permissive one (M6).
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByText('Browser extension')).not.toBeInTheDocument();
    });
  });

  /**
   * THE PAGE MAY NOT PROMISE MORE THAN THE PLATFORM DELIVERS. Identity 401s at
   * once, but peers introspect through a POSITIVE cache, so the credential is
   * still accepted at the vault for up to one TTL — measured at 33 seconds in
   * M16 PR1's live drive. docs/03 §6j names the fix as copy rather than a
   * shorter TTL; these two cases are what stop it drifting back.
   *
   * The number is asserted against `SESSION_CACHE_TTL_MS`, which
   * `step-up.test.ts` in turn pins to auth-guard's own constant — so raising
   * the TTL moves the sentence instead of falsifying it.
   */
  it('never claims a revoke is instant, and names the window it really has', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: () => jsonResponse({ data: { sessions: [CURRENT_BROWSER, PAIRED_EXTENSION] } }),
      RevokeSession: () => jsonResponse({ data: { revokeSession: { ok: true } } }),
    });
    render(<SecurityPanel />);

    const seconds = Math.ceil(SESSION_CACHE_TTL_MS / 1000);
    const intro = await screen.findByText(/Everything that can currently reach your account/);
    expect(intro.textContent).toContain(`up to ${seconds} seconds to stop accepting it`);
    // The exact word the old copy used, and the reason this test exists.
    expect(intro.textContent).not.toMatch(/takes effect immediately/);

    fireEvent.click(
      within(await rowFor('Browser extension')).getByRole('button', { name: 'Revoke' }),
    );

    // The confirmation carries the same caveat: someone who acts on a suspected
    // compromise reads THIS sentence, not the paragraph above it.
    const note = await screen.findByText(/is revoked\./);
    expect(note.textContent).toContain(`up to ${seconds} seconds to stop accepting it`);
    expect(note.textContent).not.toMatch(/can no longer be used/);
  });

  /**
   * Revoking the credential you are HOLDING goes through logout, because only
   * logout also expires the cookies carrying it. Revoking without clearing them
   * leaves a browser that still looks signed in over a dead session — what M8's
   * logout entry calls the worst outcome.
   */
  it('signs out through logout when the row is this browser’s own session', async () => {
    const calls: string[] = [];
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      RevokeSession: () => {
        calls.push('RevokeSession');
        return jsonResponse({ data: { revokeSession: { ok: true } } });
      },
      Logout: () => {
        calls.push('Logout');
        return jsonResponse({ data: { logout: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    fireEvent.click(
      within(await rowFor('Signed-in browser')).getByRole('button', {
        name: 'Sign out of this browser',
      }),
    );

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith('/login');
    });
    expect(calls).toEqual(['Logout']);
  });

  it('reads a response with no sessions field as NO DATA, never as an empty list', async () => {
    // A BFF that predates this query answers {"data":{}}. An empty list here
    // would read as "nothing else can reach your account" — the most reassuring
    // sentence on the page, said on the strength of a version skew.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: () => jsonResponse({ data: {} }),
    });
    render(<SecurityPanel />);

    expect(await screen.findByText(/isn’t a complete picture/)).toBeInTheDocument();
  });

  it('renders an audience this build has never heard of, and still offers to revoke it', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler([{ ...PAIRED_EXTENSION, audience: 'SOMETHING_NEW' }]),
    });
    render(<SecurityPanel />);

    const row = await rowFor('Unrecognised credential');
    expect(within(row).getByRole('button', { name: 'Revoke' })).toBeVisible();
  });
});

describe('extension pairing', () => {
  const MINTED = { code: 'EP1-ABCD-EFGH-JKMN', expiresAt: '2026-08-10T12:10:00.000Z' };

  it('shows the code once, having prompted for a step-up and retried the SAME action', async () => {
    let mintCalls = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      StartExtensionPairing: () => {
        mintCalls += 1;
        return mintCalls === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { startExtensionPairing: MINTED } });
      },
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Create a pairing code' }));
    const codeInput = await screen.findByLabelText('Confirm it’s you');
    expect(screen.queryByText(MINTED.code)).not.toBeInTheDocument();

    fireEvent.change(codeInput, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and create the code' }));

    expect(await screen.findByText(MINTED.code)).toBeInTheDocument();
    expect(mintCalls).toBe(2);
    expect(screen.getByText(/only time we can show it to you/i)).toBeVisible();
    // The prompt closes on success rather than sitting under the code it minted.
    await waitFor(() => {
      expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
    });
  });

  /**
   * Peers learn of an elevation through a 30-second positive introspection
   * cache, so the retry must POLL. Returning 'applied' on a still-refused
   * action would put back the M13 single-shot defect: an accepted code and a
   * prompt that sits there doing nothing.
   */
  it('keeps retrying while the peer still refuses, then shows the code', async () => {
    jest.useFakeTimers();
    try {
      let mintCalls = 0;
      installGraphqlFetchMock({
        Session: sessionHandler,
        Sessions: sessionsHandler(),
        StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
        StartExtensionPairing: () => {
          mintCalls += 1;
          return mintCalls < 3
            ? graphqlError('STEPUP_REQUIRED')
            : jsonResponse({ data: { startExtensionPairing: MINTED } });
        },
      });
      render(<SecurityPanel />);

      fireEvent.click(await screen.findByRole('button', { name: 'Create a pairing code' }));
      const codeInput = await screen.findByLabelText('Confirm it’s you');
      fireEvent.change(codeInput, { target: { value: '123456' } });
      fireEvent.click(screen.getByRole('button', { name: 'Confirm and create the code' }));

      await jest.advanceTimersByTimeAsync(STEP_UP_PROPAGATION_BUDGET_MS);
      await waitFor(() => {
        expect(screen.getByText(MINTED.code)).toBeInTheDocument();
      });
      expect(mintCalls).toBe(3);
    } finally {
      jest.useRealTimers();
    }
  });

  /**
   * CANCEL MUST CANCEL. The M13 review's round-3 finding was a prompt whose
   * retry loop kept running after the owner declined and applied the action
   * anyway — measured there as a designation appearing on the §5.1 executor
   * chain with no UI signal, because React makes the post-unmount `setState` a
   * silent no-op. Here the action mints a credential, so the same defect would
   * hand out a pairing code the owner had just refused to create.
   */
  it('mints nothing after the owner cancels mid-retry', async () => {
    jest.useFakeTimers();
    try {
      let mintCalls = 0;
      installGraphqlFetchMock({
        Session: sessionHandler,
        Sessions: sessionsHandler(),
        StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
        StartExtensionPairing: () => {
          mintCalls += 1;
          return graphqlError('STEPUP_REQUIRED');
        },
      });
      render(<SecurityPanel />);

      fireEvent.click(await screen.findByRole('button', { name: 'Create a pairing code' }));
      fireEvent.change(await screen.findByLabelText('Confirm it’s you'), {
        target: { value: '123456' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Confirm and create the code' }));

      await jest.advanceTimersByTimeAsync(STEP_UP_RETRY_INTERVAL_MS * 2);
      const beforeCancel = mintCalls;
      expect(beforeCancel).toBeGreaterThan(1);

      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
      await jest.advanceTimersByTimeAsync(STEP_UP_PROPAGATION_BUDGET_MS);

      expect(mintCalls).toBe(beforeCancel);
      expect(screen.queryByText(/only time we can show it to you/i)).not.toBeInTheDocument();
    } finally {
      jest.useRealTimers();
    }
  });

  /**
   * Found by driving the real app: the Session card kept reading "Step-up not
   * fresh" straight after a pairing code had been minted through a genuine
   * step-up, because only the standalone verify path re-read the session. A
   * security page stating the opposite of its own current state is quiet,
   * plausible, and about exactly the thing the page exists to report.
   */
  it('re-reads the session after an elevation, so the freshness chip is not stale', async () => {
    let sessionCalls = 0;
    installGraphqlFetchMock({
      Session: () => {
        sessionCalls += 1;
        return jsonResponse({ data: { session: { ...session, stepUpFresh: sessionCalls > 1 } } });
      },
      Sessions: sessionsHandler(),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      StartExtensionPairing: () =>
        sessionCalls > 0 && screen.queryByLabelText('Confirm it’s you') !== null
          ? jsonResponse({ data: { startExtensionPairing: MINTED } })
          : graphqlError('STEPUP_REQUIRED'),
    });
    render(<SecurityPanel />);

    expect(await screen.findByText('Step-up not fresh')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create a pairing code' }));
    fireEvent.change(await screen.findByLabelText('Confirm it’s you'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and create the code' }));

    expect(await screen.findByText('Step-up fresh')).toBeInTheDocument();
  });

  it('never renders a code it did not receive', async () => {
    // The VaultLaunch defect, one surface over: a version skew arrives as
    // {"data":{}} and a pairing code is a value people COPY, so "undefined" on
    // screen is worse than any refusal.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      StartExtensionPairing: () => jsonResponse({ data: {} }),
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Create a pairing code' }));

    expect(await screen.findByText(errorCopy.PAIRING_UNAVAILABLE)).toBeInTheDocument();
    expect(screen.queryByText('undefined')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create a pairing code' })).toBeVisible();
  });

  /**
   * A pairing failure must not say "nothing about your vault has changed" on a
   * screen about a browser extension — the M12 finding, which is why
   * PAIRING_UNAVAILABLE exists rather than reusing VAULT_UNAVAILABLE.
   */
  it('says what failed in the words of the thing that failed', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      StartExtensionPairing: () => graphqlError('PAIRING_UNAVAILABLE'),
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Create a pairing code' }));

    expect(await screen.findByText(errorCopy.PAIRING_UNAVAILABLE)).toBeInTheDocument();
    // Specifically NOT the vault's sentence, which reassures the reader that
    // "nothing about your vault has changed" on a screen where nothing was
    // touching a vault.
    expect(screen.queryByText(errorCopy.VAULT_UNAVAILABLE)).not.toBeInTheDocument();
  });
});

/**
 * THE PASSKEYS SECTION (M17 PR5).
 *
 * jsdom has no `navigator.credentials` and no `PublicKeyCredential` — and the
 * double installed here is FAITHFUL ABOUT WHAT IT ADDS (the M16 chrome-double
 * lesson): each case installs exactly the capability it claims the browser
 * has, and the no-support case installs nothing and asserts the surface says
 * so rather than rendering a broken button.
 */
describe('SecurityPanel passkeys', () => {
  const PASSKEY = {
    id: 'pk-00000000-0000-4000-8000-000000000001',
    nickname: 'MacBook Touch ID',
    isHardwareKey: false,
    createdAt: '2026-08-01T09:00:00.000Z',
    lastUsedAt: '2026-08-12T09:00:00.000Z',
  };

  function installPublicKeyCredential(): void {
    (window as unknown as Record<string, unknown>)['PublicKeyCredential'] = function stub(): void {
      /* presence is the capability signal */
    };
  }

  afterEach(() => {
    delete (window as unknown as Record<string, unknown>)['PublicKeyCredential'];
    delete (navigator as unknown as Record<string, unknown>)['credentials'];
  });

  it('renders the list, and the no-support sentence when the browser lacks the API', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      Passkeys: () => jsonResponse({ data: { passkeys: [PASSKEY] } }),
    });
    render(<SecurityPanel />);

    expect(await screen.findByText('MacBook Touch ID')).toBeInTheDocument();
    expect(screen.getByText(/does not support passkeys/)).toBeInTheDocument();
    expect(screen.queryByText('Add a passkey')).not.toBeInTheDocument();
  });

  it('an unreadable list is an honest error, never an empty list', async () => {
    // A BFF predating the query answers {"data":{}} — the M11 shape. An empty
    // list here would read "no passkeys", a claim the page cannot make.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      Passkeys: () => jsonResponse({ data: {} }),
    });
    render(<SecurityPanel />);

    expect(await screen.findByText(/could not be loaded just now/)).toBeInTheDocument();
    expect(screen.queryByText('No passkeys on this account yet.')).not.toBeInTheDocument();
  });

  it('ADD walks the ceremony: options → create → verify → reload', async () => {
    installPublicKeyCredential();
    const created = {
      id: 'new-cred',
      rawId: new Uint8Array([1]).buffer,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: new Uint8Array([2]).buffer,
        attestationObject: new Uint8Array([3]).buffer,
        getTransports: () => ['internal'],
      },
    };
    const create = jest.fn().mockResolvedValue(created);
    (navigator as unknown as Record<string, unknown>)['credentials'] = { create };

    let registered = false;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      Passkeys: () => jsonResponse({ data: { passkeys: registered ? [PASSKEY] : [] } }),
      WebauthnRegisterOptions: () =>
        jsonResponse({
          data: {
            webauthnRegisterOptions: {
              challenge: 'AQID',
              rp: { id: 'localhost', name: 'Estate' },
              user: { id: 'CQk', name: 'user-uuid' },
            },
          },
        }),
      WebauthnRegister: (variables) => {
        registered = true;
        // The encoded attestation crossed as JSON — the codec's output, not a
        // hand-built object.
        const response = (variables as { response: { rawId: string } }).response;
        expect(response.rawId).toBe('AQ');
        return jsonResponse({ data: { webauthnRegister: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByText('Add a passkey'));
    expect(await screen.findByText(/Passkey added/)).toBeInTheDocument();
    expect(create).toHaveBeenCalledTimes(1);
    expect(await screen.findByText('MacBook Touch ID')).toBeInTheDocument();
  });

  it('a CLOSED platform sheet renders the local sentence, never platform copy', async () => {
    installPublicKeyCredential();
    (navigator as unknown as Record<string, unknown>)['credentials'] = {
      create: jest.fn().mockRejectedValue(new DOMException('x', 'NotAllowedError')),
    };
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      WebauthnRegisterOptions: () =>
        jsonResponse({
          data: {
            webauthnRegisterOptions: {
              challenge: 'AQID',
              rp: { id: 'localhost', name: 'Estate' },
              user: { id: 'CQk', name: 'user-uuid' },
            },
          },
        }),
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByText('Add a passkey'));
    expect(await screen.findByText(/prompt was closed or timed out/)).toBeInTheDocument();
    // Nothing was changed — and nothing claims otherwise.
    expect(screen.queryByText(/Passkey added/)).not.toBeInTheDocument();
  });

  it('the enrolment gate refusal points at the verify section, in its own words', async () => {
    installPublicKeyCredential();
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      WebauthnRegisterOptions: () => graphqlError('STEPUP_REQUIRED'),
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByText('Add a passkey'));
    expect(
      await screen.findByText(/needs a fresh identity check — verify below/),
    ).toBeInTheDocument();
  });

  it('REMOVE prompts for step-up and retries THE SAME removal after elevation', async () => {
    installPublicKeyCredential();
    let elevated = false;
    let revoked = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      Passkeys: () => jsonResponse({ data: { passkeys: revoked > 0 ? [] : [PASSKEY] } }),
      RevokePasskey: (variables) => {
        expect((variables as { id: string }).id).toBe(PASSKEY.id);
        if (!elevated) {
          return graphqlError('STEPUP_REQUIRED');
        }
        revoked += 1;
        return jsonResponse({ data: { revokePasskey: { ok: true } } });
      },
      StepUp: () => {
        elevated = true;
        return jsonResponse({ data: { stepUp: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    const row = await rowFor('MacBook Touch ID');
    fireEvent.click(within(row).getByText('Remove'));

    // The refusal opened the shared prompt, with THIS removal named.
    const prompt = await screen.findByText(/Confirm to remove “MacBook Touch ID”/);
    expect(prompt).toBeInTheDocument();
    const code = screen.getByLabelText('Confirm it’s you');
    fireEvent.change(code, { target: { value: '123456' } });
    fireEvent.submit(code.closest('form') as HTMLFormElement);

    expect(await screen.findByText(/Passkey removed/)).toBeInTheDocument();
    expect(revoked).toBe(1);
  });

  it('RENAME refuses an empty label locally, before any round trip', async () => {
    installPublicKeyCredential();
    let called = false;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      Passkeys: () => jsonResponse({ data: { passkeys: [PASSKEY] } }),
      RenamePasskey: () => {
        called = true;
        return jsonResponse({ data: { renamePasskey: { ok: true } } });
      },
    });
    render(<SecurityPanel />);
    const row = await rowFor('MacBook Touch ID');
    fireEvent.click(within(row).getByText('Name'));
    fireEvent.change(screen.getByLabelText('Passkey name'), { target: { value: '   ' } });
    fireEvent.click(screen.getByText('Save name'));
    expect(await screen.findByText(/needs 1–64 characters/)).toBeInTheDocument();
    expect(called).toBe(false);
  });

  it('RENAME saves through the label field', async () => {
    installPublicKeyCredential();
    let renamed: string | null = null;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      Passkeys: () =>
        jsonResponse({
          data: { passkeys: [{ ...PASSKEY, nickname: renamed ?? PASSKEY.nickname }] },
        }),
      RenamePasskey: (variables) => {
        renamed = (variables as { nickname: string }).nickname;
        return jsonResponse({ data: { renamePasskey: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    const row = await rowFor('MacBook Touch ID');
    fireEvent.click(within(row).getByText('Name'));
    fireEvent.change(screen.getByLabelText('Passkey name'), { target: { value: 'Work laptop' } });
    fireEvent.click(screen.getByText('Save name'));

    expect(await screen.findByText('Work laptop')).toBeInTheDocument();
    expect(renamed).toBe('Work laptop');
  });
});

/**
 * M20 PR1 — the account password change.
 *
 * The load-bearing case is the retry: the form stays mounted behind the prompt,
 * so a retry that re-read the inputs could set a password the user never
 * confirmed. It must re-send the ATTEMPT.
 */
describe('SecurityPanel — password change', () => {
  const FIELDS = {
    current: 'Current password',
    next: 'New password',
    confirm: 'Confirm new password',
  } as const;

  function fill(values: { current: string; next: string; confirm: string }): void {
    fireEvent.change(screen.getByLabelText(FIELDS.current), {
      target: { value: values.current },
    });
    fireEvent.change(screen.getByLabelText(FIELDS.next), { target: { value: values.next } });
    fireEvent.change(screen.getByLabelText(FIELDS.confirm), {
      target: { value: values.confirm },
    });
  }

  it('changes the password and says the other devices were signed out', async () => {
    const calls: Array<Record<string, unknown>> = [];
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      ChangePassword: (variables) => {
        calls.push(variables as Record<string, unknown>);
        return jsonResponse({ data: { changePassword: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Password' });
    fill({ current: 'old-passphrase', next: 'a-much-longer-one', confirm: 'a-much-longer-one' });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    // The consequence a user needs to know, said on the surface that caused it.
    expect(
      await screen.findByText('Password changed. Your other devices have been signed out.'),
    ).toBeInTheDocument();
    expect(calls).toEqual([
      { currentPassword: 'old-passphrase', newPassword: 'a-much-longer-one' },
    ]);
    // Credentials do not linger in the DOM once they have been spent.
    expect(screen.getByLabelText(FIELDS.current)).toHaveValue('');
    expect(screen.getByLabelText(FIELDS.next)).toHaveValue('');
  });

  it('refuses a mismatched confirmation without calling the server', async () => {
    // A typo here is not recoverable: the change would succeed with a value
    // nobody knows, and the reset surface that would undo it is M20 PR3.
    let calls = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      ChangePassword: () => {
        calls += 1;
        return jsonResponse({ data: { changePassword: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Password' });
    fill({ current: 'old', next: 'a-much-longer-one', confirm: 'a-much-longer-typo' });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    expect(await screen.findByText('Those passwords don’t match.')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it('explains a wrong CURRENT password without mentioning an email field', async () => {
    // The M12 defect, one form over: `INVALID_CREDENTIALS` is shared with login,
    // where it means "email and password". This form has no email on it.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      ChangePassword: () => graphqlError('INVALID_CREDENTIALS'),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Password' });
    fill({ current: 'wrong', next: 'a-much-longer-one', confirm: 'a-much-longer-one' });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    expect(
      await screen.findByText(
        'That current password wasn’t right. Check it and try again — your password has not been changed.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(errorCopy.INVALID_CREDENTIALS)).not.toBeInTheDocument();
  });

  it('REPLACES the form while a change is pending, and retries with the same values', async () => {
    const calls: Array<Record<string, unknown>> = [];
    let changeCalls = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      ChangePassword: (variables) => {
        changeCalls += 1;
        calls.push(variables as Record<string, unknown>);
        return changeCalls === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { changePassword: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Password' });
    fill({ current: 'old-passphrase', next: 'the-real-new-one', confirm: 'the-real-new-one' });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    // THIS is the control, and it is why the carried attempt is belt rather
    // than the fix: with the form gone there is nothing to edit under a pending
    // change, so the retry cannot pick up a value the user never confirmed.
    // (Asserted for all three fields — leaving one mounted would reopen it.)
    expect(await screen.findByText(errorCopy.STEPUP_REQUIRED)).toBeInTheDocument();
    expect(screen.queryByLabelText(FIELDS.current)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(FIELDS.next)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(FIELDS.confirm)).not.toBeInTheDocument();
    // And exactly one "Confirm it's you" exists (the M15 identical-label rule).
    expect(screen.getAllByLabelText('Confirm it’s you')).toHaveLength(1);

    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and change password' }));

    expect(
      await screen.findByText('Password changed. Your other devices have been signed out.'),
    ).toBeInTheDocument();
    // BOTH sends carry the SUBMITTED attempt. This is the assertion the M13
    // review's defect would break.
    expect(calls).toEqual([
      { currentPassword: 'old-passphrase', newPassword: 'the-real-new-one' },
      { currentPassword: 'old-passphrase', newPassword: 'the-real-new-one' },
    ]);
  });

  it('cancelling the prompt applies nothing', async () => {
    let changeCalls = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      ChangePassword: () => {
        changeCalls += 1;
        return graphqlError('STEPUP_REQUIRED');
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Password' });
    fill({ current: 'old-passphrase', next: 'the-real-new-one', confirm: 'the-real-new-one' });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    await screen.findByText(errorCopy.STEPUP_REQUIRED);

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    // The form is back and nothing further was sent — a consent ceremony that
    // proceeds after consent is withdrawn is the one thing it must never do.
    expect(await screen.findByLabelText(FIELDS.next)).toBeInTheDocument();
    expect(changeCalls).toBe(1);
  });

  it('PUTS THE FORM BACK when the retried change is refused for another reason', async () => {
    // The M20 PR5 finding. `StepUpPrompt` does not unmount itself — the parent
    // owns `stepUp`, and this section renders the prompt INSTEAD of the form —
    // so a non-STEPUP failure that returned 'applied' without clearing it left
    // the prompt up, showing an error that tells the reader to re-check a field
    // no longer on screen. It is recoverable only by pressing Cancel, which
    // nothing suggests.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      ChangePassword: (() => {
        let n = 0;
        return () => {
          n += 1;
          // Refused for step-up, then — after a genuine elevation — refused
          // because the current password was wrong all along.
          return graphqlError(n === 1 ? 'STEPUP_REQUIRED' : 'INVALID_CREDENTIALS');
        };
      })(),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Password' });
    fill({ current: 'not-the-one', next: 'the-real-new-one', confirm: 'the-real-new-one' });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    await screen.findByText(errorCopy.STEPUP_REQUIRED);

    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and change password' }));

    // The refusal names the current password — and the field it names is on
    // screen to be corrected, which is the whole property.
    expect(
      await screen.findByText(passwordChangeMessageFor('INVALID_CREDENTIALS')),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(FIELDS.current)).toBeInTheDocument();
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });

  it('RE-READS THE DEVICES after a change, so the page does not contradict itself', async () => {
    // The success copy says "your other devices have been signed out" — true,
    // identity revokes them in the same transaction. Without a re-read the list
    // below went on showing them, so one page asserted both (M20 PR5).
    let sessionsCalls = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: () => {
        sessionsCalls += 1;
        return jsonResponse({
          data: {
            sessions: sessionsCalls === 1 ? [CURRENT_BROWSER, PAIRED_EXTENSION] : [CURRENT_BROWSER],
          },
        });
      },
      ChangePassword: () => jsonResponse({ data: { changePassword: { ok: true } } }),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Password' });
    expect(await screen.findByText('Browser extension')).toBeInTheDocument();

    fill({ current: 'old-passphrase', next: 'a-much-longer-one', confirm: 'a-much-longer-one' });
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    await screen.findByText('Password changed. Your other devices have been signed out.');
    await waitFor(() => expect(screen.queryByText('Browser extension')).not.toBeInTheDocument());
    expect(sessionsCalls).toBe(2);
  });
});

/**
 * M20 PR2 — the sign-in address change.
 *
 * TWO PROPERTIES ARE LOAD-BEARING HERE and neither is about the happy path.
 * The success copy must not claim a delivery, because identity answers 202
 * before it knows whether it will send anything — an address that already
 * belongs to somebody else is answered identically and never mailed. And the
 * "Finish a change" form must exist WITHOUT a request having been made in this
 * tab, because identity exposes no read of a pending change: a code field that
 * appeared only after a local request would strand anyone who closed the page
 * or reads their mail on another device.
 */
describe('SecurityPanel — address change', () => {
  const NEW_ADDRESS = 'somewhere.else@example.test';

  function requestChange(address = NEW_ADDRESS, password = 'the-passphrase'): void {
    fireEvent.change(screen.getByLabelText('New email address'), { target: { value: address } });
    fireEvent.change(screen.getByLabelText('Account password'), { target: { value: password } });
    fireEvent.click(screen.getByRole('button', { name: 'Send a code to the new address' }));
  }

  it('asks for a change WITHOUT claiming anything was sent', async () => {
    const calls: Array<Record<string, unknown>> = [];
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      RequestEmailChange: (variables) => {
        calls.push(variables as Record<string, unknown>);
        return jsonResponse({ data: { requestEmailChange: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    requestChange();

    // CONDITIONAL, and that is the point: "If … isn't already in use here".
    // The 202 is not a delivery receipt, so this surface may not render it as
    // one — and in the one case where nothing is mailed, saying "we've sent you
    // a code" would tell the caller what the silent-availability control exists
    // to withhold.
    const notice = await screen.findByText(/a code is on its way to it/);
    expect(notice.textContent).toContain(`If ${NEW_ADDRESS} isn’t already in use here`);
    expect(notice.textContent).toContain('Nothing has changed yet');
    expect(screen.queryByText(/We’ve sent|We have sent/)).not.toBeInTheDocument();
    expect(calls).toEqual([{ currentPassword: 'the-passphrase', newEmail: NEW_ADDRESS }]);
    // The password is spent and has no reason to stay in a DOM node. The
    // ADDRESS does: the notice above refers to it.
    expect(screen.getByLabelText('Account password')).toHaveValue('');
    expect(screen.getByLabelText('New email address')).toHaveValue(NEW_ADDRESS);
  });

  it('does not judge the address FORMAT — only emptiness', async () => {
    // Identity's schema is the gate. A second opinion here could refuse what
    // the platform would accept (the M12 upload-client rule), so a value with
    // no @ in it must reach the server.
    const calls: Array<Record<string, unknown>> = [];
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      RequestEmailChange: (variables) => {
        calls.push(variables as Record<string, unknown>);
        return jsonResponse({ data: { requestEmailChange: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    requestChange('not-an-address');

    await screen.findByText(/a code is on its way to it/);
    expect(calls).toEqual([{ currentPassword: 'the-passphrase', newEmail: 'not-an-address' }]);
  });

  it('refuses an empty address, and an empty password, without calling the server', async () => {
    let calls = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      RequestEmailChange: () => {
        calls += 1;
        return jsonResponse({ data: { requestEmailChange: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.click(screen.getByRole('button', { name: 'Send a code to the new address' }));
    expect(await screen.findByText('Enter the address you want to move to.')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('New email address'), {
      target: { value: NEW_ADDRESS },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send a code to the new address' }));
    expect(await screen.findByText('Enter your current password.')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it('explains a wrong ACCOUNT password without mentioning an email field', async () => {
    // The M12 collision for the third time: `INVALID_CREDENTIALS` means "email
    // and password" on login and "the password you just typed" here. The shared
    // copy would send somebody to re-check an address that is not the problem —
    // on the one form where an address IS present but is not what was refused,
    // which makes the wrong sentence especially convincing.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      RequestEmailChange: () => graphqlError('INVALID_CREDENTIALS'),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    requestChange();

    expect(
      await screen.findByText(
        'That current password wasn’t right. Check it and try again — your sign-in address has not been changed.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(errorCopy.INVALID_CREDENTIALS)).not.toBeInTheDocument();
  });

  it('names the actionable possibility behind identity’s conflated INVALID_REQUEST', async () => {
    // Identity answers `invalid_request` for BOTH a malformed address and one
    // that is already this account's. It genuinely conflates them, so the copy
    // names the actionable reading without asserting which applied.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      RequestEmailChange: () => graphqlError('INVALID_REQUEST'),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    requestChange();

    const message = await screen.findByText(/if it’s the one you already sign in with/);
    expect(message.textContent).toContain('Nothing has been changed');
    expect(screen.queryByText(errorCopy.INVALID_REQUEST)).not.toBeInTheDocument();
  });

  it('reports the re-issue bound as a considered answer, never as an outage', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      RequestEmailChange: () => graphqlError('CODE_REQUESTED_RECENTLY'),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    requestChange();

    // "If a code arrived" — the conditional again, because the destination
    // bound fires on volume aimed at an address that may never have been
    // mailed at all.
    const message = await screen.findByText(/If a code arrived, use that one/);
    expect(message.textContent).toContain('You asked for this very recently');
  });

  it('REPLACES the request form under a step-up, and retries with the same values', async () => {
    const calls: Array<Record<string, unknown>> = [];
    let requests = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      RequestEmailChange: (variables) => {
        requests += 1;
        calls.push(variables as Record<string, unknown>);
        return requests === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { requestEmailChange: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    requestChange();

    expect(await screen.findByText(errorCopy.STEPUP_REQUIRED)).toBeInTheDocument();
    // The form is gone, so there is nothing to edit under a pending change.
    expect(screen.queryByLabelText('New email address')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Account password')).not.toBeInTheDocument();
    // ONE prompt on the page, and its field is not confusable with the code
    // field beneath it (the M15 identical-label rule, which this section's own
    // "Account password" label exists to satisfy).
    expect(screen.getAllByLabelText('Confirm it’s you')).toHaveLength(1);
    expect(screen.getByLabelText('Code from the new address')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and send the code' }));

    await screen.findByText(/a code is on its way to it/);
    expect(calls).toEqual([
      { currentPassword: 'the-passphrase', newEmail: NEW_ADDRESS },
      { currentPassword: 'the-passphrase', newEmail: NEW_ADDRESS },
    ]);
  });

  it('offers the code form with NO request made in this tab', async () => {
    // Identity exposes no read of a pending change, so this page cannot know on
    // load whether one is outstanding. Gating the field on a local request
    // would strand anyone who asked from another device or closed the page.
    installGraphqlFetchMock({ Session: sessionHandler, Sessions: sessionsHandler() });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    expect(screen.getByLabelText('Code from the new address')).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Confirm new address' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Cancel pending change' })).toBeEnabled();
  });

  it('completes the change, says what it cost, and tells the page to re-read', async () => {
    const calls: Array<Record<string, unknown>> = [];
    const changed = jest.fn();
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      CompleteEmailChange: (variables) => {
        calls.push(variables as Record<string, unknown>);
        return jsonResponse({ data: { completeEmailChange: { ok: true } } });
      },
    });
    render(<SecurityPanel onAddressChanged={changed} />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.change(screen.getByLabelText('Code from the new address'), {
      target: { value: 'EC1-ABCD-EFGH' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm new address' }));

    const done = await screen.findByText(/Your sign-in address has been changed/);
    // Both consequences, on the surface that caused them: the sessions this
    // just ended, and the fact that redeeming the code also PROVED the address.
    expect(done.textContent).toContain('confirmed');
    expect(done.textContent).toContain('other devices have been signed out');
    // EXACTLY AS TYPED — the canonical fold lives in identity.
    expect(calls).toEqual([{ code: 'EC1-ABCD-EFGH' }]);
    // The verified status just moved too, and a sibling panel is showing it.
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it('does not offer a resend that does not exist when a code is refused', async () => {
    // Identity gives one `invalid_code` for every dead reason. The SHARED
    // sentence for that code ends "send yourself a new one", which is the
    // remedy on the address-VERIFICATION surface; there is no resend route for
    // a pending change, and offering one is how a stuck user stays stuck.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      CompleteEmailChange: () => graphqlError('INVALID_VERIFICATION_CODE'),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.change(screen.getByLabelText('Code from the new address'), {
      target: { value: 'EC1-WRONG' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm new address' }));

    const message = await screen.findByText(/cancel this change and start again/);
    expect(message.textContent).toContain('single-use');
    expect(screen.queryByText(errorCopy.INVALID_VERIFICATION_CODE)).not.toBeInTheDocument();
  });

  it('cancels without a step-up, and states what is now true rather than what it did', async () => {
    // The M6 asymmetry: asking is the gated half. Somebody who has just
    // realised they typed the wrong address must not be sent to find an
    // authenticator. And identity's cancel is idempotent and silent — 204
    // whether or not anything was pending — so the copy may not claim an action.
    let cancels = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      CancelEmailChange: () => {
        cancels += 1;
        return jsonResponse({ data: { cancelEmailChange: { ok: true } } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel pending change' }));

    expect(
      await screen.findByText(
        'There is no pending address change. Any code already sent is now dead.',
      ),
    ).toBeInTheDocument();
    expect(cancels).toBe(1);
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });

  it('treats a missing field as NO DATA, never as success', async () => {
    // A BFF predating these mutations answers `{"data":{}}`, which
    // `gqlRequest` admits — and "your address has been changed" is the worst
    // possible thing to say on the strength of a version skew.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      CompleteEmailChange: () => jsonResponse({ data: {} }),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.change(screen.getByLabelText('Code from the new address'), {
      target: { value: 'EC1-ABCD' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm new address' }));

    expect(await screen.findByText(errorCopy.UNKNOWN)).toBeInTheDocument();
    expect(screen.queryByText(/Your sign-in address has been changed/)).not.toBeInTheDocument();
  });
});

/**
 * M24 PR2 — the address on file, revealed on demand (docs/03 §6v residual 2's
 * closure).
 *
 * THE RESTING STATE IS THE PROPERTY. Every reveal spends a logged KMS decrypt
 * and lands two events on the owner's audit trail, so the first assertion in
 * this block is a NEGATIVE: rendering the page asks for nothing. The rest pin
 * that four different facts — the answer, a failed read, an erased account,
 * a version-skewed peer — each render as themselves and never as each other.
 */
describe('SecurityPanel — the address on file', () => {
  const ON_FILE = 'owner@example.test';

  it('asks for NOTHING on mount — the read is the owner’s explicit act', async () => {
    let reads = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      AccountEmail: () => {
        reads += 1;
        return jsonResponse({ data: { accountEmail: ON_FILE } });
      },
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    expect(screen.queryByText(ON_FILE)).not.toBeInTheDocument();
    expect(reads).toBe(0);

    fireEvent.click(screen.getByRole('button', { name: 'Show the address on file' }));
    const answer = await screen.findByText(ON_FILE);
    expect(reads).toBe(1);
    // The control is spent: the answer replaced it.
    expect(
      screen.queryByRole('button', { name: 'Show the address on file' }),
    ).not.toBeInTheDocument();
    // ANNOUNCED AND FOCUSED (the M24 PR2 review's finding): the answer landed
    // inside the always-mounted polite region, and focus moved onto it —
    // the activated button just unmounted, and without the move a keyboard
    // user's focus would have fallen to <body>.
    const region = answer.closest('[role="status"]');
    expect(region).not.toBeNull();
    await waitFor(() => expect(region).toHaveFocus());
  });

  it('keeps keyboard focus THROUGH the round trip, and refuses a second press', async () => {
    /*
     * M24 PR4 review — the other half of PR3's own lesson, applied back to the
     * control it was learned from. This button carried the native `disabled`
     * attribute while the reveal was in flight, and `disabled` lands on the
     * element that currently HAS focus: the browser blurs it to <body> for the
     * whole round trip (a network hop, a KMS unwrap, a decrypt, two audit
     * emits). Worse, on the discard path the button never unmounts and the
     * outcome effect deliberately skips `hidden`, so focus was never restored
     * at all. `aria-disabled` plus a handler guard keeps the element focusable
     * and still refuses the second press — which is the property that actually
     * matters, since a second press is a second audited decrypt.
     */
    let reads = 0;
    let release: ((response: Response) => void) | null = null;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      AccountEmail: () => {
        reads += 1;
        return new Promise<Response>((resolve) => {
          release = resolve;
        });
      },
    });
    render(<SecurityPanel />);

    const button = await screen.findByRole('button', { name: 'Show the address on file' });
    button.focus();
    fireEvent.click(button);

    const busy = await screen.findByRole('button', { name: 'Retrieving…' });
    expect(busy).toHaveFocus();
    expect(busy).toHaveAttribute('aria-disabled', 'true');
    // The guard, not the attribute, is what refuses: a second press must not
    // spend a second audited decrypt on the owner's trail.
    fireEvent.click(busy);
    expect(reads).toBe(1);

    // POSITIVE CONTROL: the flow still completes and still moves focus to the
    // outcome when the button unmounts.
    (release as unknown as (response: Response) => void)(
      jsonResponse({ data: { accountEmail: ON_FILE } }),
    );
    const answer = await screen.findByText(ON_FILE);
    await waitFor(() => expect(answer.closest('[role="status"]')).toHaveFocus());
  });

  it('a reveal still in flight when the change completes is DISCARDED, not resurrected', async () => {
    // The review's demonstrated race: an answer read BEFORE the switch must
    // never land AFTER its discard and be mistaken for fresh (the read
    // cache's supersede rule, needed here by hand because this read is
    // barred from the cache). Unguarded, the held-open reveal below rendered
    // the PRE-change address beside "Your sign-in address has been changed".
    let release: ((response: Response) => void) | null = null;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      AccountEmail: () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
      CompleteEmailChange: () => jsonResponse({ data: { completeEmailChange: { ok: true } } }),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.click(screen.getByRole('button', { name: 'Show the address on file' }));
    await waitFor(() => expect(release).not.toBeNull());

    fireEvent.change(screen.getByLabelText('Code from the new address'), {
      target: { value: 'EC1-ABCD' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm new address' }));
    await screen.findByText(/Your sign-in address has been changed/);
    // The discard re-armed the control while the read is still outstanding.
    expect(screen.getByRole('button', { name: 'Show the address on file' })).toBeInTheDocument();

    await act(async () => {
      release?.(jsonResponse({ data: { accountEmail: ON_FILE } }));
      await Promise.resolve();
    });

    // The stale answer is exactly the address the discard called KNOWN WRONG
    // — it must not render, and the control stays armed for a FRESH read.
    expect(screen.queryByText(ON_FILE)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Show the address on file' })).toBeInTheDocument();
  });

  it('renders a failed read as its OWN sentence — never an address, never silence', async () => {
    // No AccountEmail handler: the mock's refusal reaches the client as a
    // network failure, which is exactly the state under test.
    installGraphqlFetchMock({ Session: sessionHandler, Sessions: sessionsHandler() });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.click(screen.getByRole('button', { name: 'Show the address on file' }));

    const failed = await screen.findByText(/We couldn’t retrieve the address on file just now/);
    // Inside the ALWAYS-MOUNTED polite region (the FormStatus rule): a role
    // inserted together with its content is silent in most screen readers.
    expect(failed.closest('[role="status"]')).not.toBeNull();
    // The remedy is honest: only the LOOKING failed.
    expect(failed.textContent).toContain('The address itself is unchanged');
  });

  it('renders CONTENT_ERASED as erasure — a control firing, not an outage', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      AccountEmail: () => graphqlError('CONTENT_ERASED'),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.click(screen.getByRole('button', { name: 'Show the address on file' }));

    const erased = await screen.findByText(/erased under a deletion request/);
    expect(erased.textContent).toContain('no address left to show');
    // No retry affordance in either spelling: the key was destroyed on
    // purpose, so neither the reveal control nor the reload-remedy sentence
    // may come back and invite one.
    expect(
      screen.queryByRole('button', { name: 'Show the address on file' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/retrieve the address on file/)).not.toBeInTheDocument();
  });

  it('treats a missing field as NO DATA — never rendered as an address', async () => {
    // A BFF predating this query answers `{"data":{}}`, which `gqlRequest`
    // admits as ok — and an `undefined` where the address belongs would be a
    // rendered claim about the account on the strength of a version skew.
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      AccountEmail: () => jsonResponse({ data: {} }),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.click(screen.getByRole('button', { name: 'Show the address on file' }));

    await screen.findByText(/We couldn’t retrieve the address on file just now/);
    expect(screen.queryByText(/Currently on file/)).not.toBeInTheDocument();
  });

  it('a completed change DISCARDS the revealed address rather than re-reading it', async () => {
    let reads = 0;
    installGraphqlFetchMock({
      Session: sessionHandler,
      Sessions: sessionsHandler(),
      AccountEmail: () => {
        reads += 1;
        return jsonResponse({ data: { accountEmail: ON_FILE } });
      },
      CompleteEmailChange: () => jsonResponse({ data: { completeEmailChange: { ok: true } } }),
    });
    render(<SecurityPanel />);

    await screen.findByRole('heading', { name: 'Sign-in address' });
    fireEvent.click(screen.getByRole('button', { name: 'Show the address on file' }));
    await screen.findByText(ON_FILE);

    fireEvent.change(screen.getByLabelText('Code from the new address'), {
      target: { value: 'EC1-ABCD' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm new address' }));
    await screen.findByText(/Your sign-in address has been changed/);

    // The old answer is KNOWN WRONG and gone — and NOT auto-re-read: a fresh
    // disclosure costs an audited decrypt, so it stays the owner's explicit
    // act. One read total is the proof.
    expect(screen.queryByText(ON_FILE)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Show the address on file' })).toBeInTheDocument();
    expect(reads).toBe(1);
  });
});
