'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest, type LiveSessionInfo, type SessionInfo } from '../graphql/client';
import { messageFor, stepUpMessageFor } from '../lib/copy';
import { formatDateTime } from '../lib/datetime';
import { audienceCopy } from '../lib/sessions';
import { SESSION_CACHE_TTL_MS, type StepUpRetryOutcome } from '../lib/step-up';
import { validateTotpCode } from '../lib/validation';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';
import { StepUpPrompt } from './StepUpPrompt';

type SessionState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'signedIn'; session: SessionInfo };

/** The paired-devices list, with a NO DATA state that is not an empty list. */
type DevicesState =
  { kind: 'loading' } | { kind: 'error' } | { kind: 'ready'; sessions: LiveSessionInfo[] };

/**
 * WHICH refused action a step-up is being collected for.
 *
 * ONE PROMPT EXISTS ON THIS PAGE AT A TIME, which is the whole point of holding
 * this in one place. The page can refuse for three different reasons, and the
 * M15 PR3 defect — two fields on one screen both labelled "New vault password"
 * — is what a per-section prompt would reproduce here: `StepUpPrompt`'s field
 * is labelled "Confirm it's you" for every caller, so two of them open at once
 * are two identical inputs a person cannot tell apart, and a test cannot
 * either.
 *
 * Each section passes its OWN retry function, so the M13 review's worse defect
 * (a shared handler that ran the wrong action after a genuine step-up, minting
 * a designation the owner never chose) has no shape to reoccur in: the action
 * is bound where it is rendered, not selected afterwards from state.
 */
type StepUpTarget = 'verify' | 'export' | 'pairing';

/**
 * REVOKING IS NOT INSTANT DOWNSTREAM, AND THIS PAGE MAY NOT PRETEND IT IS.
 *
 * Identity deletes the session row synchronously and answers 401 at once — but
 * every other service resolves a caller by introspecting the token through
 * `HttpSessionVerifier`, which caches POSITIVE answers for one TTL (the
 * 2026-07-23 decision: negatives are never cached, so a transient identity
 * outage cannot lock out valid tokens). So a revoked credential keeps working
 * at the vault for up to that window — MEASURED in M16 PR1's live drive rather
 * than reasoned about: identity 401'd immediately while the vault answered 200,
 * and 401'd 33 seconds later.
 *
 * docs/03 §6j names the fix as COPY rather than a shorter TTL, because
 * shortening it would put an introspection on every request in the product.
 * This is that fix. The window it describes is BOUNDED and not alarming — what
 * survives reaches ciphertext behind a completed SRP unlock, and cannot reset a
 * vault, delete an item, touch emergency access or mint another credential —
 * but a control that reads as instantaneous while a peer still admits the token
 * is the M9 shape inverted: not a control reading as an outage, but an
 * outage-free UI reading as a STRONGER control than it is.
 *
 * DERIVED, NOT TYPED OUT. The number is `SESSION_CACHE_TTL_MS`, which
 * `step-up.test.ts` already pins to `DEFAULT_CACHE_TTL_MS` in
 * packages/auth-guard by reading that file — the compose-parity mechanism,
 * because this app cannot import a Nest package. Raise the TTL and this
 * sentence follows it instead of quietly becoming false again.
 */
const PROPAGATION_SENTENCE =
  `Signing in with it is refused straight away; other parts of the platform can take up to ` +
  `${Math.ceil(SESSION_CACHE_TTL_MS / 1000)} seconds to stop accepting it.`;

export function SecurityPanel(): ReactElement {
  const router = useRouter();
  const [sessionState, setSessionState] = useState<SessionState>({ kind: 'loading' });

  // TOTP enrollment
  const [otpauthUri, setOtpauthUri] = useState<string | null>(null);
  const [enrollBusy, setEnrollBusy] = useState(false);
  const [enrollError, setEnrollError] = useState<string | null>(null);
  const [enrollSuccess, setEnrollSuccess] = useState<string | null>(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [verifyCodeError, setVerifyCodeError] = useState<string | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  // Step-up verification — at most one target at a time (see StepUpTarget).
  const [stepUp, setStepUp] = useState<StepUpTarget | null>(null);
  const [stepUpSuccess, setStepUpSuccess] = useState<string | null>(null);

  // Paired devices (M16)
  const [devices, setDevices] = useState<DevicesState>({ kind: 'loading' });
  const [deviceBusy, setDeviceBusy] = useState<string | null>(null);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [deviceNote, setDeviceNote] = useState<string | null>(null);

  // Extension pairing (M16)
  const [pairingCode, setPairingCode] = useState<string | null>(null);
  const [pairingExpiresAt, setPairingExpiresAt] = useState<string | null>(null);
  const [pairingBusy, setPairingBusy] = useState(false);
  const [pairingError, setPairingError] = useState<string | null>(null);

  // Export (demo)
  const [exportBusy, setExportBusy] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState(false);

  const loadSession = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('Session', {});
    if (result.ok && result.data.session !== null) {
      setSessionState({ kind: 'signedIn', session: result.data.session });
    } else if (!result.ok && result.code === 'UNAUTHENTICATED') {
      setSessionState({ kind: 'signedOut' });
    } else if (result.ok) {
      setSessionState({ kind: 'signedOut' });
    } else {
      setSessionState({ kind: 'error' });
    }
  }, []);

  /**
   * Read the live credentials.
   *
   * A MISSING FIELD IS NO DATA, NEVER DATA. `gqlRequest` answers ok for any
   * `data` object, so a BFF that predates this query arrives as `{"data":{}}` —
   * which M11 and M12 both white-screened on, and which here would be worse
   * than a blank page: an empty list on this surface reads as "nothing else can
   * reach your account", the single most reassuring sentence the page can say
   * and the one it must never say on the strength of a version skew.
   */
  const loadDevices = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('Sessions', {});
    if (result.ok && Array.isArray(result.data.sessions)) {
      setDevices({ kind: 'ready', sessions: result.data.sessions });
    } else {
      setDevices({ kind: 'error' });
    }
  }, []);

  useEffect(() => {
    void loadSession();
    void loadDevices();
  }, [loadSession, loadDevices]);

  async function beginEnrollment(): Promise<void> {
    setEnrollBusy(true);
    setEnrollError(null);
    setEnrollSuccess(null);
    setCopied(false);
    const result = await gqlRequest('TotpEnroll', {});
    setEnrollBusy(false);
    if (result.ok) {
      setOtpauthUri(result.data.totpEnroll.otpauthUri);
    } else {
      setEnrollError(messageFor(result.code));
    }
  }

  async function copyUri(): Promise<void> {
    if (otpauthUri === null) return;
    try {
      await navigator.clipboard.writeText(otpauthUri);
      setCopied(true);
    } catch {
      // Clipboard unavailable — the URI stays selectable in the field.
    }
  }

  async function confirmEnrollment(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const codeError = validateTotpCode(verifyCode);
    setVerifyCodeError(codeError);
    if (codeError !== null) return;

    setVerifyBusy(true);
    setEnrollError(null);
    const result = await gqlRequest('TotpVerify', { code: verifyCode.trim() });
    setVerifyBusy(false);
    if (result.ok && result.data.totpVerify.ok) {
      setOtpauthUri(null);
      setVerifyCode('');
      setEnrollSuccess('Authenticator confirmed. Codes from your app now protect this account.');
      void loadSession();
    } else {
      // `stepUpMessageFor`, not `messageFor` — this form's only field is an
      // authenticator code, and identity answers `invalid_credentials` for a
      // rejected TOTP code exactly as for a rejected password. The generic copy
      // told the user to re-check "that email and password combination" about a
      // form with neither on it: the M12 finding, still live on this page
      // because the fix landed on the consent controls and the document
      // generator and never came back here.
      setEnrollError(stepUpMessageFor(result.ok ? 'UNKNOWN' : result.code));
    }
  }

  /**
   * The standalone elevation — no action to retry, because the elevation IS the
   * action.
   *
   * This is the §5.1 RESCUE PATH and not a convenience: a step-up writes
   * `stepup.granted` to identity's append-only ledger, which is the only thing
   * that proves an owner is alive and voids a death case against them. The
   * people surface sends users here by name for exactly that, so the control
   * stays even though every protected action now prompts inline.
   *
   * Nothing to await: `StepUpPrompt` only calls this once identity has accepted
   * the code, and the session re-read that follows belongs to
   * `withSessionRefresh` along with every other target's.
   */
  function confirmVerified(): Promise<StepUpRetryOutcome> {
    setStepUpSuccess('Identity verified. Protected actions are open for the next five minutes.');
    setExportError(null);
    setStepUp(null);
    return Promise.resolve('applied');
  }

  /**
   * Wraps a retried action so THE SESSION CARD STOPS LYING.
   *
   * `StepUpPrompt` only calls `onElevated` after identity has accepted a code,
   * so by the time any of these run the session IS step-up fresh — and this page
   * displays that as a chip. Driving the real app found the chip still reading
   * "Step-up not fresh" immediately after a pairing code had been minted through
   * a genuine step-up, because only the standalone verify path re-read the
   * session. A security page stating the opposite of its own current state is
   * the same class of defect as an empty session list: quiet, plausible, and
   * about exactly the thing the page exists to report.
   *
   * Re-read once the action has settled, not on every poll: a `stale` outcome
   * means the PEER has not caught up, and re-asking identity would neither
   * change that nor tell the user anything new.
   */
  function withSessionRefresh(
    action: () => Promise<StepUpRetryOutcome>,
  ): () => Promise<StepUpRetryOutcome> {
    return async () => {
      const outcome = await action();
      if (outcome === 'applied') {
        await loadSession();
      }
      return outcome;
    };
  }

  async function runExport(): Promise<StepUpRetryOutcome> {
    setExportBusy(true);
    setExportError(null);
    setExportSuccess(false);
    const result = await gqlRequest('ExportDemo', {});
    setExportBusy(false);
    if (result.ok && result.data.exportDemo.ok) {
      setStepUp(null);
      setExportSuccess(true);
      return 'applied';
    }
    if (!result.ok && result.code === 'STEPUP_REQUIRED') {
      setExportError(messageFor('STEPUP_REQUIRED'));
      setStepUpSuccess(null);
      setStepUp('export');
      // The peer may still be answering from its cached un-elevated session, so
      // the prompt polls to the documented deadline (lib/step-up.ts).
      return 'stale';
    }
    setExportError(messageFor(result.ok ? 'UNKNOWN' : result.code));
    return 'applied';
  }

  /**
   * Mint a pairing code for the browser extension.
   *
   * SHAPE-GUARDED before anything is displayed. `startExtensionPairing` missing
   * from the response is a version skew, and rendering `undefined` here is
   * worse than any error message, because a pairing code is a thing people COPY
   * — the defect `VaultLaunch` shipped and its test caught, where the
   * alternative failure was a form posting `code=undefined` at the vault origin.
   */
  async function mintPairing(): Promise<StepUpRetryOutcome> {
    setPairingError(null);
    setPairingBusy(true);
    const result = await gqlRequest('StartExtensionPairing', {});
    setPairingBusy(false);
    if (result.ok) {
      const minted = result.data.startExtensionPairing;
      if (typeof minted?.code !== 'string' || minted.code.length === 0) {
        setPairingError(messageFor('PAIRING_UNAVAILABLE'));
        return 'applied';
      }
      setStepUp(null);
      setPairingCode(minted.code);
      setPairingExpiresAt(typeof minted.expiresAt === 'string' ? minted.expiresAt : null);
      return 'applied';
    }
    if (result.code === 'STEPUP_REQUIRED') {
      setStepUpSuccess(null);
      setStepUp('pairing');
      return 'stale';
    }
    setPairingError(messageFor(result.code));
    return 'applied';
  }

  /**
   * Revoke one OTHER credential. One click, and deliberately no step-up: the M6
   * rule is that the protective action must never be harder than the permissive
   * one, and minting a pairing code is the gated half. Someone who believes
   * their extension is compromised must not be sent to find an authenticator
   * first.
   *
   * WHAT THIS SAYS AFTERWARDS IS A CONTROL, which is why the sentence is shared
   * rather than written twice — see PROPAGATION_SENTENCE.
   */
  async function revokeDevice(row: LiveSessionInfo): Promise<void> {
    setDeviceError(null);
    setDeviceNote(null);
    setDeviceBusy(row.sessionId);
    const result = await gqlRequest('RevokeSession', { sessionId: row.sessionId });
    setDeviceBusy(null);
    if (!result.ok) {
      setDeviceError(messageFor(result.code));
    } else {
      setDeviceNote(
        `That ${audienceCopy(row.audience).label.toLowerCase()} is revoked. ${PROPAGATION_SENTENCE}`,
      );
    }
    // Re-read either way. A refusal here is identity's UNIFORM not-found, which
    // covers "already gone" as well as "never yours", so the list — not this
    // message — is what says where things actually stand.
    await loadDevices();
  }

  /**
   * Revoking the credential you are HOLDING goes through logout, not
   * `revokeSession`.
   *
   * Both kill the same row. Only logout also expires the two cookies carrying
   * it, and leaving them in place would put the browser in exactly the state
   * M8's logout entry calls the worst outcome — a page that still looks signed
   * in over a session that is not. Revocation happens first and a failure
   * clears nothing, which is the same rule `SignOutButton` follows.
   */
  async function signOutCurrent(sessionId: string): Promise<void> {
    setDeviceError(null);
    setDeviceNote(null);
    setDeviceBusy(sessionId);
    const result = await gqlRequest('Logout', {});
    if (result.ok) {
      router.push('/login');
      router.refresh();
      return;
    }
    setDeviceBusy(null);
    setDeviceError(messageFor(result.code));
  }

  if (sessionState.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Loading your security settings…</p>
      </div>
    );
  }

  if (sessionState.kind === 'error') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t load your security settings. Please try again in a moment.
        </p>
      </div>
    );
  }

  if (sessionState.kind === 'signedOut') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">Sign in required</h2>
        <p className="mt-2 text-sm text-ink-muted">
          Security settings belong to your account. Sign in to manage them.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          <Link className="btn btn-primary" href="/login">
            Sign in
          </Link>
          <Link className="btn btn-secondary" href="/register">
            Create account
          </Link>
        </div>
      </div>
    );
  }

  const { session } = sessionState;

  return (
    <div className="space-y-6">
      <section aria-labelledby="session-heading" className="card p-6">
        <h2 id="session-heading" className="text-lg font-semibold">
          Session
        </h2>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {session.mfaLevel === 'none' ? (
            <span className="chip chip-warn">MFA not enrolled</span>
          ) : (
            <span className="chip chip-success">MFA enrolled</span>
          )}
          {session.stepUpFresh ? (
            <span className="chip chip-success">Step-up fresh</span>
          ) : (
            <span className="chip">Step-up not fresh</span>
          )}
        </div>
        <p className="mt-3 font-mono text-xs text-ink-muted">{session.userId}</p>
      </section>

      <section aria-labelledby="totp-heading" className="card p-6">
        <h2 id="totp-heading" className="text-lg font-semibold">
          Authenticator app
        </h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          Codes from an authenticator app protect sign-in and every sensitive action, from opening
          your vault to changing beneficiaries.
        </p>
        {otpauthUri === null ? (
          <button
            type="button"
            className="btn btn-secondary mt-4"
            disabled={enrollBusy}
            onClick={() => {
              void beginEnrollment();
            }}
          >
            {enrollBusy
              ? 'Preparing…'
              : session.mfaLevel === 'none'
                ? 'Set up authenticator app'
                : 'Re-enroll authenticator app'}
          </button>
        ) : (
          <div className="mt-4 space-y-4">
            <div>
              <label className="field-label" htmlFor="otpauth-uri">
                Enrollment link (otpauth URI)
              </label>
              <p id="otpauth-uri-hint" className="field-hint">
                Add this to your authenticator app, then confirm with a code. Treat it like a
                password — anyone with this link can generate your codes.
              </p>
              <div className="mt-2 flex gap-2">
                <input
                  id="otpauth-uri"
                  className="field-input font-mono text-xs"
                  readOnly
                  value={otpauthUri}
                  aria-describedby="otpauth-uri-hint"
                  onFocus={(event) => event.currentTarget.select()}
                />
                <button
                  type="button"
                  className="btn btn-secondary shrink-0"
                  onClick={() => {
                    void copyUri();
                  }}
                >
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
            <form
              className="space-y-4"
              noValidate
              onSubmit={(event) => {
                void confirmEnrollment(event);
              }}
            >
              <FormField
                id="totp-code"
                label="6-digit code"
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={verifyCode}
                onChange={setVerifyCode}
                error={verifyCodeError}
                autoComplete="one-time-code"
                disabled={verifyBusy}
              />
              <button className="btn btn-primary" type="submit" disabled={verifyBusy}>
                {verifyBusy ? 'Confirming…' : 'Confirm enrollment'}
              </button>
            </form>
          </div>
        )}
        <div className="mt-3 space-y-2">
          <FormStatus tone="error" message={enrollError} />
          <FormStatus tone="success" message={enrollSuccess} />
        </div>
      </section>

      <section aria-labelledby="stepup-heading" className="card p-6">
        <h2 id="stepup-heading" className="text-lg font-semibold">
          Step-up verification
        </h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          Sensitive actions need a fresh identity check — a code from your authenticator app,
          verified within the last 5 minutes. Verifying here also tells us you are alive, which is
          what cancels a death report filed against your account.
        </p>
        {stepUp === 'verify' ? (
          <StepUpPrompt
            idPrefix="stepup"
            hint="Enter the six-digit code from your authenticator app."
            submitLabel="Confirm identity"
            onElevated={withSessionRefresh(confirmVerified)}
            onCancel={() => {
              setStepUp(null);
            }}
          />
        ) : (
          <button
            type="button"
            className="btn btn-secondary mt-4"
            disabled={stepUp !== null}
            onClick={() => {
              setStepUpSuccess(null);
              setStepUp('verify');
            }}
          >
            Verify your identity
          </button>
        )}
        <div className="mt-3 space-y-2">
          <FormStatus tone="success" message={stepUpSuccess} />
        </div>
      </section>

      <section aria-labelledby="devices-heading" className="card p-6">
        <h2 id="devices-heading" className="text-lg font-semibold">
          Devices and sessions
        </h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          Everything that can currently reach your account. If you do not recognise one, revoke it —
          that needs nothing else from you. {PROPAGATION_SENTENCE}
        </p>

        {devices.kind === 'loading' ? (
          <p className="mt-4 text-sm text-ink-muted" role="status">
            Loading your sessions…
          </p>
        ) : devices.kind === 'error' ? (
          // NOT an empty list. "Nothing else can reach your account" is the most
          // reassuring sentence on this page, and a failed read must never say it.
          <p className="mt-4 text-sm text-ink-muted" role="status">
            We couldn’t list your sessions just now, so this isn’t a complete picture. Reload to try
            again.
          </p>
        ) : (
          <ul className="mt-4">
            {devices.sessions.map((row) => {
              const copy = audienceCopy(row.audience);
              const busy = deviceBusy === row.sessionId;
              return (
                <li
                  key={row.sessionId}
                  className="flex flex-wrap items-start justify-between gap-3 border-t border-line py-4"
                >
                  {/*
                   * `flex-1` matters: without it the row's width is the text's
                   * natural width, so a row with a LONGER description wrapped
                   * its button onto the next line while its neighbours kept
                   * theirs on the right — the button moving with the prose
                   * rather than staying where the eye expects it. Only visible
                   * in a real browser with real rows of different lengths.
                   */}
                  <div className="min-w-[16rem] max-w-prose flex-1">
                    <p className="text-sm font-medium">
                      {copy.label}
                      {row.current ? <span className="chip ml-2">This browser</span> : null}
                    </p>
                    <p className="field-hint mt-1">{copy.detail}</p>
                    <p className="field-hint mt-1">
                      Started {formatDateTime(row.createdAt)} · Expires{' '}
                      {formatDateTime(row.expiresAt)}
                    </p>
                    {row.current ? (
                      <p className="field-hint mt-1">
                        This is the session you are using right now — revoking it signs you out of
                        this browser.
                      </p>
                    ) : null}
                  </div>
                  <button
                    type="button"
                    className="btn btn-secondary shrink-0"
                    disabled={busy}
                    onClick={() => {
                      void (row.current ? signOutCurrent(row.sessionId) : revokeDevice(row));
                    }}
                  >
                    {busy
                      ? row.current
                        ? 'Signing out…'
                        : 'Revoking…'
                      : row.current
                        ? 'Sign out of this browser'
                        : 'Revoke'}
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        <div className="mt-3 space-y-2">
          <FormStatus tone="error" message={deviceError} />
        </div>
        {deviceNote !== null ? (
          <p className="mt-3 text-sm text-ink-muted" role="status">
            {deviceNote}
          </p>
        ) : null}

        <div className="mt-6 border-t border-line pt-4">
          <h3 className="text-base font-medium">Connect a browser extension</h3>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Pairing gives the Estate extension a credential of its own, which appears in the list
            above and can be revoked from there. It can look up and unlock vault items and nothing
            else — it cannot reset your vault or reach the rest of your estate. The extension itself
            is not published yet.
          </p>
          {pairingCode === null ? (
            <button
              type="button"
              className="btn btn-secondary mt-4"
              disabled={pairingBusy || stepUp !== null}
              onClick={() => {
                void mintPairing();
              }}
            >
              {pairingBusy ? 'Creating…' : 'Create a pairing code'}
            </button>
          ) : (
            <div className="mt-4 rounded-[var(--radius-card)] border border-line p-4">
              <p className="text-[0.8125rem] font-medium">
                Here is the code. This is the only time we can show it to you.
              </p>
              {/*
               * A text node in a <code> element — never markup, never a link.
               * `select-all` so it can be copied without a clipboard permission.
               */}
              <code className="mt-2 block select-all break-all text-sm">{pairingCode}</code>
              <p className="field-hint mt-2 max-w-prose">
                Type it into the extension within ten minutes
                {pairingExpiresAt === null
                  ? ''
                  : ` — it stops working at ${formatDateTime(pairingExpiresAt)}`}
                . It works once. Anyone who has it can pair an extension to your account, so type it
                yourself rather than passing it on.
              </p>
              <div className="mt-3">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => {
                    setPairingCode(null);
                    setPairingExpiresAt(null);
                  }}
                >
                  Hide this code
                </button>
              </div>
            </div>
          )}
          {stepUp === 'pairing' ? (
            <StepUpPrompt
              idPrefix="pairing-stepup"
              hint="Connecting a browser extension needs a fresh check — it creates a credential that outlives this browser. Enter the six-digit code from your authenticator."
              submitLabel="Confirm and create the code"
              onElevated={withSessionRefresh(mintPairing)}
              onCancel={() => {
                setStepUp(null);
              }}
            />
          ) : null}
          <div className="mt-3 space-y-2">
            <FormStatus tone="error" message={pairingError} />
          </div>
        </div>
      </section>

      <section aria-labelledby="export-heading" className="card p-6">
        <h2 id="export-heading" className="text-lg font-semibold">
          Export your data (demo)
        </h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          Starts a demonstration export. Like every sensitive action, it requires a fresh step-up
          verification.
        </p>
        <button
          type="button"
          className="btn btn-secondary mt-4"
          disabled={exportBusy || stepUp !== null}
          onClick={() => {
            void runExport();
          }}
        >
          {exportBusy ? 'Requesting…' : 'Export data (demo)'}
        </button>
        {stepUp === 'export' ? (
          <StepUpPrompt
            idPrefix="export-stepup"
            hint="Exporting your data needs a fresh check. Enter the six-digit code from your authenticator."
            submitLabel="Confirm and export"
            onElevated={withSessionRefresh(runExport)}
            onCancel={() => {
              setStepUp(null);
            }}
          />
        ) : null}
        <div className="mt-3 space-y-2">
          <FormStatus tone="error" message={exportError} />
          <FormStatus
            tone="success"
            message={
              exportSuccess ? 'Export started. This is a demo — check back for progress.' : null
            }
          />
        </div>
      </section>
    </div>
  );
}
