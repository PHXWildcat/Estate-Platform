'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest, type SessionInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { validateTotpCode } from '../lib/validation';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';

type SessionState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'signedIn'; session: SessionInfo };

export function SecurityPanel(): ReactElement {
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

  // Step-up verification
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [stepUpCode, setStepUpCode] = useState('');
  const [stepUpCodeError, setStepUpCodeError] = useState<string | null>(null);
  const [stepUpBusy, setStepUpBusy] = useState(false);
  const [stepUpError, setStepUpError] = useState<string | null>(null);
  const [stepUpSuccess, setStepUpSuccess] = useState<string | null>(null);

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

  useEffect(() => {
    void loadSession();
  }, [loadSession]);

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
      setEnrollError(messageFor(result.ok ? 'UNKNOWN' : result.code));
    }
  }

  async function confirmStepUp(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const codeError = validateTotpCode(stepUpCode);
    setStepUpCodeError(codeError);
    if (codeError !== null) return;

    setStepUpBusy(true);
    setStepUpError(null);
    const result = await gqlRequest('StepUp', { code: stepUpCode.trim() });
    setStepUpBusy(false);
    if (result.ok && result.data.stepUp.ok) {
      setStepUpCode('');
      setStepUpSuccess('Identity verified. You can retry the protected action now.');
      setExportError(null);
      void loadSession();
    } else {
      setStepUpError(messageFor(result.ok ? 'UNKNOWN' : result.code));
    }
  }

  async function runExport(): Promise<void> {
    setExportBusy(true);
    setExportError(null);
    setExportSuccess(false);
    const result = await gqlRequest('ExportDemo', {});
    setExportBusy(false);
    if (result.ok && result.data.exportDemo.ok) {
      setExportSuccess(true);
    } else if (!result.ok && result.code === 'STEPUP_REQUIRED') {
      setExportError(messageFor('STEPUP_REQUIRED'));
      setStepUpSuccess(null);
      setStepUpOpen(true);
    } else {
      setExportError(messageFor(result.ok ? 'UNKNOWN' : result.code));
    }
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
          verified within the last 5 minutes.
        </p>
        {stepUpOpen ? (
          <form
            className="mt-4 space-y-4"
            noValidate
            onSubmit={(event) => {
              void confirmStepUp(event);
            }}
          >
            <FormField
              id="stepup-code"
              label="6-digit code"
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={stepUpCode}
              onChange={setStepUpCode}
              error={stepUpCodeError}
              autoComplete="one-time-code"
              disabled={stepUpBusy}
            />
            <button className="btn btn-primary" type="submit" disabled={stepUpBusy}>
              {stepUpBusy ? 'Verifying…' : 'Confirm identity'}
            </button>
          </form>
        ) : (
          <button
            type="button"
            className="btn btn-secondary mt-4"
            onClick={() => setStepUpOpen(true)}
          >
            Verify your identity
          </button>
        )}
        <div className="mt-3 space-y-2">
          <FormStatus tone="error" message={stepUpError} />
          <FormStatus tone="success" message={stepUpSuccess} />
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
          disabled={exportBusy}
          onClick={() => {
            void runExport();
          }}
        >
          {exportBusy ? 'Requesting…' : 'Export data (demo)'}
        </button>
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
