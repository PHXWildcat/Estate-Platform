'use client';

import Link from 'next/link';
import { useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor, resetMessageFor } from '../lib/copy';
import { PASSWORD_MIN_LENGTH, validateEmail, validatePassword } from '../lib/validation';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';

/**
 * THE PASSWORD-RESET SURFACE (M20 PR3) — the first ceremony in the product a
 * signed-OUT caller drives, which is why it lives on the `(auth)` route group
 * rather than on /security.
 *
 * WHAT THE REQUEST ANSWER MAY SAY, which shapes every sentence here: identity
 * answers 202 for EVERY well-formed input — an unknown address, the 30-minute
 * re-issue floor and the per-destination bound are all deliberately silent,
 * because a distinguishable answer would tell an attacker where to point a
 * mailbox compromise. So the success copy is conditional on ALL THREE, and
 * this surface never says "we've sent you an email".
 *
 * THE COMPLETION FORM IS ALWAYS AVAILABLE (the M20 PR2 rule, harder here):
 * no route reads pending state, and the person holding a code may never have
 * touched this browser at all — the mail deliberately carries no link (M9:
 * "we never link you"), so arriving here by typing the address into a fresh
 * browser is the DESIGNED path, not an edge case.
 *
 * WHAT COMPLETING DOES AND DOES NOT DO, said on the surface because both
 * halves surprise people: every session on every device is signed out (the
 * attacker's sessions and the owner's cannot be told apart), and the caller is
 * signed in NOWHERE — identity mints no tokens on this route, deliberately
 * (the M15 PR4 lesson), so the next step is signing in with the password just
 * chosen. And the VAULT is untouched: 2SKD derives Zone A's keys from the
 * vault password and Secret Key, never from the account password, so a reset
 * cannot open — or lock anyone out of — the vault.
 */
export function PasswordResetForm(): ReactElement {
  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [requestBusy, setRequestBusy] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [requestNotice, setRequestNotice] = useState<string | null>(null);

  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [newPasswordError, setNewPasswordError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState('');
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [completeBusy, setCompleteBusy] = useState(false);
  const [completeFailure, setCompleteFailure] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submitRequest(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const nextEmailError = validateEmail(email);
    setEmailError(nextEmailError);
    if (nextEmailError !== null) return;

    setRequestBusy(true);
    setRequestError(null);
    setRequestNotice(null);
    const result = await gqlRequest('RequestPasswordReset', { email: email.trim() });
    setRequestBusy(false);

    if (result.ok && result.data.requestPasswordReset?.ok === true) {
      // Conditional on everything the server refuses to say: whether the
      // address has an account, and whether the re-issue floor swallowed the
      // send. A flat "we've sent you an email" would be false for exactly the
      // callers the silence exists to protect.
      setRequestNotice(
        `If ${email.trim()} has an Estate account — and you haven’t asked for a code in the ` +
          `last half hour — a code is on its way to it. Enter it below with your new password.`,
      );
      return;
    }
    // A missing field is NO DATA, never data.
    setRequestError(messageFor(result.ok ? 'UNKNOWN' : result.code));
  }

  async function submitComplete(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const trimmedCode = code.trim();
    const nextCodeError = trimmedCode.length === 0 ? 'Enter the code from the email.' : null;
    // The local minimum mirrors identity's number (pinned across the boundary
    // by password-policy.test.ts) and is ADVISORY: identity's schema is the
    // gate, this just saves a round trip for the common typo.
    const nextPasswordError = validatePassword(newPassword);
    // A typo here costs a fresh ceremony, not an unrecoverable account — but a
    // reset that succeeds with a password nobody knows sends the user straight
    // back to this page, so the confirm field earns its place exactly as it
    // does on the change form.
    const nextConfirmError = newPassword !== confirm ? 'Those passwords don’t match.' : null;
    setCodeError(nextCodeError);
    setNewPasswordError(nextPasswordError);
    setConfirmError(nextConfirmError);
    if (nextCodeError !== null || nextPasswordError !== null || nextConfirmError !== null) return;

    setCompleteBusy(true);
    setCompleteFailure(null);
    const result = await gqlRequest('CompletePasswordReset', {
      // The code EXACTLY as typed — the canonical fold lives in identity.
      code: trimmedCode,
      newPassword,
    });
    setCompleteBusy(false);

    if (result.ok && result.data.completePasswordReset?.ok === true) {
      // Credentials do not linger in DOM nodes once spent.
      setCode('');
      setNewPassword('');
      setConfirm('');
      setDone(true);
      return;
    }
    setCompleteFailure(resetMessageFor(result.ok ? 'UNKNOWN' : result.code));
  }

  if (done) {
    // The success state REPLACES both forms: the ceremony is spent, and the
    // only next step is the one the button offers. Both consequences are
    // stated — signed out everywhere, signed in nowhere — because a user who
    // expects a reset to log them in will otherwise read the login screen as
    // the reset having failed.
    return (
      <div className="card space-y-4 p-6">
        <FormStatus
          tone="success"
          message="Password reset. Every device has been signed out — including this one."
        />
        <p className="max-w-prose text-sm text-ink-muted">
          Nothing is signed in anywhere until you sign in again, so if someone else was in your
          account, they are out now. Your vault is unchanged: it has its own password and Secret
          Key, which this reset does not touch.
        </p>
        <Link className="btn btn-primary inline-block" href="/login">
          Sign in with your new password
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <form
        className="card space-y-5 p-6"
        noValidate
        onSubmit={(event) => {
          void submitRequest(event);
        }}
      >
        <FormField
          id="reset-email"
          label="Email address"
          type="email"
          value={email}
          onChange={setEmail}
          error={emailError}
          hint="The address you sign in with."
          autoComplete="email"
          disabled={requestBusy}
        />
        <FormStatus tone="error" message={requestError} />
        <FormStatus tone="info" message={requestNotice} />
        <button className="btn btn-primary w-full" type="submit" disabled={requestBusy}>
          {requestBusy ? 'Asking…' : 'Email me a reset code'}
        </button>
      </form>

      <div className="card space-y-5 p-6">
        <div>
          <h2 className="text-lg font-semibold">Have a code?</h2>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Enter it here with your new password. This works even if you asked from a different
            browser or device — the email contains no link on purpose, so typing the code here is
            the normal way to finish.
          </p>
        </div>
        <form
          className="space-y-5"
          noValidate
          onSubmit={(event) => {
            void submitComplete(event);
          }}
        >
          <FormField
            id="reset-code"
            label="Code from the email"
            type="text"
            value={code}
            onChange={setCode}
            error={codeError}
            hint="It looks like PR1-… and is good for a short while."
            autoComplete="one-time-code"
            disabled={completeBusy}
          />
          <FormField
            id="reset-new-password"
            label="New password"
            type="password"
            value={newPassword}
            onChange={setNewPassword}
            error={newPasswordError}
            hint={`At least ${PASSWORD_MIN_LENGTH} characters. A short, memorable sentence works well.`}
            autoComplete="new-password"
            disabled={completeBusy}
          />
          <FormField
            id="reset-confirm"
            label="Confirm new password"
            type="password"
            value={confirm}
            onChange={setConfirm}
            error={confirmError}
            autoComplete="new-password"
            disabled={completeBusy}
          />
          <FormStatus tone="error" message={completeFailure} />
          <button className="btn btn-primary w-full" type="submit" disabled={completeBusy}>
            {completeBusy ? 'Resetting…' : 'Reset password'}
          </button>
        </form>
        <p className="max-w-prose text-xs text-ink-muted">
          Resetting signs out every device and does not touch your vault — the vault has its own
          password and Secret Key, which Estate cannot reset for you.
        </p>
      </div>
    </div>
  );
}
