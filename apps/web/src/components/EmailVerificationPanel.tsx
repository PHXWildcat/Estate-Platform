'use client';

import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';

/**
 * THE ADDRESS-VERIFICATION SURFACE (M14 PR3).
 *
 * What this is actually for. Three shipped fail-closed controls — emergency
 * access (docs/03 §5.2), settlement intake and review-approve (§5.1), the
 * contact-link ceremony (§6g) — refuse in production rather than proceed
 * silently, on the rule that a waiting period nobody can be told about is not a
 * control. Until M14 they all tested whether SES was WIRED, never whether the
 * stored address belonged to the owner. PR2 made the arming ones ask. This is
 * the only place a user can answer.
 *
 * So the copy has a job beyond politeness: an owner who ignores this will,
 * later and elsewhere, be told they cannot arm emergency access or mint a link
 * code, and nothing at that moment will explain why. The panel says what the
 * verification is FOR, not just that it is outstanding.
 *
 * THREE STATES, NOT A BOOLEAN. `UNAVAILABLE` is a fact about the platform, and
 * rendering it as "unverified" would send somebody to complete a ceremony that
 * cannot currently run — the same mistake, one layer up, as a gate that cannot
 * tell an outage from a refusal.
 *
 * EVERY REFUSAL IS ONE ANSWER, because that is the control: identity gives the
 * same `invalid_code` for unknown, expired, spent, revoked and
 * attempt-exhausted, so whoever holds a guess learns nothing. The cost is that
 * the copy has to carry the possibilities the server will not distinguish,
 * which is why the failure message lists them instead of asking the user to
 * guess which applied.
 */

type Status = 'loading' | 'verified' | 'unverified' | 'unavailable' | 'error';

const RESEND_COPY: Record<string, string> = {
  SENT: 'Sent. Check your inbox — the code is good for a short while.',
  // The re-issue floor, reported rather than dressed up as a send. It is the
  // only rate limit on this path, so a user who is told "sent" and receives
  // nothing would keep pressing.
  TOO_SOON: 'We sent one a moment ago. Give it a minute before asking for another.',
  ALREADY_VERIFIED: 'That address is already confirmed — nothing to send.',
  UNAVAILABLE: 'We couldn’t send a code just now. Please try again shortly.',
};

export function EmailVerificationPanel(): ReactElement {
  const [status, setStatus] = useState<Status>('loading');
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('EmailVerification', {});
    if (!result.ok) {
      setStatus('error');
      return;
    }
    // A response missing the field is NO DATA, not data — the M11 lesson: a
    // version skew must not be indistinguishable from a real answer.
    const value = result.data.emailVerification;
    setStatus(
      value === 'VERIFIED' ? 'verified' : value === 'UNVERIFIED' ? 'unverified' : 'unavailable',
    );
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function resend(): Promise<void> {
    setBusy(true);
    setError(null);
    setNotice(null);
    const result = await gqlRequest('ResendEmailVerification', {});
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    setNotice(RESEND_COPY[result.data.resendEmailVerification] ?? RESEND_COPY.UNAVAILABLE ?? null);
    if (result.data.resendEmailVerification === 'ALREADY_VERIFIED') {
      // The server just told us something the panel's state disagrees with.
      // Re-read rather than patching a local boolean: the server is the
      // authority (the ConsentControls rule).
      await load();
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const trimmed = code.trim();
    if (trimmed.length === 0) {
      setCodeError('Enter the code from the email.');
      return;
    }
    // Deliberately NO client-side shape check beyond emptiness. The canonical
    // fold and the length measurement live in identity, and a second copy here
    // would be a rule that can disagree with the one that matters — the
    // documents-upload lesson (never a second opinion on the server's gate).
    setCodeError(null);
    setBusy(true);
    setError(null);
    setNotice(null);
    const result = await gqlRequest('VerifyEmail', { code: trimmed });
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    setCode('');
    setNotice('Address confirmed.');
    await load();
  }

  if (status === 'loading') {
    return <p className="text-sm text-ink-muted">Checking your email address…</p>;
  }

  if (status === 'error') {
    return (
      <FormStatus
        tone="error"
        message="We couldn’t check your email address. Reload the page to try again."
      />
    );
  }

  if (status === 'unavailable') {
    return (
      <FormStatus
        tone="info"
        message="We can’t check your email address right now. This is on our side — nothing about your account has changed. Try again shortly."
      />
    );
  }

  if (status === 'verified') {
    return (
      <div>
        <FormStatus tone="success" message="Your email address is confirmed." />
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          That means we can reach you if someone asks for emergency access to your vault, if a
          report is filed on your account, or if somebody claims a link to one of your contacts —
          the alerts that give you a chance to stop them.
        </p>
      </div>
    );
  }

  return (
    <div>
      <FormStatus tone="error" message="Your email address hasn’t been confirmed yet." />
      <p className="mt-2 max-w-prose text-sm text-ink-muted">
        We sent a code the first time you signed in. Confirming it is what lets us warn you if
        someone asks for emergency access to your vault, if a report is filed on your account, or if
        somebody claims a link to one of your contacts. Until then, some protections stay switched
        off — you won’t be able to set up emergency access or invite a contact.
      </p>

      <form onSubmit={(event) => void submit(event)} className="mt-4 max-w-sm" noValidate>
        <FormField
          id="verification-code"
          label="Code from the email"
          type="text"
          value={code}
          onChange={setCode}
          error={codeError}
          hint="It looks like EV1-… and is good for a short while."
          autoComplete="one-time-code"
          disabled={busy}
        />
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? 'Confirming…' : 'Confirm address'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => void resend()}
            disabled={busy}
          >
            Send a new code
          </button>
        </div>
      </form>

      <div className="mt-3">
        <FormStatus tone="error" message={error} />
        <FormStatus tone="info" message={notice} />
      </div>
    </div>
  );
}
