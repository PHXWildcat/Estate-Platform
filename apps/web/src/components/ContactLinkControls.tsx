'use client';

import Link from 'next/link';
import { useState, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor } from '../lib/copy';
import type { StepUpRetryOutcome } from '../lib/step-up';
import { FormStatus } from './FormStatus';
import { StepUpPrompt } from './StepUpPrompt';

/**
 * Inviting someone to link their account, and removing a link (M13 PR3).
 *
 * THE CODE IS SHOWN ONCE AND THE PLATFORM NEVER SENDS IT. The server keeps only
 * its sha256, so this panel is the only place it will ever exist outside the
 * owner's own head — and the copy says so plainly, because an owner who assumes
 * we emailed it will wait forever. Delivery is deliberately the owner's job:
 * nothing in this ceremony handles an address, which is what keeps M9's shipped
 * notification doctrine (no content, no links) intact and keeps redemption from
 * becoming a way to learn whether an account exists.
 *
 * THE GATES ARE ASYMMETRIC, and the asymmetry is visible here. Minting prompts
 * for a step-up, because a linked contact can open a death case against this
 * owner (docs/03 §6b) — handing out that capability belongs in the same class as
 * naming a fiduciary. Withdrawing a code and removing a live link are one click:
 * both only take capability away, and the M6 rule is that the protective action
 * must never be harder than the permissive one.
 */

export interface ContactLinkControlsProps {
  contactId: string;
  contactName: string;
  /** Whether the contact already has an account, or null for "we do not know". */
  linked: boolean | null;
  /** Called after a change so the parent can re-read the server's answer. */
  onChanged: () => void | Promise<void>;
}

export function ContactLinkControls({
  contactId,
  contactName,
  linked,
  onChanged,
}: ContactLinkControlsProps): ReactElement {
  const [code, setCode] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [stepUpNeeded, setStepUpNeeded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function invite(): Promise<StepUpRetryOutcome> {
    setError(null);
    setNote(null);
    setBusy(true);
    const result = await gqlRequest('InviteContactLink', { contactId });
    setBusy(false);
    if (result.ok) {
      setStepUpNeeded(false);
      setCode(result.data.inviteContactLink.code);
      setExpiresAt(result.data.inviteContactLink.expiresAt);
      return 'applied';
    }
    if (result.code === 'STEPUP_REQUIRED') {
      setStepUpNeeded(true);
      // The peer may still be answering from its cached un-elevated session;
      // the prompt polls to the documented deadline (lib/step-up.ts).
      return 'stale';
    }
    setError(messageFor(result.code));
    return 'applied';
  }

  async function withdraw(): Promise<void> {
    setError(null);
    setBusy(true);
    const result = await gqlRequest('RevokeContactLinkInvitation', { contactId });
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    // The code on screen is dead now, so it must leave the screen.
    setCode(null);
    setExpiresAt(null);
    setNote('That code no longer works.');
  }

  async function unlink(): Promise<void> {
    setError(null);
    setBusy(true);
    const result = await gqlRequest('UnlinkContact', { contactId });
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    setNote(`${contactName} is no longer linked to an account.`);
    await onChanged();
  }

  return (
    <section aria-labelledby="link-heading" className="card p-6">
      <h2 id="link-heading" className="text-lg font-semibold">
        Their account
      </h2>

      {linked === true ? (
        <>
          {/*
           * SAFETY COPY ABOUT THE §5.1 RESCUE PATH, so it has to name the action
           * that actually works. Signing in does NOT stop a death case: liveness
           * is read from identity's append-only step-up ledger, and only a
           * verified authenticator code writes `stepup.granted` there. An
           * ordinary session — however fresh — proves nothing, and a case
           * survives it. Step-up verification is on the Security page, so point
           * there rather than implying a remedy that leaves the owner locked out.
           */}
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            {contactName} has an account linked, so any role you give them can actually be used —
            and they are able to report a death on your account. That starts a review with a waiting
            period, and verifying your identity from{' '}
            <Link href="/security" className="text-accent underline underline-offset-2">
              Security
            </Link>{' '}
            cancels it.
          </p>
          <div className="mt-3">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy}
              onClick={() => {
                void unlink();
              }}
            >
              Remove the link
            </button>
          </div>
        </>
      ) : linked === false ? (
        <>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            {contactName} has no account linked, so nothing you grant them can be used yet. Invite
            them by giving them a code — <strong>we never send it for you</strong>. Pass it on
            however you normally reach them, and only to them: whoever uses the code becomes the
            linked person.
          </p>
          {code === null ? (
            <div className="mt-3">
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy}
                onClick={() => {
                  void invite();
                }}
              >
                {busy ? 'Creating…' : 'Create an invitation code'}
              </button>
            </div>
          ) : (
            <div className="mt-3 rounded-[var(--radius-card)] border border-line p-4">
              <p className="text-[0.8125rem] font-medium">
                Here is the code. This is the only time we can show it to you.
              </p>
              {/*
               * A text node in a <code> element — never markup, and never a link.
               * `select-all` so it can be copied without a clipboard permission.
               */}
              <code className="mt-2 block select-all break-all text-sm">{code}</code>
              <p className="field-hint mt-2 max-w-prose">
                Single-use, and it stops working
                {expiresAt === null ? ' after seven days' : ` on ${expiresAt.slice(0, 10)}`}. If you
                lose it, create another — that retires this one.
              </p>
              <div className="mt-3">
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={busy}
                  onClick={() => {
                    void withdraw();
                  }}
                >
                  Withdraw this code
                </button>
              </div>
            </div>
          )}
        </>
      ) : (
        // linked === null: the read that would have told us failed. Saying "no
        // account" here would be a claim about their estate on the strength of an
        // outage, and offering an invitation could contradict the server.
        <p className="mt-1 max-w-prose text-sm text-ink-muted">
          We could not check whether {contactName} has an account linked. Reload to try again.
        </p>
      )}

      {stepUpNeeded ? (
        <StepUpPrompt
          idPrefix="link-stepup"
          hint="Inviting someone to link their account needs a fresh check — a linked contact can act on your estate. Enter the six-digit code from your authenticator."
          submitLabel="Confirm and create the code"
          onElevated={invite}
          onCancel={() => {
            setStepUpNeeded(false);
          }}
        />
      ) : null}

      <FormStatus tone="error" message={error} />
      {note !== null ? <p className="mt-3 text-sm text-ink-muted">{note}</p> : null}
    </section>
  );
}
