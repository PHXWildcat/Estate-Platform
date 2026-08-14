'use client';

import { useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { FormStatus } from './FormStatus';

/**
 * Redeeming a link code, as the person being linked (M13 PR3).
 *
 * THE CODE IS THE WHOLE REQUEST. This form asks for nothing else — no email, no
 * name, no whose-estate — because there is no such field on the mutation or the
 * route beneath it. That is the anti-enumeration property docs/03 §6b depends
 * on: with nothing here in which to name an account, redemption cannot be turned
 * into a way to find out whether one exists.
 *
 * EVERY FAILURE READS THE SAME. Unknown, expired, already used, withdrawn: one
 * sentence, because telling them apart would confirm to whoever is holding a
 * guess that it named something real. The remedy offered is therefore the safe
 * one — ask the person who invited you for a fresh code.
 *
 * SUCCESS SAYS NOTHING ABOUT THE ESTATE either. The server returns no owner and
 * no contact name, so this page cannot show whose estate was joined; the person
 * who handed over the code already knows.
 */
export function RedeemLinkPanel(): ReactElement {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    if (code.trim().length === 0) {
      setError('Enter the code you were given.');
      return;
    }
    setBusy(true);
    const result = await gqlRequest('RedeemContactLink', { code: code.trim() });
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    setCode('');
    setDone(true);
  }

  if (done) {
    return (
      <section aria-labelledby="redeem-heading" className="card p-6">
        <h2 id="redeem-heading" className="text-lg font-semibold">
          You are linked
        </h2>
        <p className="mt-1 max-w-prose text-sm text-ink-muted">
          {/*
            Narrowed from "anything they choose to share with you": the platform
            can share estate contacts and nothing else today, and a link panel
            promising more is the same false expectation the people surface used
            to create with buttons. Says what a role does NOT do, then exactly
            what it can be allowed to do.
          */}
          The person who invited you has been told. A role on its own grants nothing until they
          allow it — and the only thing they can allow today is access to their estate contacts.
        </p>
      </section>
    );
  }

  return (
    <section aria-labelledby="redeem-heading" className="card p-6">
      <h2 id="redeem-heading" className="text-lg font-semibold">
        Enter your code
      </h2>
      <form
        className="mt-3"
        noValidate
        onSubmit={(event) => {
          void submit(event);
        }}
      >
        <label className="field-label" htmlFor="redeem-code">
          Invitation code
        </label>
        <p id="redeem-code-hint" className="field-hint">
          Codes look like ESL1-… and can be used once. We never email them, so if you were sent one
          by email, treat it with suspicion.
        </p>
        <input
          id="redeem-code"
          className="field-input mt-1"
          autoComplete="off"
          spellCheck={false}
          value={code}
          aria-describedby="redeem-code-hint"
          onChange={(event) => {
            setCode(event.target.value);
          }}
        />
        <div className="mt-3">
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? 'Checking…' : 'Accept invitation'}
          </button>
        </div>
        <FormStatus tone="error" message={error} />
      </form>
    </section>
  );
}
