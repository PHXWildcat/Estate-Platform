'use client';

import { useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { validateTotpCode } from '../lib/validation';
import { FormStatus } from './FormStatus';

/**
 * Per-feature consent for the assistant (docs/01 §2.8, docs/03 §4 TB5).
 *
 * THE ASYMMETRY IS THE DESIGN, and it is visible in this component. Granting
 * widens what may leave the platform for a third-party model provider — that is
 * export-class, so it is step-up gated (docs/01 §5) and the code prompt below
 * appears when the server says so. Revoking is one click, always, with no
 * challenge: the M6 emergency-access-denial rule that THE PROTECTIVE ACTION
 * MUST NEVER BE HARDER THAN THE PERMISSIVE ONE. A user who suspects something
 * is wrong has to be able to switch it off from whatever session is in front of
 * them, without finding their authenticator.
 *
 * The server is the authority on what is granted: every mutation answers with
 * the caller's full grant set and this component renders that answer, rather
 * than toggling a local boolean optimistically. Absence IS denial here, so an
 * optimistic checkbox could show a grant the server refused.
 */

interface ScopeCopy {
  readonly scope: string;
  readonly label: string;
  readonly description: string;
}

/**
 * The five scopes, in the order they escalate. `assistant.enabled` is first
 * because it is the master switch — every other grant is meaningless without
 * it, and revoking it alone turns the whole feature off.
 */
const SCOPES: readonly ScopeCopy[] = [
  {
    scope: 'assistant.enabled',
    label: 'Use the assistant',
    description:
      'The master switch. With this off, nothing about your estate is analysed and no other permission below does anything.',
  },
  {
    scope: 'assistant.assets',
    label: 'Read my asset list',
    description:
      'Titles, categories, values and beneficiary designations — the facts behind funding and beneficiary checks.',
  },
  {
    scope: 'assistant.profile',
    label: 'Read my household facts',
    description:
      'State of residence, marital status, and whether any children are minors. Never names or dates of birth.',
  },
  {
    scope: 'assistant.documents.metadata',
    label: 'Read my document list',
    description: 'Which documents exist and whether they are executed. Never their contents.',
  },
  {
    scope: 'assistant.documents.content',
    label: 'Read a document’s text',
    description:
      'The strongest permission here: it lets the assistant read the wording of a document you point it at.',
  },
];

type Pending = { scope: string; action: 'grant' | 'revoke' } | null;

export interface ConsentControlsProps {
  granted: readonly string[];
  /** Called with the server's new grant set after any successful change. */
  onChanged: (granted: string[]) => void;
}

export function ConsentControls({ granted, onChanged }: ConsentControlsProps): ReactElement {
  const [pending, setPending] = useState<Pending>(null);
  const [error, setError] = useState<string | null>(null);
  /** The scope whose grant is waiting on a step-up code, or null. */
  const [stepUpScope, setStepUpScope] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [stepUpBusy, setStepUpBusy] = useState(false);

  const isGranted = (scope: string): boolean => granted.includes(scope);

  async function grant(scope: string): Promise<void> {
    setError(null);
    setPending({ scope, action: 'grant' });
    const result = await gqlRequest('GrantConsent', { scope });
    setPending(null);
    if (result.ok) {
      setStepUpScope(null);
      onChanged(result.data.grantConsent);
      return;
    }
    if (result.code === 'STEPUP_REQUIRED') {
      // Not an error the user has to go elsewhere to resolve: reveal the code
      // field here and retry this exact grant once identity accepts it.
      setStepUpScope(scope);
      return;
    }
    setError(messageFor(result.code));
  }

  async function revoke(scope: string): Promise<void> {
    setError(null);
    setPending({ scope, action: 'revoke' });
    const result = await gqlRequest('RevokeConsent', { scope });
    setPending(null);
    if (result.ok) {
      onChanged(result.data.revokeConsent);
      return;
    }
    setError(messageFor(result.code));
  }

  async function submitStepUp(event: FormEvent): Promise<void> {
    event.preventDefault();
    const validation = validateTotpCode(code);
    setCodeError(validation);
    if (validation !== null || stepUpScope === null) {
      return;
    }
    setStepUpBusy(true);
    const stepUp = await gqlRequest('StepUp', { code });
    setStepUpBusy(false);
    if (!stepUp.ok) {
      setCodeError(messageFor(stepUp.code));
      return;
    }
    setCode('');
    // The step-up is fresh for five minutes; retry the grant that triggered it.
    await grant(stepUpScope);
  }

  return (
    <section aria-labelledby="consent-heading" className="card p-6">
      <h2 id="consent-heading" className="text-lg font-semibold">
        What the assistant may read
      </h2>
      <p className="mt-1.5 max-w-prose text-sm text-ink-muted">
        Nothing is shared until you say so, and each permission is separate. Turning one off takes
        effect immediately.
      </p>

      <ul className="mt-4">
        {SCOPES.map((entry) => {
          const on = isGranted(entry.scope);
          const busy = pending?.scope === entry.scope;
          return (
            <li
              key={entry.scope}
              // `sm:flex-nowrap` so the button stays on the right for every row
              // at desktop width: without it a longer description wrapped the
              // master switch's button under its text while the others sat
              // beside theirs, and a control that moves row to row reads as a
              // different control.
              className="flex flex-wrap items-start justify-between gap-3 border-b border-line py-4 last:border-b-0 sm:flex-nowrap"
            >
              <div className="min-w-0 max-w-prose flex-1">
                <p className="text-sm font-medium">
                  {entry.label}
                  {on ? <span className="chip chip-success ml-2">On</span> : null}
                </p>
                <p className="mt-1 text-[0.8125rem] text-ink-muted">{entry.description}</p>
              </div>
              <button
                type="button"
                className={`${on ? 'btn btn-secondary' : 'btn btn-primary'} shrink-0`}
                disabled={busy}
                onClick={() => {
                  void (on ? revoke(entry.scope) : grant(entry.scope));
                }}
              >
                {busy ? 'Saving…' : on ? 'Turn off' : 'Turn on'}
              </button>
            </li>
          );
        })}
      </ul>

      {stepUpScope !== null ? (
        <form
          className="mt-4 rounded-[var(--radius-card)] border border-line p-4"
          noValidate
          onSubmit={(event) => {
            void submitStepUp(event);
          }}
        >
          <label className="field-label" htmlFor="consent-stepup-code">
            Confirm it’s you
          </label>
          <p id="consent-stepup-hint" className="field-hint">
            Sharing estate data with a model provider needs a fresh check. Enter the six-digit code
            from your authenticator.
          </p>
          <input
            id="consent-stepup-code"
            className="field-input mt-1 max-w-[12rem]"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            aria-describedby="consent-stepup-hint consent-stepup-error"
            onChange={(event) => {
              setCode(event.target.value);
            }}
          />
          <div id="consent-stepup-error" role="status" aria-live="polite">
            {codeError !== null ? <p className="field-error">{codeError}</p> : null}
          </div>
          <div className="mt-3 flex gap-3">
            <button type="submit" className="btn btn-primary" disabled={stepUpBusy}>
              {stepUpBusy ? 'Checking…' : 'Confirm and turn on'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setStepUpScope(null);
                setCode('');
                setCodeError(null);
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      <FormStatus tone="error" message={error} />
    </section>
  );
}
