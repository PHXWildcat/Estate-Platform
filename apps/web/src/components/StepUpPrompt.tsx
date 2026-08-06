'use client';

import { useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { stepUpMessageFor } from '../lib/copy';
import { validateTotpCode } from '../lib/validation';

/**
 * The inline step-up prompt, extracted at its THIRD caller (M13).
 *
 * Step-up is a detour by nature — the server refuses until the session has a
 * fresh check — and the pattern the consent controls (M10) and the document
 * generator (M12) both settled on is to ask HERE and retry the SAME action, so
 * nobody loses a filled-in form to an authentication round trip. M13 needs it on
 * every role change, which would have made four hand-written copies of a form
 * whose wording is load-bearing: `stepUpMessageFor` exists because identity
 * answers `invalid_credentials` for a rejected TOTP code exactly as for a
 * rejected password, and a copy that forgot it would tell someone their password
 * was wrong about a form with no password on it. One component, one place for
 * that to be right.
 *
 * `onElevated` runs after identity accepts the code, and is expected to re-run
 * the action that was refused. This component owns no knowledge of what that is.
 *
 * WHAT IT DOES NOT COVER, stated rather than left to be discovered: the two
 * earlier callers keep their own copies. `ConsentControls` could adopt this
 * as-is; `DocumentGenerator` cannot, because its prompt is rendered INSIDE the
 * intake form (deliberately — the answers must survive the round trip) and this
 * component renders a `<form>`, which HTML does not allow to nest. Adding an
 * "actually a div" mode to satisfy one caller would put the branch back inside
 * the thing being shared. So the rule for anyone adding a fifth prompt: use this
 * unless you are inside a form, and if you are, the wording still has to come
 * from `stepUpMessageFor`.
 */
export interface StepUpPromptProps {
  /** Why the check is needed, in this surface's own words. */
  hint: string;
  submitLabel: string;
  /** Retry the refused action. The prompt stays open if it fails again. */
  onElevated: () => Promise<void> | void;
  onCancel: () => void;
  /** Distinguishes the field ids when more than one prompt can exist on a page. */
  idPrefix: string;
}

export function StepUpPrompt({
  hint,
  submitLabel,
  onElevated,
  onCancel,
  idPrefix,
}: StepUpPromptProps): ReactElement {
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    const validation = validateTotpCode(code);
    setCodeError(validation);
    if (validation !== null) {
      return;
    }
    setBusy(true);
    const stepUp = await gqlRequest('StepUp', { code });
    if (!stepUp.ok) {
      setBusy(false);
      setCodeError(stepUpMessageFor(stepUp.code));
      return;
    }
    setCode('');
    // Fresh for five minutes: retry whatever was refused.
    await onElevated();
    setBusy(false);
  }

  return (
    <form
      className="mt-4 rounded-[var(--radius-card)] border border-line p-4"
      noValidate
      onSubmit={(event) => {
        void submit(event);
      }}
    >
      <label className="field-label" htmlFor={`${idPrefix}-code`}>
        Confirm it’s you
      </label>
      <p id={`${idPrefix}-hint`} className="field-hint">
        {hint}
      </p>
      <input
        id={`${idPrefix}-code`}
        className="field-input mt-1 max-w-[12rem]"
        inputMode="numeric"
        autoComplete="one-time-code"
        value={code}
        aria-describedby={`${idPrefix}-hint ${idPrefix}-error`}
        onChange={(event) => {
          setCode(event.target.value);
        }}
      />
      <div id={`${idPrefix}-error`} role="status" aria-live="polite">
        {codeError !== null ? <p className="field-error">{codeError}</p> : null}
      </div>
      <div className="mt-3 flex gap-3">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? 'Checking…' : submitLabel}
        </button>
        <button type="button" className="btn btn-secondary" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
