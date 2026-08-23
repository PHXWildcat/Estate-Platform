'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor } from '../lib/copy';
import type { StepUpRetryOutcome } from '../lib/step-up';
import { FormStatus } from './FormStatus';
import { StepUpPrompt } from './StepUpPrompt';

/**
 * The waiting period, on /security (M22 PR3).
 *
 * WHY IT LIVES HERE rather than with the cases it governs: it is
 * emergency-access-configuration class. It is a standing protection on the
 * account, set once and rarely revisited, and it belongs beside the other
 * standing protections — not on a page whose entire subject is a case that
 * almost nobody has. The case surface links here, and this links back.
 *
 * A SIBLING OF `SecurityPanel`, NOT A SECTION INSIDE IT. That file is already
 * 1500 lines and owns one coherent thing (credentials and sessions); adding a
 * settlement read to it would give it a second downstream and a second reason
 * to re-render. `AccountSecurity` composes them, which is what it is for.
 *
 * STEP-UP GATED, and its refusal is NOT its neighbour's. `CASE_OPEN` means the
 * window is frozen because a case about this owner is open — a control firing,
 * with its own sentence and its own remedy — and a person who reads that as
 * "invalid input" will sit there editing a number that was never the problem.
 */

const MIN_DAYS = 5;
const MAX_DAYS = 60;

type LoadState =
  { kind: 'loading' } | { kind: 'ready'; days: number } | { kind: 'error'; message: string };

export function WaitingPeriodPanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [draft, setDraft] = useState('');
  const [pendingDays, setPendingDays] = useState<number | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('SettlementSettings', {});
    // A missing field is NO DATA — never fall back to the default of 5 and
    // show a person a number the server did not say.
    if (result.ok && typeof result.data.settlementSettings?.waitingPeriodDays === 'number') {
      const { waitingPeriodDays } = result.data.settlementSettings;
      setState({ kind: 'ready', days: waitingPeriodDays });
      setDraft(String(waitingPeriodDays));
      return;
    }
    setState({
      kind: 'error',
      message: result.ok ? messageFor('UNKNOWN') : messageFor(result.code),
    });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = useCallback(
    async (days: number): Promise<StepUpRetryOutcome> => {
      setFormError(null);
      const result = await gqlRequest('SetSettlementWaitingPeriod', { days });
      if (result.ok) {
        setPendingDays(null);
        setNotice(`Saved — we’ll wait ${days} days before opening your estate.`);
        await load();
        return 'applied';
      }
      if (result.code === 'STEPUP_REQUIRED') {
        // Carry the NUMBER, not a re-read of the input: the retry must apply
        // what was refused, even if the field has been edited since.
        setPendingDays(days);
        return 'stale';
      }
      setPendingDays(null);
      setFormError(messageFor(result.code));
      return 'applied';
    },
    [load],
  );

  function onSubmit(event: React.FormEvent): void {
    event.preventDefault();
    setNotice(null);
    const days = Number(draft);
    if (!Number.isInteger(days) || days < MIN_DAYS || days > MAX_DAYS) {
      // Refused HERE only because the field has a stated range beside it; the
      // service restates the same 5–60 CHECK and remains the authority.
      setFormError(`Choose a whole number of days between ${MIN_DAYS} and ${MAX_DAYS}.`);
      return;
    }
    void save(days);
  }

  return (
    <section aria-labelledby="waiting-period-heading" className="card mb-8 p-6">
      <h2 id="waiting-period-heading" className="text-lg font-semibold">
        Waiting period
      </h2>
      <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
        If someone reports you as deceased, this is how long we wait — after a person on our team
        has reviewed the report — before anything about your estate is released. We spend that time
        trying to reach you on every channel we have.{' '}
        <Link href="/security/cases" className="font-medium text-ink underline underline-offset-4">
          See any cases about you
        </Link>
        .
      </p>

      {state.kind === 'loading' ? <p className="text-sm text-ink-muted">Loading…</p> : null}

      {state.kind === 'error' ? (
        <>
          {/* A failed read is not a default. Never render 5 days here. */}
          <p className="text-sm text-ink-muted">{state.message}</p>
          <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
            Try again
          </button>
        </>
      ) : null}

      {state.kind === 'ready' ? (
        pendingDays !== null ? (
          // The prompt REPLACES the form it guards — never nests inside it.
          <StepUpPrompt
            idPrefix="waiting-period-stepup"
            hint="Changing how long we wait is a security setting, so it needs a fresh identity check."
            submitLabel="Confirm and save"
            onElevated={() => save(pendingDays)}
            onCancel={() => {
              setPendingDays(null);
            }}
          />
        ) : (
          <form onSubmit={onSubmit}>
            <label htmlFor="waiting-period-days" className="block text-sm font-medium">
              Days to wait
            </label>
            <input
              id="waiting-period-days"
              name="waitingPeriodDays"
              type="number"
              inputMode="numeric"
              min={MIN_DAYS}
              max={MAX_DAYS}
              step={1}
              value={draft}
              onChange={(event) => {
                setDraft(event.target.value);
              }}
              className="field-input mt-1 w-32"
              aria-describedby="waiting-period-range"
            />
            <p id="waiting-period-range" className="mt-1 text-xs text-ink-muted">
              Between {MIN_DAYS} and {MAX_DAYS} days. Currently {state.days}.
            </p>
            <button type="submit" className="btn btn-primary mt-4">
              Save
            </button>
          </form>
        )
      ) : null}

      <FormStatus tone="success" message={notice} />
      <FormStatus tone="error" message={formError} />
    </section>
  );
}
