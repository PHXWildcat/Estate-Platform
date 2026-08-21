'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import {
  gqlRequest,
  type ContactSummaryInfo,
  type EstateDistributionInfo,
  type EstateDistributionStatusChange,
} from '../graphql/client';
import { messageFor } from '../lib/copy';
import { formatDate } from '../lib/settlement';
import { FormStatus } from './FormStatus';
import { StepUpPrompt } from './StepUpPrompt';

/**
 * WHAT THE ESTATE PAID OUT (M23 PR4b) — docs/02 §7's distributions, given a
 * surface for the first time.
 *
 * NO AMOUNT IS EVER FETCHED WHILE RENDERING. Each figure is one audited
 * decrypt on the DECEDENT's own key and emits an event on their trail, so it
 * costs a deliberate click and this list opens showing none of them (docs/03
 * §6f). The list says WHETHER a sum is recorded; the sum itself is a question.
 *
 * APPROVAL IS NOT OFFERED, ANYWHERE. Clearing a distribution is an operator's
 * act under dual control, and a DDL CHECK forbids the approver being the
 * recorder — so an executor asking for it is asking to approve their own
 * payment. This screen has no control for it, which is the absence-over-filter
 * rule: the button that cannot be misused is the one that was never drawn.
 *
 * THE MOVES OFFERED ARE THE MOVES THE SERVER ALLOWS, derived from `MOVES`
 * below rather than from what reads well in a row. Never offer an action the
 * server would refuse.
 *
 * BEHIND NO ACCESS STAGE, matching the service: `listDistributions` is gated by
 * `assertCaseVisible` and not by a rung, because a distribution is procedural
 * state about the administration rather than a look inside the estate. The
 * beneficiary NAMES are behind the documents rung, so a shut rung costs this
 * panel its names and nothing else — contacts DECORATE, they never gate.
 */

type Screen =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; rows: EstateDistributionInfo[] };

/** Names for the rows, or the reason there are none. Never gates the list. */
type Names =
  | { kind: 'loading' }
  | { kind: 'locked' }
  | { kind: 'unavailable' }
  | { kind: 'ready'; contacts: ContactSummaryInfo[] };

/** A refused write, carrying its OWN arguments for the step-up retry. */
type PendingStepUp =
  | { kind: 'record'; beneficiaryContactId: string; amount: string }
  | { kind: 'move'; distributionId: string; status: EstateDistributionStatusChange };

/**
 * THE TRANSITION TABLE, and it is the SERVICE'S, not this screen's.
 *
 * `AdminService.setDistributionStatus` computes the legal `from` states for
 * each target, and `EstateDistributions.test.tsx` derives this map from that
 * source rather than trusting the copy — a hand-maintained list beside a thing
 * that grows is this repo's most repeated defect, and here the failure mode is
 * a button that answers DISTRIBUTION_NOT_APPROVED every time it is pressed.
 *
 * Read as "from this status, these moves are legal".
 */
export const MOVES: Readonly<Record<string, readonly EstateDistributionStatusChange[]>> = {
  // NOTHING from 'planned'. Dual control has not been satisfied, so every move
  // — including disputing it — is refused until an operator has looked.
  planned: [],
  approved: ['IN_PROGRESS', 'DISPUTED'],
  in_progress: ['COMPLETED', 'DISPUTED'],
  completed: ['DISPUTED'],
  disputed: [],
};

/** What a status says to somebody settling an estate, in their words. */
export function statusLabel(status: string): string {
  switch (status) {
    case 'planned':
      // NOT "pending" or "awaiting approval" alone — the sentence has to say
      // that the wait is ours and not theirs, or it reads as a task on their
      // list.
      return 'Waiting on our review';
    case 'approved':
      return 'Approved — not started';
    case 'in_progress':
      return 'In progress';
    case 'completed':
      return 'Paid out';
    case 'disputed':
      return 'Disputed';
    default:
      // A status this build has not learned yet. Shown as itself rather than
      // hidden: the DDL owns this vocabulary and a row we cannot label is
      // still a row somebody needs to see.
      return status;
  }
}

/** The button for one legal move. */
export function moveLabel(status: EstateDistributionStatusChange): string {
  switch (status) {
    case 'IN_PROGRESS':
      return 'Mark as started';
    case 'COMPLETED':
      return 'Mark as paid out';
    default:
      return 'Raise a dispute';
  }
}

/** Who a distribution names, from the contacts panel's own list. */
export function beneficiaryName(names: Names, contactId: string): string | null {
  if (names.kind !== 'ready') return null;
  return names.contacts.find((c) => c.id === contactId)?.name ?? null;
}

export function EstateDistributions({ caseId }: { caseId: string }): ReactElement {
  const [screen, setScreen] = useState<Screen>({ kind: 'loading' });
  const [names, setNames] = useState<Names>({ kind: 'loading' });
  /**
   * REVEALED AMOUNTS, held per row and never pre-populated. A row absent from
   * this map has not been read; `null` in it means the estate recorded no sum,
   * which is an answer rather than a pending read.
   */
  const [amounts, setAmounts] = useState<ReadonlyMap<string, string | null>>(new Map());
  const [busyId, setBusyId] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingStepUp | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [contactId, setContactId] = useState('');
  const [amount, setAmount] = useState('');

  const load = useCallback(async (): Promise<void> => {
    setScreen({ kind: 'loading' });
    const result = await gqlRequest('EstateDistributions', { caseId });
    // A missing field is NO DATA. `{"data":{}}` from a version-skewed BFF must
    // not destructure into "this estate has distributed nothing".
    if (result.ok && Array.isArray(result.data.estateDistributions)) {
      setScreen({ kind: 'ready', rows: result.data.estateDistributions });
      return;
    }
    setScreen({
      kind: 'error',
      message: result.ok ? messageFor('UNKNOWN') : messageFor(result.code),
    });
  }, [caseId]);

  const loadNames = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('EstateContacts', { caseId });
    if (result.ok && Array.isArray(result.data.estateContacts)) {
      setNames({ kind: 'ready', contacts: result.data.estateContacts });
      return;
    }
    // A SHUT RUNG IS NOT AN OUTAGE, and neither is an outage a shut rung —
    // two facts with two remedies, and this panel keeps them apart because one
    // of them will resolve on its own and the other will not.
    setNames(
      !result.ok && result.code === 'STAGE_NOT_APPROVED'
        ? { kind: 'locked' }
        : {
            kind: 'unavailable',
          },
    );
  }, [caseId]);

  useEffect(() => {
    void load();
    void loadNames();
  }, [load, loadNames]);

  /**
   * Reveals ONE amount. Every call is a decrypt and an audit event, so it runs
   * only from a press and never from a render.
   */
  async function reveal(distributionId: string): Promise<void> {
    setBusyId(distributionId);
    setFormError(null);
    const result = await gqlRequest('EstateDistributionAmount', { distributionId });
    setBusyId(null);
    if (!result.ok || result.data.estateDistributionAmount === undefined) {
      setFormError(result.ok ? messageFor('UNKNOWN') : messageFor(result.code));
      return;
    }
    const revealed = result.data.estateDistributionAmount;
    setAmounts((prev) => {
      const next = new Map(prev);
      // KEYED BY THE ID THE SERVER SENT BACK, not by the one we asked for, so
      // a figure can never be pinned to a row it was not read from.
      next.set(revealed.distributionId, revealed.amount);
      return next;
    });
  }

  /**
   * Records one. Returns the StepUpPrompt contract: 'stale' while the peer
   * still answers stepup_required, 'applied' once it has landed or failed for
   * some other reason.
   */
  async function record(
    args: Extract<PendingStepUp, { kind: 'record' }>,
  ): Promise<'applied' | 'stale'> {
    setBusyId('record');
    const result = await gqlRequest('RecordEstateDistribution', {
      caseId,
      beneficiaryContactId: args.beneficiaryContactId,
      // A decimal STRING, straight from the field. Never parsed, never
      // rounded, and an empty box means "no sum recorded" rather than zero.
      amount: args.amount === '' ? null : args.amount,
    });
    setBusyId(null);
    if (!result.ok) {
      if (result.code === 'STEPUP_REQUIRED') {
        setPending(args);
        return 'stale';
      }
      setPending(null);
      setFormError(messageFor(result.code));
      return 'applied';
    }
    setPending(null);
    setFormError(null);
    setFormOpen(false);
    setAmount('');
    // WHAT THE SERVER ACTUALLY DID. A recorded distribution is 'planned' and
    // waits on a review, and saying "recorded" alone would let an executor
    // believe money was cleared to move.
    setNotice('Recorded. It’s with our team for review before anything can move.');
    await load();
    return 'applied';
  }

  /** Moves one on. Same StepUpPrompt contract as `record`. */
  async function move(
    args: Extract<PendingStepUp, { kind: 'move' }>,
  ): Promise<'applied' | 'stale'> {
    setBusyId(args.distributionId);
    const result = await gqlRequest('SetEstateDistributionStatus', {
      distributionId: args.distributionId,
      status: args.status,
    });
    setBusyId(null);
    if (!result.ok) {
      if (result.code === 'STEPUP_REQUIRED') {
        setPending(args);
        return 'stale';
      }
      setPending(null);
      setFormError(messageFor(result.code));
      return 'applied';
    }
    setPending(null);
    setFormError(null);
    setNotice('Updated.');
    await load();
    return 'applied';
  }

  const canRecord = names.kind === 'ready' && names.contacts.length > 0;

  return (
    <section aria-labelledby="distributions-heading" className="card p-6">
      <h2 id="distributions-heading" className="text-lg font-semibold">
        Distributions
      </h2>
      <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
        What this estate has planned or paid out. Everything recorded here is reviewed by our team
        before it can move — that review is not something you can do yourself, and it isn’t a sign
        anything is wrong.
      </p>

      {screen.kind === 'loading' ? <p className="text-sm text-ink-muted">Loading…</p> : null}

      {screen.kind === 'error' ? (
        <>
          {/* A failed read is not an empty list. */}
          <p className="max-w-prose text-sm text-ink-muted">{screen.message}</p>
          <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
            Try again
          </button>
        </>
      ) : null}

      {screen.kind === 'ready' && screen.rows.length === 0 ? (
        <p className="max-w-prose text-sm text-ink-muted">
          Nothing has been recorded yet. That’s a real answer — no distribution has been entered for
          this estate.
        </p>
      ) : null}

      {screen.kind === 'ready' && screen.rows.length > 0 ? (
        <ul className="space-y-3">
          {screen.rows.map((row) => {
            const who = beneficiaryName(names, row.beneficiaryContactId);
            const shown = amounts.has(row.distributionId);
            const value = amounts.get(row.distributionId) ?? null;
            return (
              <li
                key={row.distributionId}
                className="border-t border-line pt-3 first:border-t-0 first:pt-0"
              >
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">
                    {/* NAMES DECORATE. Without the documents rung this panel
                        still lists every distribution — it just cannot say who
                        each one names, and it says THAT rather than nothing. */}
                    {who ?? 'A person this estate named'}
                  </span>
                  <span className="chip">{statusLabel(row.status)}</span>
                </span>

                <span className="mt-0.5 block text-sm text-ink-muted">
                  Recorded {formatDate(row.createdAt) ?? 'recently'}
                  {row.hasAmount ? null : ' · no amount recorded'}
                </span>

                {row.hasAmount ? (
                  <span className="mt-2 flex flex-wrap items-center gap-3">
                    {shown ? (
                      <span className="text-sm font-medium tabular-nums">
                        {/* A decimal STRING, rendered as itself. Never through
                            a Number: '999999999999999.99' comes back a cent
                            light and rounded. */}
                        {value ?? 'No amount recorded'}
                      </span>
                    ) : (
                      <button
                        type="button"
                        className="btn btn-secondary"
                        disabled={busyId === row.distributionId}
                        onClick={() => void reveal(row.distributionId)}
                      >
                        Show amount
                      </button>
                    )}
                  </span>
                ) : null}

                {(MOVES[row.status] ?? []).length > 0 ? (
                  <span className="mt-2 flex flex-wrap gap-2">
                    {(MOVES[row.status] ?? []).map((to) => (
                      <button
                        key={to}
                        type="button"
                        className="btn btn-secondary"
                        disabled={busyId === row.distributionId}
                        onClick={() =>
                          void move({
                            kind: 'move',
                            distributionId: row.distributionId,
                            status: to,
                          })
                        }
                      >
                        {moveLabel(to)}
                      </button>
                    ))}
                  </span>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : null}

      {screen.kind === 'ready' && !formOpen ? (
        canRecord ? (
          <button type="button" className="btn btn-primary mt-4" onClick={() => setFormOpen(true)}>
            Record a distribution
          </button>
        ) : (
          /*
           * NOT AN ERROR, AND NOT A DISABLED BUTTON. Recording needs a
           * beneficiary, and the only way to name one is the estate's contacts
           * — which sit behind the documents rung. So the panel says what is
           * missing rather than offering a form that cannot be filled.
           */
          <p className="mt-4 max-w-prose text-sm text-ink-muted">
            {names.kind === 'locked'
              ? 'Recording a distribution needs the estate’s people, which open with the documents stage above.'
              : names.kind === 'unavailable'
                ? 'We couldn’t load the estate’s people just now, so there’s nobody to record a distribution to. Try again in a moment.'
                : names.kind === 'ready'
                  ? 'This estate doesn’t name anyone, so there’s nobody to record a distribution to.'
                  : 'Loading the estate’s people…'}
          </p>
        )
      ) : null}

      {screen.kind === 'ready' && formOpen && names.kind === 'ready' ? (
        <form
          className="mt-4 space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            void record({ kind: 'record', beneficiaryContactId: contactId, amount });
          }}
        >
          <div>
            <label htmlFor="distribution-beneficiary" className="label">
              Who it goes to
            </label>
            <select
              id="distribution-beneficiary"
              className="input"
              value={contactId}
              onChange={(event) => setContactId(event.target.value)}
              required
            >
              <option value="">Choose someone</option>
              {names.contacts.map((contact) => (
                <option key={contact.id} value={contact.id}>
                  {contact.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="distribution-amount" className="label">
              Amount (optional)
            </label>
            <input
              id="distribution-amount"
              className="input"
              // `inputMode` and not `type="number"`: a number input hands back
              // a value the browser has already coerced, and money is a
              // decimal string end to end.
              inputMode="decimal"
              value={amount}
              onChange={(event) => setAmount(event.target.value)}
              placeholder="e.g. 2500.00"
            />
            <p className="mt-1 text-sm text-ink-muted">
              Leave this empty where a distribution is an item rather than a sum.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="submit" className="btn btn-primary" disabled={busyId === 'record'}>
              Record it
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setFormOpen(false);
                setFormError(null);
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      <FormStatus tone="success" message={notice} />
      <FormStatus tone="error" message={formError} />

      {pending !== null ? (
        <StepUpPrompt
          idPrefix="distribution-stepup"
          hint={
            pending.kind === 'record'
              ? 'Recording a distribution moves value out of this estate. Confirm it’s you.'
              : 'Confirm it’s you before changing what this distribution says.'
          }
          submitLabel={pending.kind === 'record' ? 'Record it' : 'Confirm'}
          onElevated={() => {
            // THE ACTION THAT WAS REFUSED, retried from the union's OWN
            // arguments — never re-read from the form, which the reader may
            // have edited while the prompt was open.
            if (pending.kind === 'record') {
              return record(pending);
            }
            return move(pending);
          }}
          onCancel={() => {
            setPending(null);
          }}
        />
      ) : null}
    </section>
  );
}
