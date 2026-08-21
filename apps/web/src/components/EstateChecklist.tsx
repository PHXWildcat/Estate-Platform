'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import { gqlRequest, type EstateTaskInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { formatCalendarDate, formatDate } from '../lib/settlement';
import { FormStatus } from './FormStatus';

/**
 * THE ESTATE'S ADMINISTRATION CHECKLIST (M23 PR3).
 *
 * BEHIND NO ACCESS STAGE, deliberately. A task is procedural state about the
 * administration — "obtain certified copies of the death certificate" — not
 * access to anything the decedent kept, so staging it would put an operator's
 * review in front of an executor seeing their own worklist. The section
 * therefore renders beside a ladder on which every rung may still be shut, and
 * that is the intended shape: on day one, this is the only thing here that
 * works, and it is the thing somebody newly handed an estate most needs.
 *
 * NO STEP-UP ON THE TICK. Everything on this screen that MOVES access is gated;
 * a tick moves nothing and transfers nothing. An executor days after a death
 * should not have to find their authenticator to say they have found the will.
 *
 * REOPENING IS THE SAME CONTROL AS COMPLETING — one checkbox, both directions,
 * one mutation with a boolean. A checklist that could be completed but not
 * corrected would make an honest mis-click permanent, and the protective action
 * must never be harder than the permissive one.
 *
 * COMPLETED ITEMS STAY VISIBLE, in place. "What is left" reads like the point
 * of a list and a finished row reads like noise, but an estate checklist is a
 * record of an administration somebody may later be asked to account for.
 *
 * A STEP AIMED AT SOMEBODY ELSE IS STILL SHOWN. The attorney files the
 * petition; the executor is the person answerable for whether it was filed.
 *
 * NOT LEGAL ADVICE, and the copy says so out loud. The list comes from a
 * generic in-repo template, not from anything about this estate.
 */

type Screen =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; tasks: EstateTaskInfo[] };

/** Whose move it is, when it is not the reader's. Null hides the label. */
export function roleLabel(assignedRole: string | null): string | null {
  switch (assignedRole) {
    case 'attorney':
      return 'The attorney’s step';
    case 'cpa':
      return 'The accountant’s step';
    default:
      // 'executor' and null alike: this is the executor's own list, so saying
      // "your step" on nearly every row is noise that buries the exceptions.
      return null;
  }
}

/** What a row's due date says, or null where the template sets no deadline. */
export function dueLabel(task: EstateTaskInfo): string | null {
  if (task.completedAt !== null) {
    const done = formatDate(task.completedAt);
    return done === null ? 'Done' : `Done ${done}`;
  }
  /*
   * `formatCalendarDate`, NOT `formatDate`. A due date is a Postgres `date`
   * widened to UTC midnight on the way out, so rendering it as an instant in
   * the reader's zone loses a day for everyone west of UTC — this screen said
   * "September 2" for a date stored as the 3rd until the browser showed it.
   * The COMPLETED timestamp above is a real instant and keeps local time.
   */
  const due = formatCalendarDate(task.dueAt);
  // NOT "overdue". A deadline here is counted from verification, and the
  // platform never records a date of death — telling a grieving executor they
  // are late, on an estimate, would be both alarming and unfounded.
  return due === null ? null : `Suggested by ${due}`;
}

export function EstateChecklist({ caseId }: { caseId: string }): ReactElement {
  const [screen, setScreen] = useState<Screen>({ kind: 'loading' });
  /** WHICH row is in flight, not whether ANY is — see `toggle`. */
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    setScreen({ kind: 'loading' });
    const result = await gqlRequest('EstateTasks', { caseId });
    // A missing field is NO DATA. `{"data":{}}` from a version-skewed BFF must
    // not destructure into an empty checklist.
    if (result.ok && Array.isArray(result.data.estateTasks)) {
      setScreen({ kind: 'ready', tasks: result.data.estateTasks });
      return;
    }
    // A failed read is not an empty checklist: "there is nothing to do" and
    // "we could not reach the service" are different facts with different
    // remedies, and this one costs its own panel.
    setScreen({
      kind: 'error',
      message: result.ok ? messageFor('UNKNOWN') : messageFor(result.code),
    });
  }, [caseId]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (task: EstateTaskInfo): Promise<void> => {
    setPendingId(task.taskId);
    setFormError(null);
    const result = await gqlRequest('SetEstateTaskCompletion', {
      taskId: task.taskId,
      completed: task.completedAt === null,
    });
    setPendingId(null);
    const updated = result.ok ? result.data.setEstateTaskCompletion : null;
    if (updated === null || updated === undefined) {
      setFormError(result.ok ? messageFor('UNKNOWN') : messageFor(result.code));
      /*
       * THE ROW IS LEFT AS THE SERVER LAST DESCRIBED IT. Nothing was applied
       * optimistically, so there is nothing to roll back — the checkbox that
       * failed to move simply has not moved. A list that showed a tick the
       * server refused would be this screen telling an executor a step was
       * recorded when it was not.
       */
      return;
    }
    // The SERVER'S row replaces ours, so `completedAt` is the service's
    // timestamp rather than one this browser invented.
    setScreen((prev) =>
      prev.kind === 'ready'
        ? {
            kind: 'ready',
            tasks: prev.tasks.map((row) => (row.taskId === updated.taskId ? updated : row)),
          }
        : prev,
    );
  };

  return (
    <section aria-labelledby="checklist-heading" className="card p-6">
      <h2 id="checklist-heading" className="text-lg font-semibold">
        Settling this estate
      </h2>
      <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
        A general list of the steps most estates go through. It isn’t legal advice and it isn’t
        specific to this estate — what actually applies depends on where the estate is settled and
        on the will itself. Tick things off as you go, and untick anything you tick by mistake.
      </p>

      {screen.kind === 'loading' ? <p className="text-sm text-ink-muted">Loading…</p> : null}

      {screen.kind === 'error' ? (
        <>
          <p className="max-w-prose text-sm text-ink-muted">{screen.message}</p>
          <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
            Try again
          </button>
        </>
      ) : null}

      {screen.kind === 'ready' && screen.tasks.length === 0 ? (
        <p className="max-w-prose text-sm text-ink-muted">
          There’s no checklist on this estate yet. One is put together when a death is verified.
        </p>
      ) : null}

      {screen.kind === 'ready' && screen.tasks.length > 0 ? (
        <ul className="space-y-3">
          {screen.tasks.map((task) => {
            const done = task.completedAt !== null;
            const whose = roleLabel(task.assignedRole);
            const when = dueLabel(task);
            return (
              <li
                key={task.taskId}
                className="flex items-start gap-3 border-t border-line pt-3 first:border-t-0 first:pt-0"
              >
                <input
                  id={`task-${task.taskId}`}
                  type="checkbox"
                  className="mt-1 h-4 w-4"
                  checked={done}
                  disabled={pendingId === task.taskId}
                  onChange={() => void toggle(task)}
                />
                <span className="min-w-0">
                  <label
                    htmlFor={`task-${task.taskId}`}
                    className={done ? 'text-ink-muted line-through' : 'font-medium'}
                  >
                    {/* A template constant, rendered as plain text. */}
                    {task.title}
                  </label>
                  {whose !== null || when !== null ? (
                    <span className="mt-0.5 block text-sm text-ink-muted">
                      {[whose, when].filter((part) => part !== null).join(' · ')}
                    </span>
                  ) : null}
                </span>
              </li>
            );
          })}
        </ul>
      ) : null}

      <FormStatus tone="error" message={formError} />
    </section>
  );
}
