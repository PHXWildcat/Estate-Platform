import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { EstateTaskInfo } from '../graphql/client';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { EstateChecklist, dueLabel, roleLabel } from './EstateChecklist';

/**
 * THE ESTATE CHECKLIST (M23 PR3).
 *
 * Four properties carry this file.
 *
 * The FIRST is that UNTICKING is as easy as ticking — one control, both
 * directions. The protective action must never be harder than the permissive
 * one, and on a checklist the correction IS the protective action: a list that
 * can be completed but not corrected turns an executor's mis-click into a
 * permanent claim that a step was taken.
 *
 * The SECOND is that a COMPLETED item stays on the list. "What is left" reads
 * like the point of a checklist, but this one is a record of an administration
 * somebody may later be asked to account for.
 *
 * The THIRD is that a failed read is not an empty checklist, and a failed WRITE
 * does not move the box. Nothing is applied optimistically, so a tick the
 * server refused is a tick the reader never sees.
 *
 * The FOURTH is that this panel asks for NO ACCESS STAGE. It is the only thing
 * on the estate screen that works on day one, and it must not be made to wait
 * behind an operator's review of a request to see one's own worklist.
 */

const CASE_ID = 'case-1';

function task(over: Partial<EstateTaskInfo> = {}): EstateTaskInfo {
  return {
    taskId: 'task-1',
    title: 'Locate the original will and any codicils',
    category: 'legal',
    assignedRole: 'executor',
    dueAt: '2026-09-02T00:00:00.000Z',
    completedAt: null,
    ...over,
  };
}

const DONE = task({
  taskId: 'task-2',
  title: 'Obtain certified copies of the death certificate',
  category: 'administrative',
  dueAt: null,
  completedAt: '2026-08-20T00:00:00.000Z',
});

function handlers(
  options: { tasks?: OperationHandler; tick?: OperationHandler } = {},
): Record<string, OperationHandler> {
  return {
    EstateTasks: options.tasks ?? (() => jsonResponse({ data: { estateTasks: [task(), DONE] } })),
    SetEstateTaskCompletion:
      options.tick ??
      ((variables: unknown) => {
        const { taskId, completed } = variables as { taskId: string; completed: boolean };
        const row = taskId === DONE.taskId ? DONE : task();
        // FAITHFUL IN BOTH DIRECTIONS: unticking CLEARS the timestamp. A double
        // that always answered "completed" would let an untick that silently
        // did nothing pass every assertion below.
        return jsonResponse({
          data: {
            setEstateTaskCompletion: {
              ...row,
              completedAt: completed ? '2026-08-21T00:00:00.000Z' : null,
            },
          },
        });
      }),
  };
}

function boxFor(title: string): HTMLInputElement {
  return screen.getByRole('checkbox', { name: new RegExp(title, 'i') });
}

describe('what a row says', () => {
  it('names whose step it is only when it is NOT the reader’s', () => {
    // Saying "your step" on nearly every row buries the exceptions, which are
    // the rows an executor most needs to notice.
    expect(roleLabel('executor')).toBeNull();
    expect(roleLabel(null)).toBeNull();
    expect(roleLabel('attorney')).toBe('The attorney’s step');
    expect(roleLabel('cpa')).toBe('The accountant’s step');
  });

  /**
   * FOUND BY DRIVING THE APP, and the reason this test exists at all.
   *
   * `due_at` is a Postgres `date` — a calendar day — that the service widens to
   * UTC midnight before the wire. Rendered as an instant in the reader's zone
   * it loses a day for everyone west of UTC: the screen said "September 2" for
   * a date stored as the 3rd, at `America/Phoenix`.
   *
   * The zone is FORCED here rather than inherited, because a suite running in
   * UTC cannot see this defect at all — which is exactly why no existing test
   * caught it.
   */
  describe('a due date is a calendar day, not an instant', () => {
    const original = process.env.TZ;
    beforeAll(() => {
      process.env.TZ = 'America/Phoenix';
    });
    afterAll(() => {
      process.env.TZ = original;
    });

    it('names the day the service stored, west of UTC', () => {
      expect(dueLabel(task({ dueAt: '2026-09-03T00:00:00.000Z' }))).toBe(
        'Suggested by September 3, 2026',
      );
    });

    it('and east of it', () => {
      process.env.TZ = 'Asia/Tokyo';
      // The other direction fails differently — a naive local render would gain
      // a day here rather than lose one — so both arms are named.
      expect(dueLabel(task({ dueAt: '2026-09-03T00:00:00.000Z' }))).toBe(
        'Suggested by September 3, 2026',
      );
      process.env.TZ = 'America/Phoenix';
    });

    it('leaves a real INSTANT in the reader’s own zone', () => {
      /*
       * The positive control, and the reason `formatDate` was not simply
       * changed to match: `completedAt` is a genuine timestamp, and a reader in
       * Phoenix should see it in Phoenix time. Late UTC on the 20th is still
       * the 20th at UTC-7, so this asserts the CONVERSION happened rather than
       * that it was skipped.
       */
      expect(dueLabel(task({ completedAt: '2026-08-21T02:00:00.000Z' }))).toBe(
        'Done August 20, 2026',
      );
    });
  });

  it('never says "overdue" — the deadline is an estimate, not a legal one', () => {
    const label = dueLabel(task({ dueAt: '2020-01-01T00:00:00.000Z' }));
    expect(label).toMatch(/suggested by/i);
    expect(label).not.toMatch(/overdue|late/i);
  });

  it('reports a completed row by when it was done, not by when it was due', () => {
    expect(dueLabel(DONE)).toMatch(/^Done /);
  });

  it('says nothing rather than inventing a date the template does not set', () => {
    expect(dueLabel(task({ dueAt: null }))).toBeNull();
    // ...and an unparseable one degrades to the same silence, never to
    // "Invalid Date" on a screen somebody reads days after a death.
    expect(dueLabel(task({ dueAt: 'not-a-date' }))).toBeNull();
  });
});

describe('the checklist', () => {
  it('shows a COMPLETED item, still on the list and ticked', async () => {
    installGraphqlFetchMock(handlers());
    render(<EstateChecklist caseId={CASE_ID} />);
    expect(await screen.findByText(DONE.title)).toBeInTheDocument();
    expect(boxFor(DONE.title).checked).toBe(true);
    expect(boxFor('original will').checked).toBe(false);
  });

  it('shows a step aimed at somebody ELSE, and says whose it is', async () => {
    installGraphqlFetchMock(
      handlers({
        tasks: () =>
          jsonResponse({
            data: {
              estateTasks: [
                task({ title: 'File the petition for probate', assignedRole: 'attorney' }),
              ],
            },
          }),
      }),
    );
    render(<EstateChecklist caseId={CASE_ID} />);
    // The attorney files it; the executor is answerable for whether it was
    // filed. Hiding it would hide the thing they have to chase.
    expect(await screen.findByText(/File the petition/i)).toBeInTheDocument();
    expect(screen.getByText(/the attorney’s step/i)).toBeInTheDocument();
  });

  it('says out loud that it is not legal advice', async () => {
    installGraphqlFetchMock(handlers());
    render(<EstateChecklist caseId={CASE_ID} />);
    await screen.findByText(DONE.title);
    expect(screen.getByText(/isn’t legal advice/i)).toBeInTheDocument();
  });

  it('ticks an open item, sending the boolean the server decides on', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<EstateChecklist caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('checkbox', { name: /original will/i }));
    await waitFor(() => {
      expect(boxFor('original will').checked).toBe(true);
    });
    expect(ticks(requests)).toEqual([{ taskId: 'task-1', completed: true }]);
  });

  it('UNTICKS a completed one through the same control', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<EstateChecklist caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('checkbox', { name: /death certificate/i }));
    await waitFor(() => {
      expect(boxFor('death certificate').checked).toBe(false);
    });
    /*
     * ONE CONTROL, `completed: false`. There is no separate "reopen" button and
     * no confirmation in front of it: correcting a mistaken tick is the
     * protective action here, and it must never be harder than making one.
     */
    expect(ticks(requests)).toEqual([{ taskId: 'task-2', completed: false }]);
  });

  it('does NOT ask for a step-up code to tick something', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<EstateChecklist caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('checkbox', { name: /original will/i }));
    await waitFor(() => {
      expect(boxFor('original will').checked).toBe(true);
    });
    // A tick moves no access and transfers no value. An executor days after a
    // death should not have to find their authenticator to record one.
    expect(screen.queryByLabelText(/six-digit code|authentication code/i)).not.toBeInTheDocument();
    expect(requests.map(operationOf)).not.toContain('StepUp');
  });

  it('leaves the box where it was when the write is REFUSED', async () => {
    installGraphqlFetchMock(handlers({ tick: () => graphqlError('UNKNOWN') }));
    render(<EstateChecklist caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('checkbox', { name: /original will/i }));
    // Nothing was applied optimistically, so there is nothing to roll back —
    // and the reader is never shown a step recorded that was not.
    expect(await screen.findByText(/something went wrong/i)).toBeInTheDocument();
    expect(boxFor('original will').checked).toBe(false);
  });

  it('renders a failed READ as its own panel, never as an empty checklist', async () => {
    installGraphqlFetchMock(handlers({ tasks: () => graphqlError('UNKNOWN') }));
    render(<EstateChecklist caseId={CASE_ID} />);
    // "There is nothing to do" and "we could not reach the service" have
    // different remedies, so they never share a screen.
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.queryByText(/no checklist on this estate yet/i)).not.toBeInTheDocument();
  });

  it('treats a version-skewed BFF’s missing field as a failed read', async () => {
    installGraphqlFetchMock(handlers({ tasks: () => jsonResponse({ data: {} }) }));
    render(<EstateChecklist caseId={CASE_ID} />);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
  });

  it('says an EMPTY checklist is empty, in words', async () => {
    installGraphqlFetchMock(handlers({ tasks: () => jsonResponse({ data: { estateTasks: [] } }) }));
    render(<EstateChecklist caseId={CASE_ID} />);
    expect(await screen.findByText(/no checklist on this estate yet/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /try again/i })).not.toBeInTheDocument();
  });

  it('asks for the CASE and sends no user id', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<EstateChecklist caseId={CASE_ID} />);
    await screen.findByText(DONE.title);
    const read = requests.find((r) => operationOf(r) === 'EstateTasks');
    expect(read?.body.variables).toEqual({ caseId: CASE_ID });
  });
});

function operationOf(request: RecordedRequest): string | undefined {
  return request.body.query?.split(/[\s({]+/)[1];
}

function ticks(requests: RecordedRequest[]): unknown[] {
  return requests
    .filter((r) => operationOf(r) === 'SetEstateTaskCompletion')
    .map((r) => r.body.variables);
}
