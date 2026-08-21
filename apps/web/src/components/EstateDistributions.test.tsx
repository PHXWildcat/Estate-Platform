import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ContactSummaryInfo, EstateDistributionInfo } from '../graphql/client';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { EstateDistributions, MOVES, beneficiaryName, statusLabel } from './EstateDistributions';

/**
 * DISTRIBUTIONS (M23 PR4b). Four properties carry this file.
 *
 * The FIRST is that NO AMOUNT IS FETCHED WHILE RENDERING. Every figure is an
 * audited decrypt on a dead person's key and an event on their trail, so the
 * list must open having read none of them and spend exactly one per press.
 *
 * The SECOND is that APPROVAL IS NOWHERE. Clearing a distribution is an
 * operator's act under dual control and a DDL CHECK forbids the approver being
 * the recorder — so there must be no control for it on this screen, and the
 * moves that ARE offered must be the ones the service would accept.
 *
 * The THIRD is that CONTACTS DECORATE AND NEVER GATE. The beneficiary names
 * sit behind the documents rung; a shut rung must cost this panel its names
 * and nothing else, because a distribution is not a look inside the estate.
 *
 * The FOURTH is that BOTH WRITES ARE STEP-UP GATED, and the retry carries its
 * own arguments rather than re-reading a form the reader may have edited.
 */

const CASE_ID = 'case-1';

function distribution(over: Partial<EstateDistributionInfo> = {}): EstateDistributionInfo {
  return {
    distributionId: 'dist-1',
    beneficiaryContactId: 'contact-1',
    assetId: null,
    status: 'planned',
    approvedAt: null,
    hasAmount: true,
    createdAt: '2026-08-20T00:00:00.000Z',
    ...over,
  };
}

const CONTACT: ContactSummaryInfo = {
  id: 'contact-1',
  name: 'Charles Babbage',
  relationship: 'child',
  professionalKind: null,
  hasEmail: false,
  hasPhone: false,
  hasAddress: false,
  hasNotes: false,
  linked: false,
};

function handlers(over: Record<string, OperationHandler> = {}): Record<string, OperationHandler> {
  return {
    EstateDistributions: () => jsonResponse({ data: { estateDistributions: [distribution()] } }),
    EstateContacts: () => jsonResponse({ data: { estateContacts: [CONTACT] } }),
    EstateDistributionAmount: (variables) =>
      jsonResponse({
        data: {
          estateDistributionAmount: {
            distributionId: (variables as { distributionId: string }).distributionId,
            amount: '999999999999999.99',
          },
        },
      }),
    ...over,
  };
}

/** Operation names actually dispatched, in order. */
function operations(requests: RecordedRequest[]): string[] {
  return requests.map((r) => r.body.query?.split(/[\s({]+/)[1] ?? '');
}

/**
 * THE MOVES OFFERED ARE THE SERVICE'S OWN, DERIVED.
 *
 * `AdminService.setDistributionStatus` computes the legal `from` states for
 * each target status, and that expression is what the RUNTIME reads. Parsing
 * it and inverting it gives the same map from the other direction, so the
 * table this screen renders buttons from cannot drift away from the table the
 * server enforces — and the failure it prevents is concrete: a button that
 * answers DISTRIBUTION_NOT_APPROVED every single time it is pressed.
 */
describe('the moves offered are the moves the server allows', () => {
  const SERVICE = join(
    __dirname,
    '..',
    '..',
    '..',
    'services',
    'settlement',
    'src',
    'admin.service.ts',
  );

  /** target status -> the statuses it may be reached FROM, per the service. */
  function serviceTransitions(): Map<string, string[]> {
    const source = readFileSync(SERVICE, 'utf8');
    const block = /const from: DistributionStatus\[\] =([\s\S]*?);\n/.exec(source);
    // Anti-vacuity: an anchor that stopped matching would slice to nothing and
    // make the comparison below compare two empty maps.
    expect(block?.[1]?.length ?? 0).toBeGreaterThan(50);
    const found = new Map<string, string[]>();
    for (const [, target, list] of (block?.[1] ?? '').matchAll(
      /to === '(\w+)'\s*\n?\s*\?\s*\[([^\]]*)\]/g,
    )) {
      found.set(
        target as string,
        [...(list as string).matchAll(/'(\w+)'/g)].map((m) => m[1] as string),
      );
    }
    /*
     * The final `: ['in_progress']` arm has no `to === ...` guard of its own —
     * it is whatever target the two guarded arms did not claim.
     *
     * ANCHORED AT THE END OF THE BLOCK, not on a trailing semicolon: the block
     * capture above stops BEFORE the `;`, so a `\];` anchor here matched
     * nothing and quietly produced `[undefined]`. The floor below is what
     * turns that into a failure instead of a silently narrower table — the
     * first version of it asked only for a non-empty array, and `[undefined]`
     * is non-empty.
     */
    const tail = /:\s*\['(\w+)'\]\s*$/.exec(block?.[1] ?? '');
    expect(tail?.[1]).toBeTruthy();
    const guarded = ['disputed', 'in_progress', 'completed'].filter((s) => !found.has(s));
    expect(guarded).toHaveLength(1);
    found.set(guarded[0] as string, [tail?.[1] as string]);
    return found;
  }

  it('mirrors the service’s transition table, inverted', () => {
    const transitions = serviceTransitions();
    // Anti-vacuity: three targets, each with at least one legal predecessor.
    expect([...transitions.keys()].sort()).toEqual(['completed', 'disputed', 'in_progress']);
    // ...and every predecessor is a REAL status string. `[undefined]` passes a
    // length check and then vanishes from the inversion below, which is
    // exactly how the first draft of this fence went green on a broken parse.
    expect(
      [...transitions.values()].flat().every((from) => typeof from === 'string' && from !== ''),
    ).toBe(true);
    expect([...transitions.values()].every((from) => from.length > 0)).toBe(true);

    // Invert: from-status -> the targets reachable from it.
    const expected = new Map<string, string[]>();
    for (const [target, froms] of transitions) {
      for (const from of froms) {
        expected.set(from, [...(expected.get(from) ?? []), target.toUpperCase()]);
      }
    }
    for (const [from, targets] of expected) {
      // SETS, not counts — a target mis-attributed from one status to another
      // preserves every length involved.
      expect([...(MOVES[from] ?? [])].sort()).toEqual([...targets].sort());
    }
    // ...and every status the screen knows about is accounted for, so a status
    // with an invented move is caught as well as one with a missing move.
    for (const [from, targets] of Object.entries(MOVES)) {
      expect([...targets].sort()).toEqual([...(expected.get(from) ?? [])].sort());
    }
  });

  it('offers NOTHING from planned — dual control has not been satisfied', () => {
    expect(MOVES['planned']).toEqual([]);
  });

  it('never offers the operator’s own act, from any status', () => {
    // The property the whole table exists to protect: approving is not
    // reachable from this screen, whatever a row's status is.
    expect(Object.values(MOVES).flat()).not.toContain('APPROVED');
  });
});

describe('what a row says', () => {
  it('says the review is OURS, not a task on the executor’s list', () => {
    // "Pending" alone reads as something they forgot to do. The wait is ours.
    expect(statusLabel('planned')).toMatch(/our review/i);
    expect(statusLabel('completed')).toBe('Paid out');
  });

  it('shows a status this build has not learned as ITSELF, never hidden', () => {
    // The DDL owns this vocabulary. A row we cannot label is still a row
    // somebody needs to see.
    expect(statusLabel('escheated')).toBe('escheated');
  });

  it('resolves a beneficiary only when the names are actually there', () => {
    expect(beneficiaryName({ kind: 'ready', contacts: [CONTACT] }, 'contact-1')).toBe(
      'Charles Babbage',
    );
    expect(beneficiaryName({ kind: 'locked' }, 'contact-1')).toBeNull();
    expect(beneficiaryName({ kind: 'ready', contacts: [CONTACT] }, 'contact-x')).toBeNull();
  });
});

describe('the distributions panel', () => {
  it('opens having read NO amount, and spends exactly one per press', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<EstateDistributions caseId={CASE_ID} />);
    const reveal = await screen.findByRole('button', { name: /show amount/i });

    // THE PROPERTY: the list rendered without a single decrypt.
    expect(operations(requests)).not.toContain('EstateDistributionAmount');

    fireEvent.click(reveal);
    // ...and the figure arrives EXACTLY, as the string it was recorded as. A
    // Number on this path returns '1000000000000000' — a cent light.
    expect(await screen.findByText('999999999999999.99')).toBeInTheDocument();
    expect(operations(requests).filter((op) => op === 'EstateDistributionAmount')).toHaveLength(1);
  });

  it('renders a revealed NULL as "no amount recorded", not as a failure', async () => {
    installGraphqlFetchMock(
      handlers({
        EstateDistributionAmount: () =>
          jsonResponse({
            data: { estateDistributionAmount: { distributionId: 'dist-1', amount: null } },
          }),
      }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: /show amount/i }));
    expect(await screen.findByText(/no amount recorded/i)).toBeInTheDocument();
  });

  it('renders a crypto-shredded amount as PERMANENT, with no retry offered', async () => {
    installGraphqlFetchMock(
      handlers({ EstateDistributionAmount: () => graphqlError('CONTENT_ERASED') }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: /show amount/i }));
    // The sentence has to close the question rather than invite another press.
    expect(await screen.findByText(/can’t be recovered/i)).toBeInTheDocument();
  });

  it('lists every distribution when the NAMES are locked behind the rung', async () => {
    installGraphqlFetchMock(handlers({ EstateContacts: () => graphqlError('STAGE_NOT_APPROVED') }));
    render(<EstateDistributions caseId={CASE_ID} />);
    const list = await screen.findByRole('list');
    // CONTACTS DECORATE, NEVER GATE. A shut rung costs the panel its names and
    // nothing else — the row is still here.
    expect(within(list).getAllByRole('listitem')).toHaveLength(1);
    expect(within(list).getByText(/a person this estate named/i)).toBeInTheDocument();
    // ...and recording says WHY it is unavailable rather than showing a form
    // with nobody to choose.
    expect(await screen.findByText(/open with the documents stage/i)).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /record a distribution/i }),
    ).not.toBeInTheDocument();
  });

  it('names the beneficiary once the rung IS open', async () => {
    // Positive control for the test above: the name is missing there because
    // the rung is shut, not because this panel never renders one.
    installGraphqlFetchMock(handlers());
    render(<EstateDistributions caseId={CASE_ID} />);
    expect(await screen.findByText('Charles Babbage')).toBeInTheDocument();
  });

  it('offers no move at all on a PLANNED row', async () => {
    installGraphqlFetchMock(handlers());
    render(<EstateDistributions caseId={CASE_ID} />);
    await screen.findByRole('list');
    // Never offer an action the server would refuse: nothing moves until an
    // operator has approved it.
    expect(screen.queryByRole('button', { name: /mark as/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /dispute/i })).not.toBeInTheDocument();
  });

  it('offers exactly the two moves an APPROVED row allows, and never approval', async () => {
    installGraphqlFetchMock(
      handlers({
        EstateDistributions: () =>
          jsonResponse({
            data: { estateDistributions: [distribution({ status: 'approved' })] },
          }),
      }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    expect(await screen.findByRole('button', { name: /mark as started/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /raise a dispute/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /mark as paid out/i })).not.toBeInTheDocument();
    // The one that must never exist anywhere on this screen.
    expect(screen.queryByRole('button', { name: /approve/i })).not.toBeInTheDocument();
  });

  it('renders a failed READ as its own panel, never as an empty estate', async () => {
    installGraphqlFetchMock(handlers({ EstateDistributions: () => graphqlError('UNKNOWN') }));
    render(<EstateDistributions caseId={CASE_ID} />);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.queryByText(/nothing has been recorded/i)).not.toBeInTheDocument();
  });

  it('treats a version-skewed BFF’s missing field as a failed read', async () => {
    installGraphqlFetchMock(handlers({ EstateDistributions: () => jsonResponse({ data: {} }) }));
    render(<EstateDistributions caseId={CASE_ID} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    });
    expect(screen.queryByText(/nothing has been recorded/i)).not.toBeInTheDocument();
  });
});

describe('recording one', () => {
  async function openForm(): Promise<void> {
    fireEvent.click(await screen.findByRole('button', { name: /record a distribution/i }));
    fireEvent.change(await screen.findByLabelText(/who it goes to/i), {
      target: { value: 'contact-1' },
    });
  }

  it('sends the amount as the STRING typed, and reports what the SERVER did', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({
        RecordEstateDistribution: () =>
          jsonResponse({
            data: {
              recordEstateDistribution: distribution({
                distributionId: 'dist-new',
                status: 'planned',
              }),
            },
          }),
      }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    await openForm();
    fireEvent.change(screen.getByLabelText(/amount/i), { target: { value: '2500.50' } });
    fireEvent.click(screen.getByRole('button', { name: /record it/i }));

    await waitFor(() => {
      expect(operations(requests)).toContain('RecordEstateDistribution');
    });
    const sent = requests.find((r) => r.body.query?.includes('RecordEstateDistribution'))?.body
      .variables as { amount: unknown };
    // A DECIMAL STRING. A Number here would round an estate's figure.
    expect(sent.amount).toBe('2500.50');
    expect(typeof sent.amount).toBe('string');

    // ...and the confirmation says the row is WAITING, not cleared. "Recorded"
    // alone would let an executor believe money was free to move.
    expect(await screen.findByText(/with our team for review/i)).toBeInTheDocument();
  });

  it('sends an EMPTY amount box as null, never as zero', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({
        RecordEstateDistribution: () =>
          jsonResponse({ data: { recordEstateDistribution: distribution({ hasAmount: false }) } }),
      }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    await openForm();
    fireEvent.click(screen.getByRole('button', { name: /record it/i }));

    await waitFor(() => {
      expect(operations(requests)).toContain('RecordEstateDistribution');
    });
    const sent = requests.find((r) => r.body.query?.includes('RecordEstateDistribution'))?.body
      .variables as { amount: unknown };
    // '0' would be a recorded sum of nothing, which is a different fact from
    // "this distribution is an item rather than a sum".
    expect(sent.amount).toBeNull();
  });

  /**
   * THE RETRY CARRIES ITS OWN ARGUMENTS.
   *
   * The step-up prompt REPLACES nothing here that the reader could edit, but
   * the rule is the same one every gated write in this app holds: the action
   * retried after elevation is the one that was refused, taken from the
   * pending union, never re-read from current form state.
   */
  it('prompts for step-up and retries the REFUSED action, not the form', async () => {
    let refuse = true;
    const { requests } = installGraphqlFetchMock(
      handlers({
        RecordEstateDistribution: () => {
          if (refuse) {
            refuse = false;
            return graphqlError('STEPUP_REQUIRED');
          }
          return jsonResponse({ data: { recordEstateDistribution: distribution() } });
        },
      }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    await openForm();
    fireEvent.change(screen.getByLabelText(/amount/i), { target: { value: '10.00' } });
    fireEvent.click(screen.getByRole('button', { name: /record it/i }));

    // The prompt appeared, and it names what is being confirmed.
    expect(await screen.findByText(/moves value out of this estate/i)).toBeInTheDocument();
    expect(requests.filter((r) => r.body.query?.includes('RecordEstateDistribution'))).toHaveLength(
      1,
    );
  });

  it('leaves the list as the server last described it when a write fails', async () => {
    installGraphqlFetchMock(
      handlers({ RecordEstateDistribution: () => graphqlError('CASE_NOT_VERIFIED') }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    await openForm();
    fireEvent.click(screen.getByRole('button', { name: /record it/i }));
    // Nothing was applied optimistically, so there is nothing to roll back —
    // and the refusal gets its own sentence rather than a generic apology.
    expect(await screen.findByText(/hasn’t reached the point/i)).toBeInTheDocument();
    expect(screen.queryByText(/with our team for review/i)).not.toBeInTheDocument();
  });
});

describe('moving one on', () => {
  it('sends the enum member NAME the schema declares', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({
        EstateDistributions: () =>
          jsonResponse({ data: { estateDistributions: [distribution({ status: 'approved' })] } }),
        SetEstateDistributionStatus: () =>
          jsonResponse({
            data: {
              setEstateDistributionStatus: distribution({ status: 'in_progress' }),
            },
          }),
      }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: /mark as started/i }));

    await waitFor(() => {
      expect(operations(requests)).toContain('SetEstateDistributionStatus');
    });
    const sent = requests.find((r) => r.body.query?.includes('SetEstateDistributionStatus'))?.body
      .variables as { status: unknown };
    // UPPERCASE: GraphQL serialises an enum as its member name, and a
    // lowercase value here fails at the BFF rather than comparing false.
    expect(sent.status).toBe('IN_PROGRESS');
  });

  it('says the dual-control refusal is a WAIT, not a mistake', async () => {
    installGraphqlFetchMock(
      handlers({
        EstateDistributions: () =>
          jsonResponse({ data: { estateDistributions: [distribution({ status: 'approved' })] } }),
        SetEstateDistributionStatus: () => graphqlError('DISTRIBUTION_NOT_APPROVED'),
      }),
    );
    render(<EstateDistributions caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: /mark as started/i }));
    // The remedy is a second person, so the sentence must not end in "try
    // again" — a loop with no exit for the person reading it.
    const message = await screen.findByText(/waiting on our review/i);
    expect(message.textContent ?? '').not.toMatch(/try again/i);
  });
});
