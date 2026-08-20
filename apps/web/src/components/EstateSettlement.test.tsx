import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ACCESS_STAGES, type EstateAccessStageInfo } from '../graphql/client';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { EstateSettlement, requestableStage, stageState } from './EstateSettlement';

/**
 * SETTLING AN ESTATE (M23 PR2).
 *
 * Three properties carry this file.
 *
 * The FIRST is that exactly one rung is ever offered, and it is the one
 * settlement would accept. The service refuses a stage whose predecessor is not
 * approved (`stage_out_of_order`) and one that already has a live request
 * (`stage_exists`); offering either is offering an action the server will
 * refuse, which is the thing this repo says never to do.
 *
 * The SECOND is that a REVOKED stage takes back what it opened. Access is a
 * grant and not a fact, and a surface that kept showing the inventory after the
 * stage behind it was closed would be the one screen in the product that
 * disagrees with the authorization system.
 *
 * The THIRD is that a failed read is never an empty estate. "This estate holds
 * nothing" is a statement about a dead person's affairs, and it must never be
 * a guess made on the strength of a 503.
 */

const CASE_ID = 'case-1';

const KASE = {
  caseId: CASE_ID,
  ownerName: 'Ada Lovelace',
  status: 'verified',
  verifiedAt: '2026-08-19T00:00:00.000Z',
};

function stage(over: Partial<EstateAccessStageInfo> = {}): EstateAccessStageInfo {
  return {
    stage: 'INVENTORY',
    status: 'approved',
    requestedAt: '2026-08-19T00:00:00.000Z',
    decidedAt: '2026-08-19T01:00:00.000Z',
    ...over,
  };
}

const ASSET = {
  assetId: 'asset-1',
  category: 'real_estate',
  title: 'The house on Elm Street',
  estValue: '450000.00',
  valuationAsOf: null,
  valuationSource: null,
  ownershipPct: 100,
  inTrust: false,
  fundingStatus: null,
  status: 'live',
  retiredAt: null,
  version: '3',
};

function handlers(
  options: {
    cases?: OperationHandler;
    stages?: OperationHandler;
    inventory?: OperationHandler;
    request?: OperationHandler;
  } = {},
): Record<string, OperationHandler> {
  return {
    ExecutorCases: options.cases ?? (() => jsonResponse({ data: { executorCases: [KASE] } })),
    EstateStages: options.stages ?? (() => jsonResponse({ data: { estateStages: [] } })),
    EstateInventory:
      options.inventory ?? (() => jsonResponse({ data: { estateInventory: [ASSET] } })),
    RequestEstateAccess:
      options.request ??
      (() =>
        jsonResponse({
          data: { requestEstateAccess: stage({ status: 'requested', decidedAt: null }) },
        })),
  };
}

/**
 * THE ORDER IS DERIVED FROM THE SDL, not restated here.
 *
 * `enum-parity.test.ts` compares the union's MEMBERS and sorts, so declaration
 * order is deliberately free there. Order is a security property on this
 * ladder — vault last means Zone A is never released alongside the inventory,
 * and it decides which rung `requestableStage` offers — so it gets its own
 * check against the schema that declares it.
 */
describe('the ladder’s order', () => {
  it('matches the SDL’s AccessStage declaration, top to bottom', () => {
    const source = readFileSync(
      join(__dirname, '..', '..', '..', '..', 'apps', 'bff', 'src', 'schema.ts'),
      'utf8',
    );
    const block = /enum AccessStage \{([^}]*)\}/.exec(source);
    const members = (block?.[1] ?? '')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => /^[A-Z_]+$/.test(line));
    // Anti-vacuity: two empty lists agree perfectly.
    expect(members.length).toBeGreaterThan(0);
    expect(ACCESS_STAGES).toEqual(members);
    expect(ACCESS_STAGES.at(-1)).toBe('VAULT');
  });
});

describe('which rung may be requested', () => {
  it('offers the first stage on a case with no ladder yet', () => {
    expect(requestableStage([])).toBe('INVENTORY');
  });

  it('offers NOTHING while a request is with the operator', () => {
    // `stage_exists` covers `requested` AND `approved`, so a second request
    // while one is pending is refused by the service.
    expect(requestableStage([stage({ status: 'requested', decidedAt: null })])).toBeNull();
  });

  it('offers the NEXT stage once its predecessor is approved', () => {
    expect(requestableStage([stage({ status: 'approved' })])).toBe('DOCUMENTS');
  });

  it('offers a DENIED stage again, and does not skip past it', () => {
    // A denial is not permanent — the service lets it be re-requested, and the
    // ladder must not advance over a rung that never opened.
    expect(requestableStage([stage({ status: 'denied' })])).toBe('INVENTORY');
  });

  it('offers a REVOKED stage again rather than the one above it', () => {
    /*
     * ONE ROW, not two. Revoking UPDATES the grant in place, and a second row
     * for the same stage cannot exist while the first is live — `stage_exists`
     * refuses it. A fixture with an approved row AND a revoked row for one
     * stage is a state the service cannot produce, and testing it would have
     * pinned this surface to a database that does not exist.
     */
    expect(requestableStage([stage({ status: 'revoked' })])).toBe('INVENTORY');
  });

  it('a re-request after a revocation is the live row, and the old one is history', () => {
    // The order `listByCase` returns: oldest first. The newer live row wins.
    const rows = [stage({ status: 'revoked' }), stage({ status: 'approved' })];
    expect(stageState(rows, 'INVENTORY')?.status).toBe('approved');
    expect(requestableStage(rows)).toBe('DOCUMENTS');
  });

  it('never offers vault while documents is unapproved, however the rows are ordered', () => {
    const rows = [
      stage({ stage: 'DOCUMENTS', status: 'denied' }),
      stage({ stage: 'INVENTORY', status: 'approved' }),
    ];
    expect(requestableStage(rows)).toBe('DOCUMENTS');
  });

  it('a live row wins over an older decided one for the same stage', () => {
    // Denied, then re-requested. `StagesRepo.findLive` uses this precedence to
    // decide whether a new request is allowed; the surface must agree with it.
    const rows = [stage({ status: 'denied' }), stage({ status: 'requested', decidedAt: null })];
    expect(stageState(rows, 'INVENTORY')?.status).toBe('requested');
    expect(requestableStage(rows)).toBeNull();
  });
});

describe('the estate screen', () => {
  it('renders every rung, including the ones that are still shut', async () => {
    installGraphqlFetchMock(handlers());
    render(<EstateSettlement caseId={CASE_ID} />);
    // SCOPED TO THE LADDER's own list. "The estate inventory" is legitimately
    // both a rung and the heading of the section below it, and an unscoped
    // query that matched either would pass while the ladder rendered nothing.
    const ladder = within(await screen.findByRole('list'));
    // The whole ladder, not just what works: a closed door with no explanation
    // reads as a broken page.
    expect(ladder.getByText('The estate inventory')).toBeInTheDocument();
    expect(ladder.getByText('Documents')).toBeInTheDocument();
    expect(ladder.getByText('The sealed vault')).toBeInTheDocument();
    // ...each saying what it IS, rather than listing bare stage names.
    expect(ladder.getByText(/only their owner could open them/i)).toBeInTheDocument();
    // ...and each carrying its state, so "shut" never reads as "broken".
    expect(ladder.getAllByText(/not requested yet/i)).toHaveLength(3);
  });

  it('offers exactly ONE request button', async () => {
    installGraphqlFetchMock(
      handlers({ stages: () => jsonResponse({ data: { estateStages: [stage()] } }) }),
    );
    render(<EstateSettlement caseId={CASE_ID} />);
    await waitFor(() => {
      expect(screen.getAllByRole('button', { name: /request access/i })).toHaveLength(1);
    });
  });

  it('sends the stage as the enum member name the wire expects', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<EstateSettlement caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: /request access/i }));
    await waitFor(() => {
      const sent = requests.filter((r) => r.body.query?.includes('RequestEstateAccess'));
      // UPPERCASE. GraphQL serialises an enum as its member NAME, and a
      // lowercase value here is a hard execution failure rather than a
      // silently-false comparison — the M20 PR1 defect's better half.
      expect(sent[0]?.body.variables).toEqual({ caseId: CASE_ID, stage: 'INVENTORY' });
    });
  });

  it('reads the inventory ONLY once its stage is approved', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<EstateSettlement caseId={CASE_ID} />);
    await screen.findByRole('button', { name: /request access/i });
    // Audited-decrypt volume is a UI constraint: every row of that list is a
    // KMS operation and an audit event on a dead person's trail. A locked
    // stage must not spend one.
    expect(requests.filter((r) => r.body.query?.includes('EstateInventory'))).toHaveLength(0);
    expect(
      screen.getByText(/opens once the inventory stage above is approved/i),
    ).toBeInTheDocument();
  });

  it('shows the inventory when the stage is approved, with money formatted not parsed', async () => {
    installGraphqlFetchMock(
      handlers({ stages: () => jsonResponse({ data: { estateStages: [stage()] } }) }),
    );
    render(<EstateSettlement caseId={CASE_ID} />);
    expect(await screen.findByText(/the house on elm street/i)).toBeInTheDocument();
    expect(screen.getByText('$450,000.00')).toBeInTheDocument();
  });

  it('a REVOKED stage takes the inventory away with it', async () => {
    installGraphqlFetchMock(
      handlers({
        stages: () => jsonResponse({ data: { estateStages: [stage({ status: 'revoked' })] } }),
      }),
    );
    render(<EstateSettlement caseId={CASE_ID} />);
    await screen.findByRole('button', { name: /request access/i });
    expect(screen.queryByText(/the house on elm street/i)).not.toBeInTheDocument();
    expect(screen.getByText(/closed again/i)).toBeInTheDocument();
  });

  it('a stage REVOKED under the reader takes the inventory back on reload', async () => {
    /*
     * WRITTEN BECAUSE A MUTATION SURVIVED. Deleting the `else` that re-locks
     * the inventory left every test green, because each one renders a fresh
     * component where `locked` is already the initial state. The branch only
     * matters on a RELOAD — and this is the sequence that reaches it: the
     * inventory is open, an operator revokes the stage, and the executor's
     * next action re-reads the ladder. A surface that kept the list it had
     * would be the one screen in the product still showing an estate the
     * authorization system has closed.
     */
    let ladder = [stage({ status: 'approved' })];
    installGraphqlFetchMock(
      handlers({
        stages: () => jsonResponse({ data: { estateStages: ladder } }),
        request: () => {
          ladder = [stage({ status: 'revoked' })];
          return jsonResponse({
            data: { requestEstateAccess: stage({ stage: 'DOCUMENTS', status: 'requested' }) },
          });
        },
      }),
    );
    render(<EstateSettlement caseId={CASE_ID} />);
    // Open, and showing the estate.
    expect(await screen.findByText(/the house on elm street/i)).toBeInTheDocument();

    // The executor asks for the next rung; the reload finds the first revoked.
    fireEvent.click(screen.getByRole('button', { name: /request access/i }));
    await waitFor(() => {
      expect(screen.queryByText(/the house on elm street/i)).not.toBeInTheDocument();
    });
    expect(
      screen.getByText(/opens once the inventory stage above is approved/i),
    ).toBeInTheDocument();
  });

  it('a failed inventory read is not an empty estate', async () => {
    installGraphqlFetchMock(
      handlers({
        stages: () => jsonResponse({ data: { estateStages: [stage()] } }),
        inventory: () => graphqlError('UNKNOWN'),
      }),
    );
    render(<EstateSettlement caseId={CASE_ID} />);
    expect(await screen.findByText(/couldn’t load the inventory/i)).toBeInTheDocument();
    expect(screen.queryByText(/nothing recorded in this estate/i)).not.toBeInTheDocument();
  });

  it('an EMPTY inventory is a real answer and says so', async () => {
    installGraphqlFetchMock(
      handlers({
        stages: () => jsonResponse({ data: { estateStages: [stage()] } }),
        inventory: () => jsonResponse({ data: { estateInventory: [] } }),
      }),
    );
    render(<EstateSettlement caseId={CASE_ID} />);
    expect(await screen.findByText(/nothing recorded in this estate/i)).toBeInTheDocument();
  });

  it('a case this caller does not administer reads as not found, not as an error', async () => {
    // Reached by URL, so somebody can arrive here with a stale or borrowed id.
    // The copy must not tell them whether the id names anything.
    installGraphqlFetchMock(handlers());
    render(<EstateSettlement caseId="not-mine" />);
    expect(await screen.findByText(/couldn’t find that/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /try again/i })).not.toBeInTheDocument();
  });

  it('a failed CASE read is an error with a retry, never "no estate here"', async () => {
    installGraphqlFetchMock(handlers({ cases: () => graphqlError('UNKNOWN') }));
    render(<EstateSettlement caseId={CASE_ID} />);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.queryByText(/couldn’t find that/i)).not.toBeInTheDocument();
  });

  it('treats a version-skewed BFF’s missing field as no data', async () => {
    installGraphqlFetchMock(handlers({ stages: () => jsonResponse({ data: {} }) }));
    render(<EstateSettlement caseId={CASE_ID} />);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
  });

  it('renders STAGE_OUT_OF_ORDER as the ladder working, not as a failure', async () => {
    installGraphqlFetchMock(handlers({ request: () => graphqlError('STAGE_OUT_OF_ORDER') }));
    render(<EstateSettlement caseId={CASE_ID} />);
    fireEvent.click(await screen.findByRole('button', { name: /request access/i }));
    expect(
      await screen.findByText(/stage before this one hasn’t been approved/i),
    ).toBeInTheDocument();
  });
});
