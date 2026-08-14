import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AssetDetailPanel, historyDetail } from './AssetDetailPanel';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';

const ASSET_ID = 'a2c2e6a4-0000-4000-8000-00000000000a';

const DETAIL = {
  assetId: ASSET_ID,
  category: 'real_estate',
  title: 'Lake house',
  estValue: '850000.00',
  valuationAsOf: '2026-07-01',
  valuationSource: 'appraisal',
  ownershipPct: 100,
  costBasis: '400000.00',
  location: 'deed drawer',
  notes: 'shared with Sam',
  inTrust: true,
  fundingStatus: 'funded',
  status: 'live',
  retiredAt: null as string | null,
  version: '3',
};

const ACK = {
  assetId: ASSET_ID,
  eventId: 'e2c2e6a4-0000-4000-8000-00000000000e',
  version: '4',
  occurredAt: '2026-08-13T00:00:00.000Z',
  replayed: false,
};

function detailHandler(overrides: Partial<typeof DETAIL> = {}) {
  return () => jsonResponse({ data: { asset: { ...DETAIL, ...overrides } } });
}

describe('AssetDetailPanel', () => {
  it('renders the full record, including the fields the list cannot carry', async () => {
    installGraphqlFetchMock({ Asset: detailHandler() });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    expect(await screen.findByText('Lake house')).toBeInTheDocument();
    expect(screen.getByText('deed drawer')).toBeInTheDocument();
    expect(screen.getByText('shared with Sam')).toBeInTheDocument();
    expect(screen.getByText('$850,000.00')).toBeInTheDocument();
  });

  it('reads a BFF response missing its field as NO DATA, never as data (M11)', async () => {
    // A BFF predating the Asset query answers {"data":{}} with ok=true.
    installGraphqlFetchMock({ Asset: () => jsonResponse({ data: {} }) });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    expect(await screen.findByText(/couldn’t load this asset/)).toBeInTheDocument();
  });

  it('renders the uniform not-found copy for NOT_FOUND', async () => {
    installGraphqlFetchMock({ Asset: () => graphqlError('NOT_FOUND') });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    expect(await screen.findByText('That isn’t available.')).toBeInTheDocument();
  });

  it('a RETIRED asset shows its record and NO action forms', async () => {
    // Never offer what the server refuses (the M12 legal-hold lesson):
    // commands on a retired asset answer 404, so the forms are absent.
    installGraphqlFetchMock({
      Asset: detailHandler({ status: 'retired', retiredAt: '2026-08-10T00:00:00.000Z' }),
    });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    expect(await screen.findByText(/This asset was retired/)).toBeInTheDocument();
    expect(screen.queryByText('Record a value')).not.toBeInTheDocument();
    expect(screen.queryByText('Retire this asset')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit details' })).not.toBeInTheDocument();
    // The record itself still reads.
    expect(screen.getByText('deed drawer')).toBeInTheDocument();
  });

  it('RETIRING RUNS THE STEP-UP CEREMONY, and the form hides while it is up', async () => {
    // M19 PR4: retirement is the service's one irreversible verb and was its
    // least guarded — proven live, designate answered 403 stepup_required on
    // the same session that retired an asset with a 200.
    let attempts = 0;
    installGraphqlFetchMock({
      Asset: detailHandler(),
      RetireAsset: () => {
        attempts += 1;
        return attempts === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { retireAsset: ACK } });
      },
    });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');
    fireEvent.click(screen.getByRole('button', { name: 'Retire…' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm retire' }));

    // The refusal opens the prompt, and the retire form goes away with it:
    // two visible Cancels is the M15 identical-label ambiguity.
    expect(await screen.findByLabelText(/Confirm it’s you|Confirm it's you/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm retire' })).not.toBeInTheDocument();
    expect(screen.getByText(/cannot be undone/)).toBeInTheDocument();
  });

  it('a cancelled retire ceremony retires nothing', async () => {
    let attempts = 0;
    installGraphqlFetchMock({
      Asset: detailHandler(),
      RetireAsset: () => {
        attempts += 1;
        return graphqlError('STEPUP_REQUIRED');
      },
    });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');
    fireEvent.click(screen.getByRole('button', { name: 'Retire…' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm retire' }));
    await screen.findByLabelText(/Confirm it’s you|Confirm it's you/);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => {
      expect(screen.queryByLabelText(/Confirm it’s you|Confirm it's you/)).not.toBeInTheDocument();
    });
    expect(attempts).toBe(1);
  });

  it('an OPEN edit form closes when the asset is retired underneath it', async () => {
    // The M19 PR4 review's finding: `!retired` gated the "Edit details" BUTTON
    // and not the FORM it opens, and both the form and the retire control are
    // on screen at once — so retiring while editing left an edit form for an
    // asset the service now answers 404 for. Reachable only by changing status
    // WHILE the form is open, which the retired-from-first-render case cannot
    // construct.
    let reads = 0;
    installGraphqlFetchMock({
      Asset: () => {
        reads += 1;
        return reads === 1
          ? jsonResponse({ data: { asset: DETAIL } })
          : jsonResponse({
              data: { asset: { ...DETAIL, status: 'retired', retiredAt: '2026-08-13T00:00:00Z' } },
            });
      },
      RetireAsset: () => jsonResponse({ data: { retireAsset: ACK } }),
    });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');
    fireEvent.click(screen.getByRole('button', { name: 'Edit details' }));
    expect(screen.getByLabelText('Name')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Retire…' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm retire' }));

    expect(await screen.findByText(/This asset was retired/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
  });

  it('a DESIGNATION drops an open history view, which would otherwise be one event short', async () => {
    // M19 PR4: `onVersionBumped` advanced the version and left the loaded
    // ledger alone, so after designating a beneficiary the history on screen
    // was missing the event that bump refers to — while the version beside it
    // said the asset had moved on. `reloadAfter` drops history to idle for
    // this panel's own commands for exactly this reason; the designation path
    // bypassed it.
    installGraphqlFetchMock({
      Asset: detailHandler(),
      AssetHistory: () =>
        jsonResponse({
          data: {
            assetHistory: [
              {
                version: '1',
                eventId: 'e1',
                eventType: 'AssetCreated',
                occurredAt: '2026-07-01T00:00:00.000Z',
                payload: { v: 1, type: 'AssetCreated', title: 'Lake house' },
              },
            ],
          },
        }),
      AssetBeneficiaries: () =>
        jsonResponse({
          data: { assetBeneficiaries: { assetId: ASSET_ID, beneficiaries: [], totals: [] } },
        }),
      // The contact shape is the BFF's `ContactSummary`, copied from the
      // beneficiary panel's own fixture rather than invented — an invented
      // one renders "no contacts" and the designation never runs, which is a
      // test that measures the fixture.
      Contacts: () =>
        jsonResponse({
          data: {
            contacts: [
              {
                id: 'c1c1e6a4-0000-4000-8000-00000000000c',
                name: 'Alice Attorney',
                relationship: 'friend',
                professionalKind: 'attorney',
                hasEmail: true,
                hasPhone: false,
                hasAddress: false,
                hasNotes: false,
                linked: false,
              },
            ],
          },
        }),
      DesignateBeneficiary: () =>
        jsonResponse({ data: { designateBeneficiary: { ...ACK, version: '5' } } }),
    });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');
    fireEvent.click(screen.getByRole('button', { name: /history/i }));
    expect(await screen.findByText('Added to the estate')).toBeInTheDocument();

    // The REAL child flow, not a test hook: a designation is what calls
    // onVersionBumped, and production code must not grow a handle for a test.
    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    fireEvent.change(await screen.findByLabelText('Who'), {
      target: { value: 'c1c1e6a4-0000-4000-8000-00000000000c' },
    });
    fireEvent.change(screen.getByLabelText('Share %'), { target: { value: '100' } });
    fireEvent.click(screen.getByRole('button', { name: 'Designate' }));

    await waitFor(() => {
      expect(screen.queryByText('Added to the estate')).not.toBeInTheDocument();
    });
  });

  it('loads history ONLY on demand — the decrypt budget is the design', async () => {
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      Asset: detailHandler(),
      AssetHistory: () =>
        jsonResponse({
          data: {
            assetHistory: [
              {
                version: '1',
                eventId: 'e1',
                eventType: 'AssetCreated',
                occurredAt: '2026-07-01T00:00:00.000Z',
                payload: { v: 1, type: 'AssetCreated', title: 'Lake house' },
              },
              {
                version: '2',
                eventId: 'e2',
                eventType: 'ValuationRecorded',
                occurredAt: '2026-07-02T00:00:00.000Z',
                payload: { estValue: '850000.00', valuationSource: 'appraisal' },
              },
            ],
          },
        }),
    });
    requests = mock.requests;
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');
    // Nothing prefetched: each history entry costs an audited decrypt.
    expect(requests.some((r) => r.body.query?.includes('AssetHistory'))).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: 'Load history' }));
    expect(await screen.findByText('Added to the estate')).toBeInTheDocument();
    expect(screen.getByText(/Value recorded/)).toBeInTheDocument();
    // Once in the header, once in the history entry.
    expect(screen.getAllByText(/\$850,000\.00/).length).toBeGreaterThan(1);
  });

  it('edit sends ONLY changed fields, and a cleared field travels as NULL', async () => {
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      Asset: detailHandler(),
      UpdateAsset: () => jsonResponse({ data: { updateAsset: ACK } }),
    });
    requests = mock.requests;
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');

    fireEvent.click(screen.getByRole('button', { name: 'Edit details' }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Lake house (north)' } });
    // Clearing notes = the explicit CLEAR; location untouched = absent.
    fireEvent.change(screen.getByLabelText('Notes'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => {
      expect(requests.some((r) => r.body.query?.includes('UpdateAsset'))).toBe(true);
    });
    const update = requests.find((r) => r.body.query?.includes('UpdateAsset'));
    const { clientEventId, ...variables } = update?.body.variables as Record<string, unknown>;
    expect(String(clientEventId)).toMatch(/^[0-9a-f-]{36}$/);
    expect(variables).toEqual({
      assetId: ASSET_ID,
      expectedVersion: '3',
      title: 'Lake house (north)',
      notes: null,
    });
    expect(variables).not.toHaveProperty('location');
    expect(variables).not.toHaveProperty('inTrust');
  });

  it('a stale version surfaces the re-read copy and never auto-retries', async () => {
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      Asset: detailHandler(),
      RecordValuation: () => graphqlError('VERSION_CONFLICT'),
    });
    requests = mock.requests;
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');

    fireEvent.change(screen.getByLabelText('Value'), { target: { value: '900000.00' } });
    fireEvent.change(screen.getByLabelText('As of'), { target: { value: '2026-08-13' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record value' }));

    expect(await screen.findByText(/This changed since you opened it/)).toBeInTheDocument();
    // Exactly ONE mutation request: the remedy is re-read, never blind retry.
    expect(requests.filter((r) => r.body.query?.includes('RecordValuation'))).toHaveLength(1);
  });

  it('a successful valuation re-reads the record and says so', async () => {
    let assetReads = 0;
    installGraphqlFetchMock({
      Asset: () => {
        assetReads += 1;
        return jsonResponse({
          data: { asset: assetReads > 1 ? { ...DETAIL, estValue: '900000.00' } : DETAIL },
        });
      },
      RecordValuation: () => jsonResponse({ data: { recordValuation: ACK } }),
    });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');

    fireEvent.change(screen.getByLabelText('Value'), { target: { value: '900000.00' } });
    fireEvent.change(screen.getByLabelText('As of'), { target: { value: '2026-08-13' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record value' }));

    expect(await screen.findByText('Value recorded.')).toBeInTheDocument();
    expect(assetReads).toBeGreaterThan(1);
    expect(screen.getByText('$900,000.00')).toBeInTheDocument();
  });

  it('a replayed ack is reported as a retry, not a fresh change', async () => {
    installGraphqlFetchMock({
      Asset: detailHandler(),
      RetireAsset: () => jsonResponse({ data: { retireAsset: { ...ACK, replayed: true } } }),
    });
    render(<AssetDetailPanel assetId={ASSET_ID} />);
    await screen.findByText('Lake house');

    fireEvent.click(screen.getByRole('button', { name: 'Retire…' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm retire' }));

    expect(await screen.findByText(/Already applied/)).toBeInTheDocument();
  });
});

it('updates ownership and shows validation for a bad share', async () => {
  let requests = [];
  const mock = installGraphqlFetchMock({
    Asset: detailHandler(),
    ChangeOwnership: () => jsonResponse({ data: { changeOwnership: ACK } }),
  });
  requests = mock.requests;
  render(<AssetDetailPanel assetId={ASSET_ID} />);
  await screen.findByText('Lake house');

  fireEvent.change(screen.getByLabelText('Your ownership share %'), {
    target: { value: '150' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Update ownership' }));
  expect(await screen.findByText(/between 0 and 100/)).toBeInTheDocument();
  expect(requests.some((r) => r.body.query?.includes('ChangeOwnership'))).toBe(false);

  fireEvent.change(screen.getByLabelText('Your ownership share %'), {
    target: { value: '50' },
  });
  fireEvent.change(screen.getByLabelText('Cost basis (optional)'), {
    target: { value: '400000.00' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Update ownership' }));
  expect(await screen.findByText('Ownership updated.')).toBeInTheDocument();
  const call = requests.find((r) => r.body.query?.includes('ChangeOwnership'));
  const vars = call?.body.variables as Record<string, unknown>;
  expect(vars['ownershipPct']).toBe(50);
  expect(vars['costBasis']).toBe('400000.00');
  expect(vars['expectedVersion']).toBe('3');
});

it('validates the valuation form before any request leaves', async () => {
  let requests = [];
  const mock = installGraphqlFetchMock({ Asset: detailHandler() });
  requests = mock.requests;
  render(<AssetDetailPanel assetId={ASSET_ID} />);
  await screen.findByText('Lake house');

  fireEvent.change(screen.getByLabelText('Value'), { target: { value: 'not-money' } });
  fireEvent.click(screen.getByRole('button', { name: 'Record value' }));
  expect(await screen.findByText(/plain amount/)).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Value'), { target: { value: '900000.00' } });
  fireEvent.click(screen.getByRole('button', { name: 'Record value' }));
  expect(await screen.findByText(/date this value is as of/)).toBeInTheDocument();
  expect(requests.some((r) => r.body.query?.includes('RecordValuation'))).toBe(false);
});

it('edit cancel restores the read view without a request', async () => {
  let requests = [];
  const mock = installGraphqlFetchMock({ Asset: detailHandler() });
  requests = mock.requests;
  render(<AssetDetailPanel assetId={ASSET_ID} />);
  await screen.findByText('Lake house');
  fireEvent.click(screen.getByRole('button', { name: 'Edit details' }));
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.getByRole('button', { name: 'Edit details' })).toBeInTheDocument();
  expect(requests.some((r) => r.body.query?.includes('UpdateAsset'))).toBe(false);
});

it('renders the signed-out state on UNAUTHENTICATED', async () => {
  installGraphqlFetchMock({ Asset: () => graphqlError('UNAUTHENTICATED') });
  render(<AssetDetailPanel assetId={ASSET_ID} />);
  expect(await screen.findByText('Sign in required')).toBeInTheDocument();
});

it('edit exercises the trust/funding controls and surfaces a command failure', async () => {
  installGraphqlFetchMock({
    Asset: detailHandler(),
    UpdateAsset: () => graphqlError('INVALID_REQUEST'),
  });
  render(<AssetDetailPanel assetId={ASSET_ID} />);
  await screen.findByText('Lake house');
  fireEvent.click(screen.getByRole('button', { name: 'Edit details' }));
  fireEvent.click(screen.getByLabelText('Titled in a trust'));
  fireEvent.change(screen.getByLabelText('Trust funding status'), { target: { value: '' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
  expect(await screen.findByText(/Something about that request/)).toBeInTheDocument();
  // A blank name is refused locally before any request.
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: '   ' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
  expect(await screen.findByText('The asset needs a name.')).toBeInTheDocument();
});

it('surfaces ownership and retire command failures in copy', async () => {
  installGraphqlFetchMock({
    Asset: detailHandler(),
    ChangeOwnership: () => graphqlError('VERSION_CONFLICT'),
    RetireAsset: () => graphqlError('VERSION_CONFLICT'),
  });
  render(<AssetDetailPanel assetId={ASSET_ID} />);
  await screen.findByText('Lake house');

  fireEvent.change(screen.getByLabelText('Your ownership share %'), {
    target: { value: '50' },
  });
  fireEvent.change(screen.getByLabelText('Cost basis (optional)'), {
    target: { value: 'abc' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Update ownership' }));
  expect(await screen.findByText(/Cost basis must be a plain amount/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Cost basis (optional)'), { target: { value: '' } });
  fireEvent.click(screen.getByRole('button', { name: 'Update ownership' }));
  expect((await screen.findAllByText(/This changed since you opened it/)).length).toBe(1);

  fireEvent.click(screen.getByRole('button', { name: 'Retire…' }));
  fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'gifted' } });
  fireEvent.click(screen.getByRole('button', { name: 'Confirm retire' }));
  await waitFor(() => {
    expect(screen.getAllByText(/This changed since you opened it/).length).toBe(2);
  });
  // Cancel disarms the confirm step.
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.getByRole('button', { name: 'Retire…' })).toBeInTheDocument();
});

it('history load failure reads as an error, not an empty ledger', async () => {
  installGraphqlFetchMock({
    Asset: detailHandler(),
    AssetHistory: () => graphqlError('UNKNOWN'),
  });
  render(<AssetDetailPanel assetId={ASSET_ID} />);
  await screen.findByText('Lake house');
  fireEvent.click(screen.getByRole('button', { name: 'Load history' }));
  expect(await screen.findByText(/couldn’t load the history/)).toBeInTheDocument();
});

describe('historyDetail', () => {
  it('renders known keys and money through formatMoney', () => {
    expect(
      historyDetail({
        estValue: '850000.00',
        valuationAsOf: '2026-07-01',
        valuationSource: 'appraisal',
      }),
    ).toBe('value $850,000.00 as of 2026-07-01 (appraisal)');
  });

  it('renders a cleared field as cleared, never as a value', () => {
    expect(historyDetail({ notes: null })).toBe('notes cleared');
  });

  it('degrades to an empty detail on an unknown payload rather than crashing', () => {
    expect(historyDetail({ mystery: { deep: true } })).toBe('');
  });

  it('covers the remaining event vocabularies defensively', () => {
    expect(historyDetail({ title: 'Boat' })).toBe('“Boat”');
    expect(historyDetail({ ownershipPct: 50 })).toBe('50% share');
    expect(historyDetail({ sharePct: 60, designation: 'primary' })).toBe('60% primary');
    expect(historyDetail({ reason: 'sold' })).toBe('reason: sold');
    expect(historyDetail({ location: 'safe' })).toBe('location updated');
    expect(historyDetail({ costBasis: '1000.00' })).toBe('cost basis $1,000.00');
    expect(historyDetail({ inTrust: true })).toBe('marked in trust');
    expect(historyDetail({ inTrust: false })).toBe('marked not in trust');
    expect(historyDetail({ fundingStatus: 'funded' })).toBe('Funded to trust');
    expect(historyDetail({ fundingStatus: null })).toBe('funding status cleared');
  });
});
