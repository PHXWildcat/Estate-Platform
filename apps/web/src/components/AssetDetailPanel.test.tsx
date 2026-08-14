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
  retiredAt: null,
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
    expect(update?.body.variables).toEqual({
      assetId: ASSET_ID,
      expectedVersion: '3',
      title: 'Lake house (north)',
      notes: null,
      clientEventId: expect.stringMatching(/^[0-9a-f-]{36}$/) as unknown as string,
    });
    const variables = update?.body.variables as Record<string, unknown>;
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

    expect(
      await screen.findByText(/This changed since you opened it/),
    ).toBeInTheDocument();
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

describe('historyDetail', () => {
  it('renders known keys and money through formatMoney', () => {
    expect(
      historyDetail({ estValue: '850000.00', valuationAsOf: '2026-07-01', valuationSource: 'appraisal' }),
    ).toBe('value $850,000.00 as of 2026-07-01 (appraisal)');
  });

  it('renders a cleared field as cleared, never as a value', () => {
    expect(historyDetail({ notes: null })).toBe('notes cleared');
  });

  it('degrades to an empty detail on an unknown payload rather than crashing', () => {
    expect(historyDetail({ mystery: { deep: true } })).toBe('');
  });
});
