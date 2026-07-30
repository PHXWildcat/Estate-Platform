import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { AssetsPanel } from './AssetsPanel';

const pushMock = jest.fn();
const refreshMock = jest.fn();
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: pushMock, refresh: refreshMock }),
}));

const ASSET = {
  assetId: 'a2c2e6a4-0000-4000-8000-00000000000a',
  category: 'real_estate',
  title: 'The lake house',
  estValue: '450000.00',
  ownershipPct: 50,
  inTrust: true,
  version: '4',
};

const NET_WORTH = {
  totalValue: '225000.00',
  assetCount: 1,
  valuedAssetCount: 1,
  inTrustValue: '225000.00',
};

function assetsHandler(assets = [ASSET]): OperationHandler {
  return () => jsonResponse({ data: { assets } });
}
function netWorthHandler(netWorth = NET_WORTH): OperationHandler {
  return () => jsonResponse({ data: { netWorth } });
}

/** Fill the create form; the valuation fields only exist once a value is typed. */
function fillCreateForm(options: { title: string; value?: string; asOf?: string }): void {
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: options.title } });
  if (options.value !== undefined) {
    fireEvent.change(screen.getByLabelText('Estimated value (optional)'), {
      target: { value: options.value },
    });
  }
  if (options.asOf !== undefined) {
    fireEvent.change(screen.getByLabelText('Value as of'), { target: { value: options.asOf } });
  }
}

describe('AssetsPanel', () => {
  it('renders net worth and the inventory, money verbatim as decimal strings', async () => {
    installGraphqlFetchMock({ Assets: assetsHandler(), NetWorth: netWorthHandler() });
    render(<AssetsPanel />);

    // Rendered EXACTLY as the ledger sent it — never parsed through a float.
    expect(await screen.findByText('$225000.00')).toBeInTheDocument();
    expect(screen.getByText('The lake house')).toBeInTheDocument();
    expect(screen.getByText('$450000.00')).toBeInTheDocument();
    // Partial ownership and trust status are surfaced, not silently dropped.
    expect(screen.getByText(/Real estate · in trust · 50% owned/)).toBeInTheDocument();
  });

  it('shows a sign-in prompt when unauthenticated, never an error', async () => {
    installGraphqlFetchMock({
      Assets: () => graphqlError('UNAUTHENTICATED'),
      NetWorth: () => graphqlError('UNAUTHENTICATED'),
    });
    render(<AssetsPanel />);

    expect(await screen.findByText('Sign in required')).toBeInTheDocument();
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
  });

  it('shows a generic failure for any other error', async () => {
    installGraphqlFetchMock({
      Assets: () => graphqlError('UNKNOWN'),
      NetWorth: netWorthHandler(),
    });
    render(<AssetsPanel />);

    expect(await screen.findByText(/couldn’t load your assets/)).toBeInTheDocument();
  });

  it('invites a first asset when the inventory is empty', async () => {
    installGraphqlFetchMock({
      Assets: assetsHandler([]),
      NetWorth: netWorthHandler({ ...NET_WORTH, assetCount: 0, valuedAssetCount: 0 }),
    });
    render(<AssetsPanel />);

    expect(await screen.findByText(/Nothing recorded yet/)).toBeInTheDocument();
  });

  it('creates an asset with no valuation, then reloads', async () => {
    let requests: RecordedRequest[] = [];
    let listCalls = 0;
    const mock = installGraphqlFetchMock({
      Assets: () => {
        listCalls += 1;
        return jsonResponse({ data: { assets: [] } });
      },
      NetWorth: netWorthHandler(),
      CreateAsset: () => jsonResponse({ data: { createAsset: { assetId: 'x', version: '1' } } }),
    });
    requests = mock.requests;
    render(<AssetsPanel />);
    await screen.findByLabelText('Name');

    fillCreateForm({ title: 'Wallet' });
    fireEvent.click(screen.getByRole('button', { name: 'Add asset' }));

    await waitFor(() => {
      expect(listCalls).toBeGreaterThan(1); // reloaded after success
    });
    const create = requests.find((r) => r.body.query?.includes('CreateAsset'));
    // No valuation keys at all — not nulls, not empty strings.
    expect(create?.body.variables).toEqual({ category: 'cash', title: 'Wallet' });
  });

  it('sends the valuation TRIPLE together when a value is given', async () => {
    const { requests } = installGraphqlFetchMock({
      Assets: assetsHandler([]),
      NetWorth: netWorthHandler(),
      CreateAsset: () => jsonResponse({ data: { createAsset: { assetId: 'x', version: '1' } } }),
    });
    render(<AssetsPanel />);
    await screen.findByLabelText('Name');

    fillCreateForm({ title: 'Chase checking', value: '12500.50' });
    fillCreateForm({ title: 'Chase checking', asOf: '2026-07-01' });
    fireEvent.click(screen.getByRole('button', { name: 'Add asset' }));

    await waitFor(() => {
      expect(requests.some((r) => r.body.query?.includes('CreateAsset'))).toBe(true);
    });
    const create = requests.find((r) => r.body.query?.includes('CreateAsset'));
    expect(create?.body.variables).toEqual({
      category: 'cash',
      title: 'Chase checking',
      estValue: '12500.50',
      valuationAsOf: '2026-07-01',
      valuationSource: 'owner_estimate',
    });
  });

  it('refuses to submit a value without a date — the ledger’s all-or-nothing rule', async () => {
    const { requests } = installGraphqlFetchMock({
      Assets: assetsHandler([]),
      NetWorth: netWorthHandler(),
    });
    render(<AssetsPanel />);
    await screen.findByLabelText('Name');

    fillCreateForm({ title: 'Chase checking', value: '100.00' });
    fireEvent.click(screen.getByRole('button', { name: 'Add asset' }));

    expect(await screen.findByText('Add the date this value is as of.')).toBeInTheDocument();
    // Never reached the network: no partial valuation is ever sent.
    expect(requests.some((r) => r.body.query?.includes('CreateAsset'))).toBe(false);
  });

  it('validates the amount format and the required name locally', async () => {
    const { requests } = installGraphqlFetchMock({
      Assets: assetsHandler([]),
      NetWorth: netWorthHandler(),
    });
    render(<AssetsPanel />);
    await screen.findByLabelText('Name');

    fireEvent.click(screen.getByRole('button', { name: 'Add asset' }));
    expect(await screen.findByText('Give the asset a name.')).toBeInTheDocument();

    fillCreateForm({ title: 'Odd', value: '1,000' });
    fireEvent.click(screen.getByRole('button', { name: 'Add asset' }));
    expect(await screen.findByText(/plain amount like 12500/)).toBeInTheDocument();
    expect(requests.some((r) => r.body.query?.includes('CreateAsset'))).toBe(false);
  });

  it('surfaces a create failure in generic copy and keeps the form filled', async () => {
    installGraphqlFetchMock({
      Assets: assetsHandler([]),
      NetWorth: netWorthHandler(),
      CreateAsset: () => graphqlError('INVALID_REQUEST'),
    });
    render(<AssetsPanel />);
    await screen.findByLabelText('Name');

    fillCreateForm({ title: 'Wallet' });
    fireEvent.click(screen.getByRole('button', { name: 'Add asset' }));

    expect(await screen.findByText(/wasn’t right/)).toBeInTheDocument();
    expect(screen.getByLabelText('Name')).toHaveValue('Wallet');
  });

  it('hides the valuation fields until an amount is entered', async () => {
    installGraphqlFetchMock({ Assets: assetsHandler([]), NetWorth: netWorthHandler() });
    render(<AssetsPanel />);
    await screen.findByLabelText('Name');

    expect(screen.queryByLabelText('Value as of')).not.toBeInTheDocument();
    fillCreateForm({ title: 'House', value: '1' });
    expect(screen.getByLabelText('Value as of')).toBeInTheDocument();
    expect(screen.getByLabelText('Where the value came from')).toBeInTheDocument();
  });
});
