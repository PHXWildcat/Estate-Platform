'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest, type AssetInfo, type NetWorthInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { formatMoney } from '../lib/money';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';

/**
 * The asset inventory: list, net worth, and a create form.
 *
 * Money stays a STRING end to end — the ledger's decimal strings are rendered
 * verbatim, never parsed into floats. The category list here is a display
 * subset of the ledger's enum; the service validates the real one.
 */

/** Display subset of the ledger's category enum (values must match it). */
const CATEGORIES = [
  'cash',
  'real_estate',
  'vehicle',
  'business',
  'crypto',
  'life_insurance',
  'digital_asset',
  'other',
] as const;

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'ready'; assets: AssetInfo[]; netWorth: NetWorthInfo };

const CATEGORY_LABELS: Record<string, string> = {
  cash: 'Cash',
  real_estate: 'Real estate',
  vehicle: 'Vehicle',
  business: 'Business',
  crypto: 'Crypto',
  life_insurance: 'Life insurance',
  digital_asset: 'Digital asset',
  other: 'Other',
};

function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? category;
}

/** Uppercase micro-label above a stat figure. */
const STAT_LABEL = 'text-[0.6875rem] font-semibold uppercase tracking-[0.08em] text-ink-muted';

export function AssetsPanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  const [title, setTitle] = useState('');
  const [titleError, setTitleError] = useState<string | null>(null);
  const [category, setCategory] = useState<string>('cash');
  const [estValue, setEstValue] = useState('');
  const [estValueError, setEstValueError] = useState<string | null>(null);
  const [valuationAsOf, setValuationAsOf] = useState('');
  const [valuationAsOfError, setValuationAsOfError] = useState<string | null>(null);
  const [valuationSource, setValuationSource] = useState<string>('owner_estimate');
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const [assets, netWorth] = await Promise.all([
      gqlRequest('Assets', {}),
      gqlRequest('NetWorth', {}),
    ]);
    if (assets.ok && netWorth.ok) {
      setState({ kind: 'ready', assets: assets.data.assets, netWorth: netWorth.data.netWorth });
      return;
    }
    const code = !assets.ok ? assets.code : !netWorth.ok ? netWorth.code : 'UNKNOWN';
    setState(code === 'UNAUTHENTICATED' ? { kind: 'signedOut' } : { kind: 'error' });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function createAsset(event: FormEvent): Promise<void> {
    event.preventDefault();
    setCreateError(null);
    const trimmedTitle = title.trim();
    const trimmedValue = estValue.trim();
    let invalid = false;
    if (trimmedTitle.length === 0) {
      setTitleError('Give the asset a name.');
      invalid = true;
    } else {
      setTitleError(null);
    }
    if (trimmedValue.length > 0 && !/^\d+(\.\d{1,2})?$/.test(trimmedValue)) {
      setEstValueError('Enter a plain amount like 12500 or 12500.50, or leave it blank.');
      invalid = true;
    } else {
      setEstValueError(null);
    }
    // A valuation is all-or-nothing (the ledger's rule): an amount without a
    // date and a source is not a claim anyone could audit later.
    const trimmedAsOf = valuationAsOf.trim();
    if (trimmedValue.length > 0 && trimmedAsOf.length === 0) {
      setValuationAsOfError('Add the date this value is as of.');
      invalid = true;
    } else {
      setValuationAsOfError(null);
    }
    if (invalid) {
      return;
    }
    setCreateBusy(true);
    const result = await gqlRequest('CreateAsset', {
      category,
      title: trimmedTitle,
      ...(trimmedValue.length > 0
        ? { estValue: trimmedValue, valuationAsOf: trimmedAsOf, valuationSource }
        : {}),
    });
    setCreateBusy(false);
    if (!result.ok) {
      setCreateError(messageFor(result.code));
      return;
    }
    setTitle('');
    setEstValue('');
    setValuationAsOf('');
    await load();
  }

  if (state.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Loading your assets…</p>
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t load your assets. Please try again in a moment.
        </p>
      </div>
    );
  }

  if (state.kind === 'signedOut') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">Sign in required</h2>
        <p className="mt-2 text-sm text-ink-muted">
          Your asset inventory belongs to your account. Sign in to see it.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          <Link className="btn btn-primary" href="/login">
            Sign in
          </Link>
          <Link className="btn btn-secondary" href="/register">
            Create account
          </Link>
        </div>
      </div>
    );
  }

  const { assets, netWorth } = state;
  const inTrustCount = assets.filter((asset) => asset.inTrust).length;
  const unvaluedCount = netWorth.assetCount - netWorth.valuedAssetCount;

  return (
    <div className="space-y-4">
      <section aria-label="Totals" className="flex flex-col gap-4 sm:flex-row">
        <div className="card flex-[1.6] p-5">
          <h2 className={STAT_LABEL}>Net worth</h2>
          <p className="mt-1.5 text-4xl font-semibold tabular-nums tracking-tight">
            {formatMoney(netWorth.totalValue)}
          </p>
          <p className="mt-1.5 text-[0.8125rem] text-ink-muted">
            {netWorth.valuedAssetCount} of {netWorth.assetCount}{' '}
            {netWorth.assetCount === 1 ? 'asset' : 'assets'} valued
          </p>
        </div>
        <div className="card flex-1 p-5">
          <h2 className={STAT_LABEL}>Held in trust</h2>
          <p className="mt-2 text-2xl font-semibold tabular-nums tracking-tight">
            {formatMoney(netWorth.inTrustValue)}
          </p>
          <p className="mt-1.5 text-[0.8125rem] text-ink-muted">
            {inTrustCount} {inTrustCount === 1 ? 'asset' : 'assets'}
          </p>
        </div>
        <div className="card flex-1 p-5">
          <h2 className={STAT_LABEL}>Inventory</h2>
          <p className="mt-2 text-2xl font-semibold tabular-nums tracking-tight">
            {netWorth.assetCount}
          </p>
          <p className="mt-1.5 text-[0.8125rem] text-ink-muted">
            {unvaluedCount === 0
              ? 'All valued'
              : `${unvaluedCount} ${unvaluedCount === 1 ? 'asset' : 'assets'} unvalued`}
          </p>
        </div>
      </section>

      <section aria-labelledby="assets-heading" className="card px-5 pb-2 pt-1 sm:px-6">
        <h2 id="assets-heading" className="sr-only">
          Assets
        </h2>
        {assets.length === 0 ? (
          <p className="py-4 text-sm text-ink-muted">
            Nothing recorded yet. Add your first asset below — every change is kept as a permanent,
            auditable history.
          </p>
        ) : (
          <>
            <div
              aria-hidden="true"
              className="grid grid-cols-[minmax(0,1fr)_7rem] gap-4 border-b border-line py-3 sm:grid-cols-[minmax(0,1fr)_9.5rem_8rem]"
            >
              <span className={STAT_LABEL}>Asset</span>
              <span className={`${STAT_LABEL} hidden sm:block`}>Category</span>
              <span className={`${STAT_LABEL} text-right`}>Value</span>
            </div>
            <ul aria-label="Your assets">
              {assets.map((asset) => (
                <li
                  key={asset.assetId}
                  className="grid grid-cols-[minmax(0,1fr)_7rem] items-center gap-4 border-b border-line py-3 last:border-b-0 sm:grid-cols-[minmax(0,1fr)_9.5rem_8rem]"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">
                      {asset.title}
                      {asset.inTrust ? (
                        <span className="chip chip-trust ml-2">In trust</span>
                      ) : null}
                    </p>
                    {asset.ownershipPct !== 100 ? (
                      <p className="mt-0.5 text-xs text-ink-muted">
                        {asset.ownershipPct}% ownership
                      </p>
                    ) : null}
                  </div>
                  <p className="hidden text-[0.8125rem] text-ink-muted sm:block">
                    {categoryLabel(asset.category)}
                  </p>
                  <p className="text-right text-sm font-medium tabular-nums">
                    {formatMoney(asset.estValue)}
                  </p>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section id="add-asset" aria-labelledby="add-asset-heading" className="card scroll-mt-6 p-6">
        <h2 id="add-asset-heading" className="text-lg font-semibold">
          Add an asset
        </h2>
        <form
          className="mt-4 space-y-4"
          noValidate
          onSubmit={(event) => {
            void createAsset(event);
          }}
        >
          <FormField
            id="asset-title"
            label="Name"
            type="text"
            hint="How you’d describe it to your executor — “Chase checking”, “The lake house”."
            value={title}
            error={titleError}
            onChange={setTitle}
          />
          <div>
            <label className="field-label" htmlFor="asset-category">
              Category
            </label>
            <select
              id="asset-category"
              className="field-input mt-1"
              value={category}
              onChange={(event) => {
                setCategory(event.target.value);
              }}
            >
              {CATEGORIES.map((value) => (
                <option key={value} value={value}>
                  {categoryLabel(value)}
                </option>
              ))}
            </select>
          </div>
          <FormField
            id="asset-value"
            label="Estimated value (optional)"
            type="text"
            inputMode="numeric"
            hint="Dollars, e.g. 12500.50. Stored encrypted; shown only to you."
            value={estValue}
            error={estValueError}
            onChange={setEstValue}
          />
          {estValue.trim().length > 0 ? (
            <>
              <div>
                <label className="field-label" htmlFor="asset-as-of">
                  Value as of
                </label>
                <p id="asset-as-of-hint" className="field-hint">
                  A value is only meaningful with a date and a source — that is what makes it
                  auditable later.
                </p>
                <input
                  id="asset-as-of"
                  type="date"
                  className="field-input mt-1"
                  value={valuationAsOf}
                  aria-describedby="asset-as-of-hint asset-as-of-error"
                  onChange={(event) => {
                    setValuationAsOf(event.target.value);
                  }}
                />
                <div id="asset-as-of-error" role="status" aria-live="polite">
                  {valuationAsOfError !== null ? (
                    <p className="text-sm text-danger">{valuationAsOfError}</p>
                  ) : null}
                </div>
              </div>
              <div>
                <label className="field-label" htmlFor="asset-source">
                  Where the value came from
                </label>
                <select
                  id="asset-source"
                  className="field-input mt-1"
                  value={valuationSource}
                  onChange={(event) => {
                    setValuationSource(event.target.value);
                  }}
                >
                  <option value="owner_estimate">My own estimate</option>
                  <option value="appraisal">Appraisal</option>
                  <option value="purchase_price">Purchase price</option>
                  <option value="market">Market price</option>
                </select>
              </div>
            </>
          ) : null}
          <FormStatus tone="error" message={createError} />
          <button type="submit" className="btn btn-primary" disabled={createBusy}>
            {createBusy ? 'Adding…' : 'Add asset'}
          </button>
        </form>
      </section>
    </div>
  );
}
