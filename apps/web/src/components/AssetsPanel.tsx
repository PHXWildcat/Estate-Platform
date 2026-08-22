'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest, type AssetInfo, type NetWorthInfo } from '../graphql/client';
import { categoryLabel } from '../lib/categories';
import { commandEventId, type CommandId } from '../lib/command-id';
import { messageFor } from '../lib/copy';
import { formatMoney } from '../lib/money';
import { formatPct } from '../lib/percent';
import { STAT_LABEL } from '../lib/stat';
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

export const FUNDING_LABELS: Record<string, string> = {
  unfunded: 'Not yet in trust',
  in_progress: 'Retitling under way',
  funded: 'Funded to trust',
  na: 'Trust funding N/A',
};

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
  const [showMore, setShowMore] = useState(false);
  const [ownershipPct, setOwnershipPct] = useState('');
  const [ownershipError, setOwnershipError] = useState<string | null>(null);
  const [inTrustNew, setInTrustNew] = useState(false);
  const [fundingStatusNew, setFundingStatusNew] = useState('');
  const [costBasis, setCostBasis] = useState('');
  const [costBasisError, setCostBasisError] = useState<string | null>(null);
  const [location, setLocation] = useState('');
  const [notes, setNotes] = useState('');
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  // Idempotency: one eventId per PAYLOAD, held across retries of the same
  // payload so a resend after a lost response is a no-op (command-id.ts).
  const createId = useRef<CommandId | null>(null);

  const [showRetired, setShowRetired] = useState(false);

  const load = useCallback(async (includeRetired: boolean): Promise<void> => {
    const [assets, netWorth] = await Promise.all([
      gqlRequest('Assets', includeRetired ? { includeRetired: true } : {}),
      gqlRequest('NetWorth', {}),
    ]);
    // SHAPE-GUARD BEFORE TRUSTING (the M11 rule, previously missing here): a
    // BFF predating a field answers {"data":{}} with ok=true, and an empty
    // page must read as NO DATA, never as an empty estate.
    if (
      assets.ok &&
      netWorth.ok &&
      Array.isArray(assets.data.assets) &&
      typeof netWorth.data.netWorth?.totalValue === 'string'
    ) {
      setState({ kind: 'ready', assets: assets.data.assets, netWorth: netWorth.data.netWorth });
      return;
    }
    const code = !assets.ok ? assets.code : !netWorth.ok ? netWorth.code : 'UNKNOWN';
    setState(code === 'UNAUTHENTICATED' ? { kind: 'signedOut' } : { kind: 'error' });
  }, []);

  useEffect(() => {
    void load(showRetired);
  }, [load, showRetired]);

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
    const trimmedOwnership = ownershipPct.trim();
    if (trimmedOwnership.length > 0) {
      const pct = Number(trimmedOwnership);
      if (!Number.isFinite(pct) || pct <= 0 || pct > 100) {
        setOwnershipError('Enter a share between 0 and 100, like 50.');
        invalid = true;
      } else {
        setOwnershipError(null);
      }
    } else {
      setOwnershipError(null);
    }
    const trimmedCostBasis = costBasis.trim();
    if (trimmedCostBasis.length > 0 && !/^\d+(\.\d{1,2})?$/.test(trimmedCostBasis)) {
      setCostBasisError('Enter a plain amount like 12500 or 12500.50, or leave it blank.');
      invalid = true;
    } else {
      setCostBasisError(null);
    }
    if (invalid) {
      return;
    }
    setCreateBusy(true);
    const trimmedLocation = location.trim();
    const trimmedNotes = notes.trim();
    const input = {
      category,
      title: trimmedTitle,
      ...(trimmedValue.length > 0
        ? { estValue: trimmedValue, valuationAsOf: trimmedAsOf, valuationSource }
        : {}),
      ...(trimmedOwnership.length > 0 ? { ownershipPct: Number(trimmedOwnership) } : {}),
      ...(inTrustNew ? { inTrust: true } : {}),
      ...(fundingStatusNew.length > 0 ? { fundingStatus: fundingStatusNew } : {}),
      ...(trimmedCostBasis.length > 0 ? { costBasis: trimmedCostBasis } : {}),
      ...(trimmedLocation.length > 0 ? { location: trimmedLocation } : {}),
      ...(trimmedNotes.length > 0 ? { notes: trimmedNotes } : {}),
    };
    createId.current = commandEventId(createId.current, JSON.stringify(input));
    const result = await gqlRequest('CreateAsset', {
      input: { ...input, clientEventId: createId.current.id },
    });
    setCreateBusy(false);
    if (!result.ok) {
      setCreateError(messageFor(result.code));
      return;
    }
    createId.current = null;
    setTitle('');
    setEstValue('');
    setValuationAsOf('');
    setOwnershipPct('');
    setInTrustNew(false);
    setFundingStatusNew('');
    setCostBasis('');
    setLocation('');
    setNotes('');
    await load(showRetired);
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
  // Live assets only: with "Show retired" on, a retired in-trust asset would
  // otherwise be COUNTED beside a server total that (correctly) excludes it —
  // a card disagreeing with itself (found by the M19 PR2 live drive).
  const inTrustCount = assets.filter((asset) => asset.inTrust && asset.status !== 'retired').length;
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
        <div className="flex items-center justify-between border-b border-line py-2">
          <h2 id="assets-heading" className={STAT_LABEL}>
            Assets
          </h2>
          <label className="flex items-center gap-2 text-[0.8125rem] text-ink-muted">
            <input
              type="checkbox"
              checked={showRetired}
              onChange={(event) => {
                setShowRetired(event.target.checked);
              }}
            />
            Show retired
          </label>
        </div>
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
                      <Link className="hover:underline" href={`/assets/${asset.assetId}`}>
                        {asset.title}
                      </Link>
                      {asset.status === 'retired' ? (
                        <span className="chip chip-warn ml-2">Retired</span>
                      ) : asset.inTrust ? (
                        <span className="chip chip-trust ml-2">In trust</span>
                      ) : null}
                      {asset.status !== 'retired' && asset.fundingStatus === 'in_progress' ? (
                        <span className="chip ml-2">Retitling</span>
                      ) : null}
                    </p>
                    {asset.ownershipPct !== 100 ? (
                      <p className="mt-0.5 text-xs text-ink-muted">
                        {formatPct(asset.ownershipPct)}% ownership
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
          {showMore ? (
            <div className="space-y-4 border-t border-line pt-4">
              <FormField
                id="asset-ownership"
                label="Ownership share % (optional)"
                type="text"
                inputMode="numeric"
                hint="Leave blank for 100%. Net worth counts only your share."
                value={ownershipPct}
                error={ownershipError}
                onChange={setOwnershipPct}
              />
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={inTrustNew}
                  onChange={(event) => {
                    setInTrustNew(event.target.checked);
                  }}
                />
                Titled in a trust
              </label>
              <div>
                <label className="field-label" htmlFor="asset-funding">
                  Trust funding status (optional)
                </label>
                <select
                  id="asset-funding"
                  className="field-input mt-1"
                  value={fundingStatusNew}
                  onChange={(event) => {
                    setFundingStatusNew(event.target.value);
                  }}
                >
                  <option value="">Not set</option>
                  <option value="unfunded">{FUNDING_LABELS['unfunded']}</option>
                  <option value="in_progress">{FUNDING_LABELS['in_progress']}</option>
                  <option value="funded">{FUNDING_LABELS['funded']}</option>
                  <option value="na">{FUNDING_LABELS['na']}</option>
                </select>
              </div>
              <FormField
                id="asset-cost-basis"
                label="Cost basis (optional)"
                type="text"
                inputMode="numeric"
                hint="What you paid. Stored encrypted; shown only to you."
                value={costBasis}
                error={costBasisError}
                onChange={setCostBasis}
              />
              <FormField
                id="asset-location"
                label="Where to find it (optional)"
                type="text"
                hint="Deed drawer, safe, institution — what your executor would need. Encrypted."
                value={location}
                error={null}
                onChange={setLocation}
              />
              <FormField
                id="asset-notes"
                label="Notes (optional)"
                type="text"
                hint="Anything else worth knowing. Encrypted."
                value={notes}
                error={null}
                onChange={setNotes}
              />
            </div>
          ) : (
            <button
              type="button"
              className="text-sm text-ink-muted underline"
              onClick={() => {
                setShowMore(true);
              }}
            >
              More details (ownership, trust, cost basis, location, notes)
            </button>
          )}
          <FormStatus tone="error" message={createError} />
          <button type="submit" className="btn btn-primary" disabled={createBusy}>
            {createBusy ? 'Adding…' : 'Add asset'}
          </button>
        </form>
      </section>
    </div>
  );
}
