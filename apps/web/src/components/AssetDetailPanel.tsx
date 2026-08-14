'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactElement } from 'react';
import {
  gqlRequest,
  type AssetDetailInfo,
  type AssetHistoryEntryInfo,
  type GqlFailureCode,
} from '../graphql/client';
import { commandEventId, type CommandId } from '../lib/command-id';
import { messageFor } from '../lib/copy';
import { formatMoney } from '../lib/money';
import { formatPct } from '../lib/percent';
import { AssetBeneficiaries } from './AssetBeneficiaries';
import { FUNDING_LABELS } from './AssetsPanel';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';
import { StepUpPrompt } from './StepUpPrompt';

/**
 * One asset's full record and its command surface (M19 PR2).
 *
 * THE DECRYPT BUDGET SHAPES THIS PAGE: the detail read costs four audited
 * decrypts, and the ledger history costs ONE PER EVENT — so history loads
 * only on an explicit press, is never prefetched, and is never re-fetched on
 * a re-render (docs/03 §4 TB4, the M18 decrypt-rate baseline).
 *
 * CONCURRENCY: every command carries `expectedVersion` (the version this
 * page last READ). A stale one answers VERSION_CONFLICT, and the remedy is
 * always RE-READ — the page never blind-retries over someone else's newer
 * change. Idempotency: each form mints a clientEventId per payload
 * (command-id.ts), so resending after a lost response is a no-op.
 *
 * RETIRED ASSETS render their record and NO action forms — the server
 * refuses commands on them, and offering what the server refuses is the M12
 * rule broken (the documents legal-hold lesson).
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'notFound' }
  | { kind: 'error' }
  | { kind: 'ready'; asset: AssetDetailInfo };

type HistoryState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'error' }
  | { kind: 'ready'; entries: AssetHistoryEntryInfo[] };

const EVENT_LABELS: Record<string, string> = {
  AssetCreated: 'Added to the estate',
  ValuationRecorded: 'Value recorded',
  AssetDetailsUpdated: 'Details updated',
  OwnershipChanged: 'Ownership changed',
  BeneficiaryDesignated: 'Beneficiary designated',
  BeneficiaryRemoved: 'Beneficiary designation removed',
  AssetRetired: 'Retired',
};

const SOURCE_LABELS: Record<string, string> = {
  owner_estimate: 'my own estimate',
  appraisal: 'appraisal',
  purchase_price: 'purchase price',
  market: 'market price',
};

const RETIRE_REASONS: Array<{ value: string; label: string }> = [
  { value: 'sold', label: 'Sold' },
  { value: 'gifted', label: 'Gifted' },
  { value: 'lost', label: 'Lost or destroyed' },
  { value: 'error', label: 'Added by mistake' },
  { value: 'other', label: 'Other' },
];

/**
 * Renders a ledger payload DEFENSIVELY: every key is type-checked before
 * use, unknown keys are ignored, and an unknown event still renders its
 * type token. The payload is the service's own validated output, but a
 * version-skewed page must degrade to less detail, never to a crash.
 */
export function historyDetail(payload: Record<string, unknown>): string {
  const parts: string[] = [];
  if (typeof payload['title'] === 'string') {
    parts.push(`“${payload['title']}”`);
  }
  if (typeof payload['estValue'] === 'string') {
    let phrase = `value ${formatMoney(payload['estValue'])}`;
    if (typeof payload['valuationAsOf'] === 'string') {
      phrase += ` as of ${payload['valuationAsOf']}`;
    }
    if (typeof payload['valuationSource'] === 'string') {
      phrase += ` (${SOURCE_LABELS[payload['valuationSource']] ?? payload['valuationSource']})`;
    }
    parts.push(phrase);
  }
  if (typeof payload['ownershipPct'] === 'number') {
    parts.push(`${formatPct(payload['ownershipPct'])}% share`);
  }
  if (typeof payload['sharePct'] === 'number' && typeof payload['designation'] === 'string') {
    parts.push(`${formatPct(payload['sharePct'])}% ${payload['designation']}`);
  }
  if (typeof payload['reason'] === 'string') {
    parts.push(`reason: ${payload['reason']}`);
  }
  const fieldNotes: string[] = [];
  for (const field of ['location', 'notes', 'costBasis'] as const) {
    if (payload[field] === null) {
      fieldNotes.push(`${field} cleared`);
    } else if (field !== 'costBasis' && typeof payload[field] === 'string') {
      fieldNotes.push(`${field} updated`);
    } else if (field === 'costBasis' && typeof payload[field] === 'string') {
      fieldNotes.push(`cost basis ${formatMoney(payload[field])}`);
    }
  }
  if (typeof payload['inTrust'] === 'boolean') {
    fieldNotes.push(payload['inTrust'] ? 'marked in trust' : 'marked not in trust');
  }
  if (typeof payload['fundingStatus'] === 'string') {
    fieldNotes.push(FUNDING_LABELS[payload['fundingStatus']] ?? payload['fundingStatus']);
  } else if (payload['fundingStatus'] === null) {
    fieldNotes.push('funding status cleared');
  }
  parts.push(...fieldNotes);
  return parts.join(' · ');
}

export function AssetDetailPanel({ assetId }: { assetId: string }): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [history, setHistory] = useState<HistoryState>({ kind: 'idle' });
  const [notice, setNotice] = useState<string | null>(null);

  // ---- forms ----------------------------------------------------------
  const [valAmount, setValAmount] = useState('');
  const [valAmountError, setValAmountError] = useState<string | null>(null);
  const [valAsOf, setValAsOf] = useState('');
  const [valSource, setValSource] = useState('owner_estimate');
  const [valBusy, setValBusy] = useState(false);
  const [valError, setValError] = useState<string | null>(null);
  const valId = useRef<CommandId | null>(null);

  const [editing, setEditing] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [editLocation, setEditLocation] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [editInTrust, setEditInTrust] = useState(false);
  const [editFunding, setEditFunding] = useState('');
  const [editBusy, setEditBusy] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const editId = useRef<CommandId | null>(null);

  const [ownPct, setOwnPct] = useState('');
  const [ownPctError, setOwnPctError] = useState<string | null>(null);
  const [ownCostBasis, setOwnCostBasis] = useState('');
  const [ownBusy, setOwnBusy] = useState(false);
  const [ownError, setOwnError] = useState<string | null>(null);
  const ownId = useRef<CommandId | null>(null);

  const [retireArmed, setRetireArmed] = useState(false);
  const [retireReason, setRetireReason] = useState('sold');
  const [retireBusy, setRetireBusy] = useState(false);
  const [retireError, setRetireError] = useState<string | null>(null);
  /** The refused retirement, carrying its OWN arguments for the retry. */
  const [pendingRetire, setPendingRetire] = useState<{
    expectedVersion: string;
    reason: string;
  } | null>(null);
  const retireId = useRef<CommandId | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('Asset', { assetId });
    // SHAPE-GUARD BEFORE DESTRUCTURING (M11): a BFF predating this query
    // answers {"data":{}} — that is NO DATA, never data.
    if (result.ok && typeof result.data.asset?.assetId === 'string') {
      setState({ kind: 'ready', asset: result.data.asset });
      return;
    }
    const code: GqlFailureCode = result.ok ? 'UNKNOWN' : result.code;
    setState(
      code === 'UNAUTHENTICATED'
        ? { kind: 'signedOut' }
        : code === 'NOT_FOUND'
          ? { kind: 'notFound' }
          : { kind: 'error' },
    );
  }, [assetId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function loadHistory(): Promise<void> {
    setHistory({ kind: 'loading' });
    const result = await gqlRequest('AssetHistory', { assetId });
    if (result.ok && Array.isArray(result.data.assetHistory)) {
      setHistory({ kind: 'ready', entries: result.data.assetHistory });
      return;
    }
    setHistory({ kind: 'error' });
  }

  /** Re-read after a command: values AND the concurrency token moved. */
  async function reloadAfter(ackReplayed: boolean, said: string): Promise<void> {
    setNotice(ackReplayed ? 'Already applied — this was a retry of an earlier change.' : said);
    // A stale history view after a command would show a record missing the
    // change the user just made; drop it back to on-demand.
    setHistory({ kind: 'idle' });
    await load();
  }

  async function submitValuation(event: FormEvent, expectedVersion: string): Promise<void> {
    event.preventDefault();
    setValError(null);
    setNotice(null);
    const amount = valAmount.trim();
    if (!/^\d+(\.\d{1,2})?$/.test(amount)) {
      setValAmountError('Enter a plain amount like 12500 or 12500.50.');
      return;
    }
    setValAmountError(null);
    if (valAsOf.trim().length === 0) {
      setValError('Add the date this value is as of.');
      return;
    }
    const payload = {
      assetId,
      expectedVersion,
      estValue: amount,
      valuationAsOf: valAsOf.trim(),
      valuationSource: valSource,
    };
    valId.current = commandEventId(valId.current, JSON.stringify(payload));
    setValBusy(true);
    const result = await gqlRequest('RecordValuation', {
      ...payload,
      clientEventId: valId.current.id,
    });
    setValBusy(false);
    if (!result.ok) {
      setValError(messageFor(result.code));
      return;
    }
    valId.current = null;
    setValAmount('');
    setValAsOf('');
    await reloadAfter(result.data.recordValuation.replayed, 'Value recorded.');
  }

  function startEditing(asset: AssetDetailInfo): void {
    setEditing(true);
    setEditError(null);
    setEditTitle(asset.title);
    setEditLocation(asset.location ?? '');
    setEditNotes(asset.notes ?? '');
    setEditInTrust(asset.inTrust);
    setEditFunding(asset.fundingStatus ?? '');
  }

  async function submitEdit(event: FormEvent, asset: AssetDetailInfo): Promise<void> {
    event.preventDefault();
    setEditError(null);
    setNotice(null);
    const title = editTitle.trim();
    if (title.length === 0) {
      setEditError('The asset needs a name.');
      return;
    }
    // ONLY CHANGED FIELDS travel; a text field EDITED TO EMPTY travels as
    // null — the explicit CLEAR the service understands. Untouched fields
    // are absent and stay exactly as they are.
    const location = editLocation.trim();
    const notes = editNotes.trim();
    const changes: {
      title?: string;
      location?: string | null;
      notes?: string | null;
      inTrust?: boolean;
      fundingStatus?: string | null;
    } = {
      ...(title !== asset.title ? { title } : {}),
      ...(location !== (asset.location ?? '')
        ? { location: location.length > 0 ? location : null }
        : {}),
      ...(notes !== (asset.notes ?? '') ? { notes: notes.length > 0 ? notes : null } : {}),
      ...(editInTrust !== asset.inTrust ? { inTrust: editInTrust } : {}),
      ...(editFunding !== (asset.fundingStatus ?? '')
        ? { fundingStatus: editFunding.length > 0 ? editFunding : null }
        : {}),
    };
    if (Object.keys(changes).length === 0) {
      setEditing(false);
      return;
    }
    const payload = { assetId, expectedVersion: asset.version, ...changes };
    editId.current = commandEventId(editId.current, JSON.stringify(payload));
    setEditBusy(true);
    const result = await gqlRequest('UpdateAsset', {
      ...payload,
      clientEventId: editId.current.id,
    });
    setEditBusy(false);
    if (!result.ok) {
      setEditError(messageFor(result.code));
      return;
    }
    editId.current = null;
    setEditing(false);
    await reloadAfter(result.data.updateAsset.replayed, 'Details updated.');
  }

  async function submitOwnership(event: FormEvent, expectedVersion: string): Promise<void> {
    event.preventDefault();
    setOwnError(null);
    setNotice(null);
    const pct = Number(ownPct.trim());
    if (!Number.isFinite(pct) || pct <= 0 || pct > 100) {
      setOwnPctError('Enter a share between 0 and 100, like 50.');
      return;
    }
    setOwnPctError(null);
    const basis = ownCostBasis.trim();
    if (basis.length > 0 && !/^\d+(\.\d{1,2})?$/.test(basis)) {
      setOwnError('Cost basis must be a plain amount like 12500.50, or blank.');
      return;
    }
    const payload = {
      assetId,
      expectedVersion,
      ownershipPct: pct,
      ...(basis.length > 0 ? { costBasis: basis } : {}),
    };
    ownId.current = commandEventId(ownId.current, JSON.stringify(payload));
    setOwnBusy(true);
    const result = await gqlRequest('ChangeOwnership', {
      ...payload,
      clientEventId: ownId.current.id,
    });
    setOwnBusy(false);
    if (!result.ok) {
      setOwnError(messageFor(result.code));
      return;
    }
    ownId.current = null;
    setOwnPct('');
    setOwnCostBasis('');
    await reloadAfter(result.data.changeOwnership.replayed, 'Ownership updated.');
  }

  /**
   * Retires the asset. Returns the StepUpPrompt contract: 'stale' while the
   * peer still answers stepup_required (the prompt polls to its deadline —
   * peers learn of an elevation through a 30s positive session cache, so a
   * single-shot retry would leave the prompt idle after an accepted code),
   * 'applied' once the retirement landed or failed for any other reason.
   *
   * Retirement is step-up gated as of the M19 PR4 review: it is the service's
   * one irreversible verb, and it was its least guarded. The ceremony is the
   * same one the designation surface runs, and the ARGUMENTS travel with the
   * pending state rather than being read back out of the form — the M13
   * review's worse defect was a shared retry running a different action than
   * the one that was refused.
   */
  async function submitRetire(args: {
    expectedVersion: string;
    reason: string;
  }): Promise<'applied' | 'stale'> {
    setRetireError(null);
    setNotice(null);
    const payload = { assetId, expectedVersion: args.expectedVersion, reason: args.reason };
    retireId.current = commandEventId(retireId.current, JSON.stringify(payload));
    setRetireBusy(true);
    const result = await gqlRequest('RetireAsset', {
      ...payload,
      clientEventId: retireId.current.id,
    });
    setRetireBusy(false);
    if (!result.ok) {
      if (result.code === 'STEPUP_REQUIRED') {
        setPendingRetire(args);
        return 'stale';
      }
      setPendingRetire(null);
      setRetireError(messageFor(result.code));
      return 'applied';
    }
    retireId.current = null;
    setPendingRetire(null);
    setRetireArmed(false);
    await reloadAfter(result.data.retireAsset.replayed, 'Asset retired. Its history remains.');
    return 'applied';
  }

  if (state.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Loading the asset…</p>
      </div>
    );
  }

  if (state.kind === 'signedOut') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">Sign in required</h2>
        <p className="mt-2 text-sm text-ink-muted">Sign in to see this asset.</p>
        <div className="mt-4">
          <Link className="btn btn-primary" href="/login">
            Sign in
          </Link>
        </div>
      </div>
    );
  }

  if (state.kind === 'notFound') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">{messageFor('NOT_FOUND')}</p>
        <div className="mt-4">
          <Link className="btn btn-secondary" href="/assets">
            Back to assets
          </Link>
        </div>
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t load this asset. Please try again in a moment.
        </p>
      </div>
    );
  }

  const { asset } = state;
  const retired = asset.status === 'retired';

  return (
    <div className="space-y-4">
      {retired ? (
        <div className="card border-amber-300 p-4" role="status">
          <p className="text-sm">
            <span className="chip chip-warn mr-2">Retired</span>
            This asset was retired{asset.retiredAt ? ` on ${asset.retiredAt.slice(0, 10)}` : ''}.
            Its record and history remain; it can no longer be changed.
          </p>
        </div>
      ) : null}
      <FormStatus tone="success" message={notice} />

      <section aria-labelledby="asset-summary" className="card p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="asset-summary" className="text-lg font-semibold">
              {asset.title}
              {asset.inTrust ? <span className="chip chip-trust ml-2">In trust</span> : null}
            </h2>
            <p className="mt-1 text-sm text-ink-muted">
              {asset.category}
              {asset.ownershipPct !== 100 ? ` · ${formatPct(asset.ownershipPct)}% ownership` : ''}
              {asset.fundingStatus
                ? ` · ${FUNDING_LABELS[asset.fundingStatus] ?? asset.fundingStatus}`
                : ''}
            </p>
          </div>
          <div className="text-right">
            <p className="text-2xl font-semibold tabular-nums">{formatMoney(asset.estValue)}</p>
            {asset.valuationAsOf ? (
              <p className="text-xs text-ink-muted">
                as of {asset.valuationAsOf}
                {asset.valuationSource
                  ? ` · ${SOURCE_LABELS[asset.valuationSource] ?? asset.valuationSource}`
                  : ''}
              </p>
            ) : (
              <p className="text-xs text-ink-muted">No value recorded</p>
            )}
          </div>
        </div>
        <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
          {asset.costBasis !== null ? (
            <div>
              <dt className="text-ink-muted">Cost basis</dt>
              <dd className="tabular-nums">{formatMoney(asset.costBasis)}</dd>
            </div>
          ) : null}
          {asset.location !== null ? (
            <div>
              <dt className="text-ink-muted">Where to find it</dt>
              <dd>{asset.location}</dd>
            </div>
          ) : null}
          {asset.notes !== null ? (
            <div className="sm:col-span-2">
              <dt className="text-ink-muted">Notes</dt>
              <dd>{asset.notes}</dd>
            </div>
          ) : null}
        </dl>
        {!retired && !editing ? (
          <button
            type="button"
            className="btn btn-secondary mt-4"
            onClick={() => {
              startEditing(asset);
            }}
          >
            Edit details
          </button>
        ) : null}
        {/* `!retired` is on the FORM as well as on the button that opens it.
            Both are reachable at once — open Edit details, then retire below,
            and the reload leaves `editing` true against a retired asset — so
            without this the page offers an edit the service answers 404. Never
            offer what the server would refuse (the M12 legal-hold rule). */}
        {editing && !retired ? (
          <form
            className="mt-4 space-y-4 border-t border-line pt-4"
            noValidate
            onSubmit={(event) => {
              void submitEdit(event, asset);
            }}
          >
            <FormField
              id="edit-title"
              label="Name"
              type="text"
              value={editTitle}
              error={null}
              onChange={setEditTitle}
            />
            <FormField
              id="edit-location"
              label="Where to find it"
              type="text"
              hint="Clearing this field removes it from the record."
              value={editLocation}
              error={null}
              onChange={setEditLocation}
            />
            <FormField
              id="edit-notes"
              label="Notes"
              type="text"
              hint="Clearing this field removes it from the record."
              value={editNotes}
              error={null}
              onChange={setEditNotes}
            />
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={editInTrust}
                onChange={(event) => {
                  setEditInTrust(event.target.checked);
                }}
              />
              Titled in a trust
            </label>
            <div>
              <label className="field-label" htmlFor="edit-funding">
                Trust funding status
              </label>
              <select
                id="edit-funding"
                className="field-input mt-1"
                value={editFunding}
                onChange={(event) => {
                  setEditFunding(event.target.value);
                }}
              >
                <option value="">Not set</option>
                <option value="unfunded">{FUNDING_LABELS['unfunded']}</option>
                <option value="in_progress">{FUNDING_LABELS['in_progress']}</option>
                <option value="funded">{FUNDING_LABELS['funded']}</option>
                <option value="na">{FUNDING_LABELS['na']}</option>
              </select>
            </div>
            <FormStatus tone="error" message={editError} />
            <div className="flex gap-3">
              <button type="submit" className="btn btn-primary" disabled={editBusy}>
                {editBusy ? 'Saving…' : 'Save changes'}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setEditing(false);
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        ) : null}
      </section>

      <AssetBeneficiaries
        assetId={assetId}
        version={asset.version}
        retired={retired}
        onVersionBumped={(newVersion) => {
          // A designation is a ledger event: it advances the asset's version,
          // and this panel's own If-Match must follow WITHOUT re-reading the
          // detail (a re-read would spend four audited decrypts on a number).
          setState((current) =>
            current.kind === 'ready'
              ? { kind: 'ready', asset: { ...current.asset, version: newVersion } }
              : current,
          );
          // …and the loaded history is now missing the event that bump refers
          // to. `reloadAfter` drops it to idle for this panel's own commands
          // for exactly this reason, and the designation path bypassed it —
          // so an open ledger view sat one event short of the truth while the
          // version beside it said otherwise. Idle, not re-fetched: history
          // costs ONE audited decrypt PER EVENT and stays on-demand.
          setHistory({ kind: 'idle' });
        }}
      />

      {!retired ? (
        <section aria-labelledby="record-value" className="card p-6">
          <h2 id="record-value" className="text-lg font-semibold">
            Record a value
          </h2>
          <p className="mt-1 text-sm text-ink-muted">
            A value needs a date and a source — that is what makes it auditable later.
          </p>
          <form
            className="mt-4 space-y-4"
            noValidate
            onSubmit={(event) => {
              void submitValuation(event, asset.version);
            }}
          >
            <FormField
              id="val-amount"
              label="Value"
              type="text"
              inputMode="numeric"
              value={valAmount}
              error={valAmountError}
              onChange={setValAmount}
            />
            <div>
              <label className="field-label" htmlFor="val-as-of">
                As of
              </label>
              <input
                id="val-as-of"
                type="date"
                className="field-input mt-1"
                value={valAsOf}
                onChange={(event) => {
                  setValAsOf(event.target.value);
                }}
              />
            </div>
            <div>
              <label className="field-label" htmlFor="val-source">
                Where the value came from
              </label>
              <select
                id="val-source"
                className="field-input mt-1"
                value={valSource}
                onChange={(event) => {
                  setValSource(event.target.value);
                }}
              >
                <option value="owner_estimate">My own estimate</option>
                <option value="appraisal">Appraisal</option>
                <option value="purchase_price">Purchase price</option>
                <option value="market">Market price</option>
              </select>
            </div>
            <FormStatus tone="error" message={valError} />
            <button type="submit" className="btn btn-primary" disabled={valBusy}>
              {valBusy ? 'Recording…' : 'Record value'}
            </button>
          </form>
        </section>
      ) : null}

      {!retired ? (
        <section aria-labelledby="ownership" className="card p-6">
          <h2 id="ownership" className="text-lg font-semibold">
            Ownership
          </h2>
          <p className="mt-1 text-sm text-ink-muted">
            Currently {formatPct(asset.ownershipPct)}%. Net worth counts only your share.
          </p>
          <form
            className="mt-4 space-y-4"
            noValidate
            onSubmit={(event) => {
              void submitOwnership(event, asset.version);
            }}
          >
            <FormField
              id="own-pct"
              label="Your ownership share %"
              type="text"
              inputMode="numeric"
              value={ownPct}
              error={ownPctError}
              onChange={setOwnPct}
            />
            <FormField
              id="own-cost-basis"
              label="Cost basis (optional)"
              type="text"
              inputMode="numeric"
              hint="Leave blank to keep the current cost basis."
              value={ownCostBasis}
              error={null}
              onChange={setOwnCostBasis}
            />
            <FormStatus tone="error" message={ownError} />
            <button type="submit" className="btn btn-primary" disabled={ownBusy}>
              {ownBusy ? 'Updating…' : 'Update ownership'}
            </button>
          </form>
        </section>
      ) : null}

      <section aria-labelledby="asset-history" className="card p-6">
        <h2 id="asset-history" className="text-lg font-semibold">
          History
        </h2>
        <p className="mt-1 text-sm text-ink-muted">
          The permanent ledger of every change. Each entry is decrypted on request and logged to
          your audit trail.
        </p>
        {history.kind === 'idle' ? (
          <button
            type="button"
            className="btn btn-secondary mt-4"
            onClick={() => {
              void loadHistory();
            }}
          >
            Load history
          </button>
        ) : null}
        {history.kind === 'loading' ? (
          <p className="mt-4 text-sm text-ink-muted" role="status">
            Loading history…
          </p>
        ) : null}
        {history.kind === 'error' ? (
          <p className="mt-4 text-sm text-ink-muted" role="status">
            We couldn’t load the history. Please try again in a moment.
          </p>
        ) : null}
        {history.kind === 'ready' ? (
          <ol className="mt-4 space-y-3" aria-label="Asset history">
            {history.entries.map((entry) => (
              <li key={entry.eventId} className="border-b border-line pb-3 last:border-b-0">
                <p className="text-sm font-medium">
                  {EVENT_LABELS[entry.eventType] ?? entry.eventType}
                </p>
                <p className="text-xs text-ink-muted">
                  {entry.occurredAt.slice(0, 10)}
                  {historyDetail(entry.payload) ? ` · ${historyDetail(entry.payload)}` : ''}
                </p>
              </li>
            ))}
          </ol>
        ) : null}
      </section>

      {!retired ? (
        <section aria-labelledby="retire" className="card p-6">
          <h2 id="retire" className="text-lg font-semibold">
            Retire this asset
          </h2>
          <p className="mt-1 text-sm text-ink-muted">
            Record that it left the estate — sold, gifted, or lost. This can’t be undone, and the
            record and its full history stay visible under “Show retired”.
          </p>
          {pendingRetire !== null ? (
            /* The form HIDES while the ceremony is up: two visible Cancels —
               the form's and the prompt's — are the M15 identical-label
               ambiguity for a person and a test alike. */
            <StepUpPrompt
              idPrefix="retire-stepup"
              hint="Retiring an asset records that it left your estate and cannot be undone, so it needs a fresh check. Enter the six-digit code from your authenticator."
              submitLabel="Confirm and retire"
              onElevated={() => submitRetire(pendingRetire)}
              onCancel={() => {
                setPendingRetire(null);
              }}
            />
          ) : !retireArmed ? (
            <button
              type="button"
              className="btn btn-secondary mt-4"
              onClick={() => {
                setRetireArmed(true);
              }}
            >
              Retire…
            </button>
          ) : (
            <div className="mt-4 space-y-4">
              <div>
                <label className="field-label" htmlFor="retire-reason">
                  Reason
                </label>
                <select
                  id="retire-reason"
                  className="field-input mt-1"
                  value={retireReason}
                  onChange={(event) => {
                    setRetireReason(event.target.value);
                  }}
                >
                  {RETIRE_REASONS.map((reason) => (
                    <option key={reason.value} value={reason.value}>
                      {reason.label}
                    </option>
                  ))}
                </select>
              </div>
              <FormStatus tone="error" message={retireError} />
              <div className="flex gap-3">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={retireBusy}
                  onClick={() => {
                    void submitRetire({
                      expectedVersion: asset.version,
                      reason: retireReason,
                    });
                  }}
                >
                  {retireBusy ? 'Retiring…' : 'Confirm retire'}
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => {
                    setRetireArmed(false);
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </section>
      ) : null}
    </div>
  );
}
