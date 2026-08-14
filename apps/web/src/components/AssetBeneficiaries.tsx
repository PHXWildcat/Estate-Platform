'use client';

import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactElement } from 'react';
import {
  gqlRequest,
  type AssetBeneficiariesInfo,
  type ContactSummaryInfo,
} from '../graphql/client';
import { commandEventId, type CommandId } from '../lib/command-id';
import { messageFor } from '../lib/copy';
import { formatPct } from '../lib/percent';
import { StepUpPrompt } from './StepUpPrompt';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';

/**
 * Beneficiary designations on one asset — the M19 PR3 ceremony, and the
 * surface that closes the M10 incoherence where the readiness page reported
 * designation gaps the product gave owners no way to act on.
 *
 * STEP-UP: designating AND removing are both gated downstream (docs/01 §5;
 * removal equally, the profile role-removal precedent — equal, never
 * harder). ONE StepUpPrompt serves both, bound through a discriminated
 * union that CARRIES every argument of the refused action (the M13-review
 * rule: the prompt retries THE ACTION THAT WAS REFUSED, never whatever the
 * form currently holds).
 *
 * WHAT A DESIGNATION IS NOT: it grants no access of any kind, and — the
 * stronger truth, stated on screen — nobody a user names can see the
 * designation, or this asset, today. Beneficiary visibility does not exist
 * yet (`namedBeneficiaries` is structurally empty until the contact-link
 * projection lands), and the copy must not promise otherwise.
 *
 * A DANGLING CONTACT (deleted from /people after being designated) renders
 * by that fact — "no longer in your contacts" — and stays removable; hiding
 * it would make the designation unremovable forever.
 */

type PendingStepUp =
  | { kind: 'designate'; contactId: string; designation: string; sharePct: number }
  | { kind: 'remove'; contactId: string; designation: string }
  | null;

const STEP_UP_HINT: Record<NonNullable<PendingStepUp>['kind'], string> = {
  designate:
    'Naming a beneficiary changes who your estate passes to, so it needs a fresh check. Enter the six-digit code from your authenticator.',
  remove:
    'Removing a beneficiary designation changes who your estate passes to, so it is protected the same way naming one is.',
};

const STEP_UP_LABEL: Record<NonNullable<PendingStepUp>['kind'], string> = {
  designate: 'Confirm and designate',
  remove: 'Confirm and remove',
};

const DESIGNATION_LABELS: Record<string, string> = {
  primary: 'Primary',
  contingent: 'Contingent',
};

type LoadState =
  { kind: 'loading' } | { kind: 'error' } | { kind: 'ready'; data: AssetBeneficiariesInfo };

type PickerState =
  | { kind: 'closed' }
  | { kind: 'loading' }
  | { kind: 'error' }
  | { kind: 'open'; contacts: ContactSummaryInfo[] };

export function AssetBeneficiaries({
  assetId,
  version,
  retired,
  onVersionBumped,
}: {
  assetId: string;
  version: string;
  retired: boolean;
  /** Designations are ledger events: every command advances the asset's
   * version, and the parent's own If-Match must follow without re-reading
   * (a re-read would spend four audited decrypts to learn one number). */
  onVersionBumped: (version: string) => void;
}): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [picker, setPicker] = useState<PickerState>({ kind: 'closed' });
  const [contactId, setContactId] = useState('');
  const [designation, setDesignation] = useState('primary');
  const [sharePct, setSharePct] = useState('');
  const [shareError, setShareError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<PendingStepUp>(null);
  const designateId = useRef<CommandId | null>(null);
  const removeId = useRef<CommandId | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('AssetBeneficiaries', { assetId });
    // A missing field is NO DATA (M11): a BFF predating this query must
    // render as an error, never as "no beneficiaries designated".
    if (result.ok && Array.isArray(result.data.assetBeneficiaries?.beneficiaries)) {
      setState({ kind: 'ready', data: result.data.assetBeneficiaries });
      return;
    }
    setState({ kind: 'error' });
  }, [assetId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function openPicker(): Promise<void> {
    setPicker({ kind: 'loading' });
    const result = await gqlRequest('Contacts', {});
    if (result.ok && Array.isArray(result.data.contacts)) {
      setPicker({ kind: 'open', contacts: result.data.contacts });
      setContactId(result.data.contacts[0]?.id ?? '');
      return;
    }
    setPicker({ kind: 'error' });
  }

  /** Shared success path: reload designations, hand the new version up. */
  async function landed(ackVersion: string, replayed: boolean, said: string): Promise<void> {
    onVersionBumped(ackVersion);
    setNotice(replayed ? 'Already applied — this was a retry of an earlier change.' : said);
    await load();
  }

  /**
   * Runs the designate command. Returns the StepUpPrompt contract: 'stale'
   * while the peer still answers stepup_required (the prompt polls to its
   * deadline), 'applied' once the designation landed.
   */
  async function designate(
    args: NonNullable<Extract<PendingStepUp, { kind: 'designate' }>>,
  ): Promise<'applied' | 'stale'> {
    const payload = {
      assetId,
      expectedVersion: version,
      contactId: args.contactId,
      designation: args.designation,
      sharePct: args.sharePct,
    };
    designateId.current = commandEventId(designateId.current, JSON.stringify(payload));
    setBusy(true);
    const result = await gqlRequest('DesignateBeneficiary', {
      ...payload,
      clientEventId: designateId.current.id,
    });
    setBusy(false);
    if (!result.ok) {
      if (result.code === 'STEPUP_REQUIRED') {
        setPending(args);
        return 'stale';
      }
      setPending(null);
      setFormError(messageFor(result.code));
      return 'applied';
    }
    designateId.current = null;
    setPending(null);
    setFormError(null);
    setPicker({ kind: 'closed' });
    setSharePct('');
    await landed(
      result.data.designateBeneficiary.version,
      result.data.designateBeneficiary.replayed,
      'Beneficiary designated.',
    );
    return 'applied';
  }

  async function remove(
    args: NonNullable<Extract<PendingStepUp, { kind: 'remove' }>>,
  ): Promise<'applied' | 'stale'> {
    const payload = {
      assetId,
      expectedVersion: version,
      contactId: args.contactId,
      designation: args.designation,
    };
    removeId.current = commandEventId(removeId.current, JSON.stringify(payload));
    setBusy(true);
    const result = await gqlRequest('RemoveBeneficiary', {
      ...payload,
      clientEventId: removeId.current.id,
    });
    setBusy(false);
    if (!result.ok) {
      if (result.code === 'STEPUP_REQUIRED') {
        setPending(args);
        return 'stale';
      }
      setPending(null);
      setFormError(messageFor(result.code));
      return 'applied';
    }
    removeId.current = null;
    setPending(null);
    setFormError(null);
    await landed(
      result.data.removeBeneficiary.version,
      result.data.removeBeneficiary.replayed,
      'Designation removed.',
    );
    return 'applied';
  }

  function submitDesignate(event: FormEvent): void {
    event.preventDefault();
    setFormError(null);
    setNotice(null);
    if (contactId.length === 0) {
      setFormError('Choose a person from your contacts.');
      return;
    }
    const pct = Number(sharePct.trim());
    if (!Number.isFinite(pct) || pct <= 0 || pct > 100) {
      setShareError('Enter a share between 0 and 100, like 50.');
      return;
    }
    setShareError(null);
    void designate({ kind: 'designate', contactId, designation, sharePct: pct });
  }

  if (state.kind === 'loading') {
    return (
      <section className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Loading beneficiaries…</p>
      </section>
    );
  }

  if (state.kind === 'error') {
    return (
      <section className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t load the beneficiary designations. Please try again in a moment.
        </p>
      </section>
    );
  }

  const { data } = state;

  return (
    <section aria-labelledby="beneficiaries-heading" className="card p-6">
      <h2 id="beneficiaries-heading" className="text-lg font-semibold">
        Beneficiaries
      </h2>
      <p className="mt-1 text-sm text-ink-muted">
        A designation is not access: naming someone here gives them no ability to see or change
        anything. No one you name can see this designation — or this asset — today; beneficiary
        visibility is not built yet.
      </p>

      <FormStatus tone="success" message={notice} />

      {data.beneficiaries.length === 0 ? (
        <p className="mt-4 text-sm text-ink-muted">No beneficiaries designated on this asset.</p>
      ) : (
        <ul className="mt-4" aria-label="Beneficiary designations">
          {data.beneficiaries.map((beneficiary) => (
            <li
              key={`${beneficiary.contactId}:${beneficiary.designation}`}
              className="flex items-center justify-between gap-4 border-b border-line py-3 last:border-b-0"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">
                  {beneficiary.name ?? 'No longer in your contacts'}
                  {beneficiary.name === null ? (
                    <span className="chip chip-warn ml-2">Contact removed</span>
                  ) : null}
                </p>
                <p className="text-xs text-ink-muted">
                  {DESIGNATION_LABELS[beneficiary.designation] ?? beneficiary.designation} ·{' '}
                  {formatPct(beneficiary.sharePct)}%
                </p>
              </div>
              {!retired ? (
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={busy || pending !== null}
                  onClick={() => {
                    setNotice(null);
                    setFormError(null);
                    void remove({
                      kind: 'remove',
                      contactId: beneficiary.contactId,
                      designation: beneficiary.designation,
                    });
                  }}
                >
                  Remove
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}

      {data.totals.length > 0 ? (
        <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
          {data.totals.map((total) => (
            <div key={total.designation}>
              <dt className="text-ink-muted">
                {DESIGNATION_LABELS[total.designation] ?? total.designation} shares
              </dt>
              <dd>
                {formatPct(total.sharePct)}% designated
                {total.designationComplete
                  ? ' — complete'
                  : ` (${formatPct(100 - total.sharePct)}% unassigned)`}
              </dd>
            </div>
          ))}
        </dl>
      ) : null}

      {!retired && picker.kind === 'closed' ? (
        <button
          type="button"
          className="btn btn-secondary mt-4"
          disabled={busy || pending !== null}
          onClick={() => {
            setNotice(null);
            void openPicker();
          }}
        >
          Designate a beneficiary
        </button>
      ) : null}
      {picker.kind === 'loading' ? (
        <p className="mt-4 text-sm text-ink-muted" role="status">
          Loading your contacts…
        </p>
      ) : null}
      {picker.kind === 'error' ? (
        <p className="mt-4 text-sm text-ink-muted" role="status">
          We couldn’t load your contacts. Please try again in a moment.
        </p>
      ) : null}
      {/* The form HIDES while the consent ceremony is up: the prompt carries
          the refused action's own arguments, and two visible Cancels — the
          form's and the ceremony's — would be the M15 identical-label
          ambiguity for a person and a test alike. */}
      {/* `!retired` again, for the same reason it is on the opening button: an
          open picker survives the parent's retirement (both controls are
          reachable at once), and a designation on a retired asset is refused.
          Never offer what the server would refuse. */}
      {picker.kind === 'open' && pending === null && !retired ? (
        picker.contacts.length === 0 ? (
          <p className="mt-4 text-sm text-ink-muted">
            You have no contacts yet. Add the person under People first — a designation names one of
            your own contacts.
          </p>
        ) : (
          <form
            className="mt-4 space-y-4 border-t border-line pt-4"
            noValidate
            onSubmit={submitDesignate}
          >
            <div>
              <label className="field-label" htmlFor="beneficiary-contact">
                Who
              </label>
              <select
                id="beneficiary-contact"
                className="field-input mt-1"
                value={contactId}
                onChange={(event) => {
                  setContactId(event.target.value);
                }}
              >
                {picker.contacts.map((contact) => (
                  <option key={contact.id} value={contact.id}>
                    {contact.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="field-label" htmlFor="beneficiary-designation">
                Designation
              </label>
              <select
                id="beneficiary-designation"
                className="field-input mt-1"
                value={designation}
                onChange={(event) => {
                  setDesignation(event.target.value);
                }}
              >
                <option value="primary">Primary</option>
                <option value="contingent">Contingent</option>
              </select>
            </div>
            <FormField
              id="beneficiary-share"
              label="Share %"
              type="text"
              inputMode="numeric"
              hint="Shares for one designation class can total at most 100%."
              value={sharePct}
              error={shareError}
              onChange={setSharePct}
            />
            <div className="flex gap-3">
              <button type="submit" className="btn btn-primary" disabled={busy || pending !== null}>
                {busy ? 'Designating…' : 'Designate'}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setPicker({ kind: 'closed' });
                  setShareError(null);
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        )
      ) : null}

      <FormStatus tone="error" message={formError} />

      {pending !== null ? (
        <StepUpPrompt
          idPrefix="beneficiary-stepup"
          hint={STEP_UP_HINT[pending.kind]}
          submitLabel={STEP_UP_LABEL[pending.kind]}
          onElevated={() => {
            // Retry THE ACTION THAT WAS REFUSED, from the union's own
            // arguments — never from the form's current state.
            if (pending.kind === 'designate') {
              return designate(pending);
            }
            return remove(pending);
          }}
          onCancel={() => {
            setPending(null);
          }}
        />
      ) : null}
    </section>
  );
}
