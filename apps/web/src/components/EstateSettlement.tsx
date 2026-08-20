'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import {
  ACCESS_STAGES,
  gqlRequest,
  type AccessStage,
  type AssetInfo,
  type EstateAccessStageInfo,
  type ExecutorCaseInfo,
} from '../graphql/client';
import { messageFor } from '../lib/copy';
import { formatMoney } from '../lib/money';
import { FormStatus } from './FormStatus';
import { estateName } from './SettlingEstatesPanel';

/**
 * SETTLING ONE ESTATE (M23 PR2) — docs/03 §5.1 control 5, staged access, with
 * a surface for the first time since M7 shipped the mechanism.
 *
 * THE LADDER IS THE PRODUCT, not a permissions detail to hide. A verified death
 * case grants an executor NOTHING on its own: it is the right to ask, one rung
 * at a time, and every rung is a human decision an operator makes. So the
 * ladder is rendered whole — including the rungs that are still shut and the
 * one that is next — rather than as a list of things that happen to work. An
 * executor who cannot see the shape of it reads a closed door as a broken page.
 *
 * VAULT IS LAST AND SAYS SO. Zone A is sealed material the server itself cannot
 * read, and it is never released alongside the inventory. The order comes from
 * `ACCESS_STAGES`, which is the same list the service's own ladder walks.
 *
 * NEVER OFFER WHAT THE SERVER WOULD REFUSE. "Request access" appears on exactly
 * one rung: the first with no live request whose predecessors are all approved.
 * Those are the two conditions settlement itself checks (`stage_exists` and
 * `assertPredecessorApproved`), restated here to decide whether to OFFER —
 * never to decide authority, which is re-decided under a row lock on the write.
 *
 * A REVOKED STAGE IS NOT A DENIED ONE. Both can be re-requested and they mean
 * different things: denied is "we looked and said no", revoked is "we opened it
 * and closed it again". Access is a grant, not a fact, and a surface that
 * cached "approved" would keep showing a door that has since been shut.
 */

type Screen =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'missing' }
  | { kind: 'ready'; kase: ExecutorCaseInfo; stages: EstateAccessStageInfo[] };

/** The inventory, or the reason there is none to show. */
type Inventory =
  | { kind: 'locked' }
  | { kind: 'loading' }
  | { kind: 'unavailable' }
  | { kind: 'ready'; assets: AssetInfo[] };

const STAGE_COPY: Record<AccessStage, { title: string; blurb: string }> = {
  INVENTORY: {
    title: 'The estate inventory',
    blurb: 'What the estate holds, and what each item is valued at.',
  },
  DOCUMENTS: {
    title: 'Documents',
    blurb: 'The will and the other documents the estate keeps on file.',
  },
  VAULT: {
    title: 'The sealed vault',
    blurb:
      'Items sealed so that only their owner could open them. Released last, and separately — ' +
      'we cannot read them either.',
  },
};

/**
 * What the ladder currently says about one stage.
 *
 * A stage can have SEVERAL rows over a case's life — denied then re-requested,
 * approved then revoked — so a live row (`requested` or `approved`) wins, and
 * otherwise the most recent decided row is the history worth showing. That is
 * the same precedence `StagesRepo.findLive` uses to decide whether a new
 * request is allowed.
 */
export function stageState(
  stages: readonly EstateAccessStageInfo[],
  stage: AccessStage,
): EstateAccessStageInfo | null {
  const mine = stages.filter((row) => row.stage === stage);
  return (
    mine.find((row) => row.status === 'requested' || row.status === 'approved') ??
    mine.at(-1) ??
    null
  );
}

/**
 * Which stage, if any, may be requested right now.
 *
 * Returns AT MOST ONE. Offering two would let somebody request `vault` while
 * `documents` is merely requested, which settlement refuses — and a button
 * whose only outcome is a refusal is worse than no button.
 */
export function requestableStage(stages: readonly EstateAccessStageInfo[]): AccessStage | null {
  for (const stage of ACCESS_STAGES) {
    const state = stageState(stages, stage);
    if (state?.status === 'approved') continue;
    // The first stage that is not approved is the only candidate: everything
    // above it fails the predecessor check by construction.
    if (state?.status === 'requested') return null;
    return stage;
  }
  return null;
}

function statusLabel(state: EstateAccessStageInfo | null): string {
  switch (state?.status) {
    case 'approved':
      return 'Open';
    case 'requested':
      return 'With our team';
    case 'denied':
      return 'Not approved';
    case 'revoked':
      return 'Closed again';
    default:
      return 'Not requested yet';
  }
}

export function EstateSettlement({ caseId }: { caseId: string }): ReactElement {
  const [screen, setScreen] = useState<Screen>({ kind: 'loading' });
  const [inventory, setInventory] = useState<Inventory>({ kind: 'locked' });
  const [pending, setPending] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const loadInventory = useCallback(async (): Promise<void> => {
    setInventory({ kind: 'loading' });
    const result = await gqlRequest('EstateInventory', { caseId });
    if (result.ok && Array.isArray(result.data.estateInventory)) {
      setInventory({ kind: 'ready', assets: result.data.estateInventory });
      return;
    }
    // A failed read is NOT an empty estate. "This estate holds nothing" is a
    // statement about a dead person's affairs and must never be a guess.
    setInventory({ kind: 'unavailable' });
  }, [caseId]);

  const load = useCallback(async (): Promise<void> => {
    setScreen({ kind: 'loading' });
    const cases = await gqlRequest('ExecutorCases', {});
    if (!cases.ok || !Array.isArray(cases.data.executorCases)) {
      setScreen({
        kind: 'error',
        message: cases.ok ? messageFor('UNKNOWN') : messageFor(cases.code),
      });
      return;
    }
    const kase = cases.data.executorCases.find((row) => row.caseId === caseId);
    if (kase === undefined) {
      // The same answer an id that names nothing gets. This screen is reached
      // by URL, so it is a place somebody can arrive with a stale or borrowed
      // id, and it must not tell them which of the two they have.
      setScreen({ kind: 'missing' });
      return;
    }
    const stages = await gqlRequest('EstateStages', { caseId });
    if (!stages.ok || !Array.isArray(stages.data.estateStages)) {
      setScreen({
        kind: 'error',
        message: stages.ok ? messageFor('UNKNOWN') : messageFor(stages.code),
      });
      return;
    }
    setScreen({ kind: 'ready', kase, stages: stages.data.estateStages });
    if (stageState(stages.data.estateStages, 'INVENTORY')?.status === 'approved') {
      await loadInventory();
    } else {
      // Re-locked rather than left stale: a revoked stage must take the list
      // it opened away with it.
      setInventory({ kind: 'locked' });
    }
  }, [caseId, loadInventory]);

  useEffect(() => {
    void load();
  }, [load]);

  const request = async (stage: AccessStage): Promise<void> => {
    setPending(true);
    setFormError(null);
    const result = await gqlRequest('RequestEstateAccess', { caseId, stage });
    setPending(false);
    if (result.ok && result.data.requestEstateAccess) {
      await load();
      return;
    }
    setFormError(result.ok ? messageFor('UNKNOWN') : messageFor(result.code));
  };

  if (screen.kind === 'loading') {
    return <p className="text-sm text-ink-muted">Loading…</p>;
  }

  if (screen.kind === 'missing') {
    return (
      <section className="card p-6">
        <h2 className="text-lg font-semibold">We couldn’t find that</h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          There’s no estate here for you to settle. If you were expecting one, the case may not have
          been verified yet — we’ll let you know when it has.
        </p>
      </section>
    );
  }

  if (screen.kind === 'error') {
    return (
      <section className="card p-6">
        {/* A refused read is not "there is nothing here" — its own panel. */}
        <h2 className="text-lg font-semibold">We couldn’t load this</h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">{screen.message}</p>
        <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
          Try again
        </button>
      </section>
    );
  }

  const { kase, stages } = screen;
  const next = requestableStage(stages);

  return (
    <div className="grid gap-6">
      <section aria-labelledby="ladder-heading" className="card p-6">
        <h2 id="ladder-heading" className="text-lg font-semibold">
          Access to {estateName(kase)}’s estate
        </h2>
        <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
          Access opens in stages, in this order, and our team reviews each request before it does.
          Nothing opens automatically and nothing opens all at once — it’s what keeps a wrongly
          reported death from becoming a wrongly opened estate.
        </p>

        <ol className="space-y-3">
          {ACCESS_STAGES.map((stage) => {
            const state = stageState(stages, stage);
            return (
              <li
                key={stage}
                className="flex flex-wrap items-start justify-between gap-3 border-t border-line pt-3 first:border-t-0 first:pt-0"
              >
                <span className="max-w-prose">
                  <span className="font-medium">{STAGE_COPY[stage].title}</span>
                  <span className="ml-2 chip">{statusLabel(state)}</span>
                  <span className="mt-0.5 block text-sm text-ink-muted">
                    {STAGE_COPY[stage].blurb}
                  </span>
                </span>
                {next === stage ? (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    disabled={pending}
                    onClick={() => void request(stage)}
                  >
                    {pending ? 'Asking…' : 'Request access'}
                  </button>
                ) : null}
              </li>
            );
          })}
        </ol>

        <FormStatus tone="error" message={formError} />
      </section>

      <section aria-labelledby="inventory-heading" className="card p-6">
        <h2 id="inventory-heading" className="text-lg font-semibold">
          The estate inventory
        </h2>
        {inventory.kind === 'locked' ? (
          <p className="mt-2 max-w-prose text-sm text-ink-muted">
            This opens once the inventory stage above is approved. Nothing here is hidden from you
            permanently — it’s waiting on a review.
          </p>
        ) : null}
        {inventory.kind === 'loading' ? (
          <p className="mt-2 text-sm text-ink-muted">Loading the inventory…</p>
        ) : null}
        {inventory.kind === 'unavailable' ? (
          /* Not "this estate holds nothing": we could not read the list. */
          <p className="mt-2 max-w-prose text-sm text-ink-muted">
            We couldn’t load the inventory just now. Please try again in a moment — this doesn’t
            mean the estate is empty.
          </p>
        ) : null}
        {inventory.kind === 'ready' ? (
          inventory.assets.length === 0 ? (
            <p className="mt-2 max-w-prose text-sm text-ink-muted">
              There’s nothing recorded in this estate’s inventory. That’s a real answer — the owner
              never added anything here.
            </p>
          ) : (
            <ul className="mt-4 space-y-3">
              {inventory.assets.map((asset) => (
                <li
                  key={asset.assetId}
                  className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3 first:border-t-0 first:pt-0"
                >
                  <span className="font-medium">{asset.title}</span>
                  {/* Money is a decimal STRING end to end and formatted, never
                      parsed — `formatMoney` groups digits without touching a
                      float. */}
                  <span className="text-right text-sm font-medium tabular-nums">
                    {formatMoney(asset.estValue)}
                  </span>
                </li>
              ))}
            </ul>
          )
        ) : null}
      </section>
    </div>
  );
}
