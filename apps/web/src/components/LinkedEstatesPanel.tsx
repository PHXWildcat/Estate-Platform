'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import Link from 'next/link';
import { gqlRequest, type LinkedEstateInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { roleLabel } from '../lib/people';

/**
 * THE ESTATES THAT NAME YOU (M22 PR4a) — the mirror of `PeoplePanel`, and the
 * first surface in the product to face that direction.
 *
 * Everything else on this page is owner→contact: the people YOU named. This is
 * contact→owner, and until this panel a person could be named in somebody's
 * estate — as their executor, with a standing capability to open a death case
 * about them — and have no way to see it. Redemption returns nothing, and
 * settlement's reportable-estates list is a set of bare UUIDs.
 *
 * WHAT IT DELIBERATELY DOES NOT OFFER: any control over the LINK. You cannot
 * leave an estate from here, decline a role, or edit anything. That is not an
 * oversight to fill in later — the link is the OWNER's record of their own
 * intent, and a contact who could quietly remove themselves from an estate
 * would be editing someone else's plan, silently, at the moment it matters
 * least to them and most to the owner. If the relationship should end, it ends
 * from the owner's side, where they can see what they are changing.
 *
 * THAT SENTENCE READ "any control at all" UNTIL M22 PR4c, and the narrowing is
 * deliberate rather than a loophole being widened. The reason above was always
 * about editing somebody else's plan; reporting a death edits nothing and
 * grants nothing — it opens a case that locks no account, notifies the owner
 * on every channel, and can be closed by them with one click. This panel is
 * the only place in the product that names these estates, so it is the only
 * honest place to act on one, and the action LEAVES: it is a link to a page
 * with a review step, not a button that files anything from here.
 *
 * A MISSING NAME IS NOT "UNKNOWN". `ownerName` is null when that owner has
 * never saved a profile, and the copy says so in words rather than printing a
 * placeholder — the same rule that keeps a failed read from rendering as an
 * empty one, applied to one field.
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; estates: LinkedEstateInfo[] }
  | { kind: 'error'; message: string };

export function LinkedEstatesPanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('LinkedEstates', {});
    // A missing field is NO DATA (M11): a BFF predating this query answers
    // `{"data":{}}`, and destructuring that into an empty list would tell
    // somebody no estate names them on the word of a server never asked.
    if (result.ok && Array.isArray(result.data.linkedEstates)) {
      setState({ kind: 'ready', estates: result.data.linkedEstates });
      return;
    }
    setState({
      kind: 'error',
      message: result.ok ? messageFor('UNKNOWN') : messageFor(result.code),
    });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section aria-labelledby="linked-estates-heading" className="card p-6">
      <h2 id="linked-estates-heading" className="text-lg font-semibold">
        Estates that name you
      </h2>
      <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
        People who have named you in their plan and linked you to it. Being named records their
        intent — it grants you nothing until their estate is actually being settled. Only they can
        change this.
      </p>

      {state.kind === 'loading' ? <p className="text-sm text-ink-muted">Loading…</p> : null}

      {state.kind === 'error' ? (
        <>
          {/* A failed read is not an empty one — never render this as "nobody". */}
          <p className="text-sm text-ink-muted">{state.message}</p>
          <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
            Try again
          </button>
        </>
      ) : null}

      {state.kind === 'ready' ? (
        state.estates.length === 0 ? (
          <p className="text-sm text-ink-muted">
            Nobody has named you in their plan yet. If someone does, they will give you a code to
            link your account, and their estate will appear here.
          </p>
        ) : (
          <>
            {/*
              ONE POINTER, NOT A BUTTON PER ROW. Filing is a page with a review
              step on it, and a control on each name would put a death report
              one misclick from a list people open for other reasons.
            */}
            <p className="mb-4 text-sm text-ink-muted">
              If one of these people has died,{' '}
              <Link
                href="/people/report"
                className="font-medium text-ink underline underline-offset-4"
              >
                you can tell us
              </Link>
              . We review every report ourselves and contact them first.
            </p>
            <ul className="space-y-3">
              {state.estates.map((estate) => (
                <li
                  key={estate.contactId}
                  className="flex flex-wrap items-baseline justify-between gap-2 border-t border-line pt-3 first:border-t-0 first:pt-0"
                >
                  <span className="font-medium">
                    {estate.ownerName ?? (
                      // The owner exists; their name does not. Say which.
                      <span className="text-ink-muted">
                        Someone who hasn’t added their name yet
                      </span>
                    )}
                  </span>
                  <span className="text-sm text-ink-muted">
                    {estate.roles.length === 0
                      ? 'Linked, with no role yet'
                      : estate.roles.map(roleLabel).join(', ')}
                  </span>
                </li>
              ))}
            </ul>
          </>
        )
      ) : null}
    </section>
  );
}
