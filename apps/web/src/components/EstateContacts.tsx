'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import { gqlRequest, type ContactSummaryInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { onFileSummary, professionalLabel, relationLabel } from '../lib/people';

/**
 * THE ESTATE'S PEOPLE (M23 PR4a) — docs/03 §5.4's control, built.
 *
 * The threat model has said since it was written that the executor dashboard
 * "shows verified contact cards for the estate's attorney/CPA", and the reason
 * is §5.4's attack: after a real death, attackers phish executors with
 * "probate portal fee required", possibly with a cloned voice of the family
 * attorney. The defence is not a warning banner — it is that the estate's REAL
 * attorney is already on a screen the executor trusts, named by the person who
 * chose them, so an impostor has something to contradict.
 *
 * SO THE COPY SAYS WHAT THE CARDS ARE FOR. A list of names with no stated
 * purpose is a directory; the same list with one sentence about impostors is a
 * control. A reader who does not know why it is there cannot use it.
 *
 * BEHIND THE DOCUMENTS RUNG, not INVENTORY. Who the decedent named is
 * disclosure about LIVING THIRD PARTIES rather than about the estate's
 * holdings, and it is the estate's documents that name them. Until that rung is
 * approved this panel says so and offers nothing — the refusal is the server's
 * and this screen only reports it.
 *
 * PROFESSIONALS FIRST, and that is the §5.4 ordering rather than an aesthetic
 * one: the attorney and the accountant are the identities an impostor claims.
 *
 * NAMES AND ROLES ONLY. No email, no phone, no address — each is another
 * audited decrypt on a dead person's trail, and recognising an impostor needs
 * to know WHO the attorney is, not how to call them. The panel says what is on
 * file without reading any of it.
 */

type Screen =
  | { kind: 'loading' }
  | { kind: 'locked' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; contacts: ContactSummaryInfo[] };

/** What a card says under the name. Null when there is nothing to add. */
export function contactRole(contact: ContactSummaryInfo): string | null {
  if (contact.professionalKind !== null) {
    return professionalLabel(contact.professionalKind);
  }
  if (contact.relationship !== null) {
    return relationLabel(contact.relationship);
  }
  return null;
}

/**
 * Professionals first — see the docstring. Stable within each group, so the
 * order the service returned (its own, by insertion) survives inside a group
 * rather than being re-sorted into something this screen invented.
 */
export function professionalsFirst(contacts: readonly ContactSummaryInfo[]): ContactSummaryInfo[] {
  return [
    ...contacts.filter((c) => c.professionalKind !== null),
    ...contacts.filter((c) => c.professionalKind === null),
  ];
}

export function EstateContacts({ caseId }: { caseId: string }): ReactElement {
  const [screen, setScreen] = useState<Screen>({ kind: 'loading' });

  const load = useCallback(async (): Promise<void> => {
    setScreen({ kind: 'loading' });
    const result = await gqlRequest('EstateContacts', { caseId });
    // A missing field is NO DATA — `{"data":{}}` from a version-skewed BFF must
    // not destructure into "this estate names nobody".
    if (result.ok && Array.isArray(result.data.estateContacts)) {
      setScreen({ kind: 'ready', contacts: result.data.estateContacts });
      return;
    }
    if (!result.ok && result.code === 'STAGE_NOT_APPROVED') {
      /*
       * THE RUNG IS SHUT, which is a control firing and not an outage — the one
       * substitution this repo's error rules forbid outright. Profile answers a
       * uniform 403 for "not approved" and for "we could not reach settlement"
       * alike, so this screen cannot tell them apart either and must not
       * pretend to: it says what is true of both, which is that access has not
       * opened yet.
       */
      setScreen({ kind: 'locked' });
      return;
    }
    setScreen({
      kind: 'error',
      message: result.ok ? messageFor('UNKNOWN') : messageFor(result.code),
    });
  }, [caseId]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section aria-labelledby="estate-contacts-heading" className="card p-6">
      <h2 id="estate-contacts-heading" className="text-lg font-semibold">
        The estate’s people
      </h2>
      <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
        The people this estate named — their attorney, their accountant, and the family they
        recorded. If someone contacts you claiming to act for this estate and they aren’t on this
        list, treat that as a reason to stop. We will never ask you to pay a fee to release an
        estate, and we will never send you a payment link.
      </p>

      {screen.kind === 'loading' ? <p className="text-sm text-ink-muted">Loading…</p> : null}

      {screen.kind === 'locked' ? (
        <p className="max-w-prose text-sm text-ink-muted">
          This opens once the documents stage above is approved. The people an estate names are
          private to it, so they’re released with the documents that name them — not with the
          inventory.
        </p>
      ) : null}

      {screen.kind === 'error' ? (
        <>
          <p className="max-w-prose text-sm text-ink-muted">{screen.message}</p>
          <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
            Try again
          </button>
        </>
      ) : null}

      {screen.kind === 'ready' && screen.contacts.length === 0 ? (
        <p className="max-w-prose text-sm text-ink-muted">
          This estate doesn’t name anyone. That’s a real answer — nobody was recorded here.
        </p>
      ) : null}

      {screen.kind === 'ready' && screen.contacts.length > 0 ? (
        <ul className="space-y-3">
          {professionalsFirst(screen.contacts).map((contact) => {
            const role = contactRole(contact);
            return (
              <li
                key={contact.id}
                className="border-t border-line pt-3 first:border-t-0 first:pt-0"
              >
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{contact.name}</span>
                  {role !== null ? <span className="chip">{role}</span> : null}
                </span>
                {/* Built from the `has` flags — the list never fetched a value,
                    so this sentence is the whole of what it can say about
                    them. */}
                <span className="mt-0.5 block text-sm text-ink-muted">
                  {onFileSummary(contact)}
                </span>
              </li>
            );
          })}
        </ul>
      ) : null}
    </section>
  );
}
