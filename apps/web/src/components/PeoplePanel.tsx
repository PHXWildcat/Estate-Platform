'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest, type ContactSummaryInfo, type RoleAssignmentInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { onFileSummary, professionalLabel, roleLabel, PROFESSIONAL_KINDS } from '../lib/people';
import { FormStatus } from './FormStatus';

/**
 * The estate contact list (M13 PR2) — the first consumer of routes the profile
 * service has had since M2.
 *
 * THE LIST DECRYPTS ONE FIELD PER PERSON, AND THAT IS A DELIBERATE CEILING.
 * Contact PII lives under the owner's DEK and every field read is one audited
 * `crypto.field.decrypted` on their own trail, so a list showing email and phone
 * would turn a single page load into five events per row — noise on the very
 * signal docs/03 §4 TB4 calls the single most important insider control. The
 * summaries this panel renders carry a name and flags saying WHAT is on file;
 * the values themselves arrive only when someone opens that one person.
 *
 * ROLES ARE SHOWN HERE BUT NOT GRANTED HERE. A row says who someone is to the
 * estate, because a list of names with no roles is an address book rather than an
 * estate plan — but naming a fiduciary is a step-up-gated act that belongs on
 * that person's own page, next to what it actually means.
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'ready'; contacts: ContactSummaryInfo[]; roles: RoleAssignmentInfo[] };

/**
 * Built as ONE string so it reaches the DOM as a single text node: a sentence
 * split across elements is one a screen reader can announce in pieces.
 */
function summaryLine(contacts: readonly ContactSummaryInfo[], withRoles: number): string {
  if (contacts.length === 0) {
    return 'Nobody on file yet.';
  }
  const people = contacts.length === 1 ? '1 person' : `${contacts.length} people`;
  if (withRoles === 0) {
    return `${people} on file, none holding a role in your estate yet.`;
  }
  return `${people} on file, ${withRoles} holding a role in your estate.`;
}

function ContactRow({
  contact,
  roles,
}: {
  contact: ContactSummaryInfo;
  roles: readonly RoleAssignmentInfo[];
}): ReactElement {
  const theirRoles = roles.filter((role) => role.contactId === contact.id);
  return (
    <li className="border-b border-line py-4 last:border-b-0">
      <div className="flex flex-wrap items-start justify-between gap-3 sm:flex-nowrap">
        <div className="min-w-0 max-w-prose flex-1">
          <Link
            className="text-sm font-medium underline-offset-2 hover:underline"
            href={`/people/${contact.id}`}
          >
            {/* User-authored text, rendered as a child — never as markup. */}
            {contact.name}
          </Link>
          <p className="mt-1 text-[0.8125rem] text-ink-muted">
            {[
              contact.relationship,
              contact.professionalKind === null
                ? null
                : professionalLabel(contact.professionalKind),
              onFileSummary(contact),
            ]
              .filter((part): part is string => part !== null && part.length > 0)
              .join(' · ')}
          </p>
          {theirRoles.length > 0 ? (
            <p className="mt-1.5 flex flex-wrap gap-1.5">
              {theirRoles.map((role) => (
                <span key={role.id} className="chip">
                  {roleLabel(role.role)}
                </span>
              ))}
            </p>
          ) : null}
        </div>
        <div className="shrink-0">
          {/*
           * Whether this person has an account decides whether any designation
           * they hold can ever be exercised — no linked account means no
           * role-holder read, no executor resolution, no death report. Showing
           * it is what stops the page implying a designation does something it
           * cannot (M7: designation alone grants nothing).
           */}
          {contact.linked ? (
            <span className="chip chip-success">Has an account</span>
          ) : (
            <span className="chip">No account yet</span>
          )}
        </div>
      </div>
    </li>
  );
}

export function PeoplePanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState('');
  const [relationship, setRelationship] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [professionalKind, setProfessionalKind] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const [contacts, roles] = await Promise.all([
      gqlRequest('Contacts', {}),
      gqlRequest('RoleAssignments', {}),
    ]);
    if (!contacts.ok || !roles.ok) {
      const code = contacts.ok ? (roles.ok ? 'UNKNOWN' : roles.code) : contacts.code;
      setState({ kind: code === 'UNAUTHENTICATED' ? 'signedOut' : 'error' });
      return;
    }
    setState({
      kind: 'ready',
      contacts: contacts.data.contacts,
      roles: roles.data.roleAssignments,
    });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    if (name.trim().length === 0) {
      setError('A name is needed.');
      return;
    }
    setBusy(true);
    const result = await gqlRequest('AddContact', {
      name: name.trim(),
      // Blank fields are omitted rather than sent empty: the service's schema
      // requires a non-empty value for every optional field it accepts, so an
      // empty string would be a 400 for something the user expressed as "leave
      // this out".
      ...(relationship.trim().length > 0 ? { relationship: relationship.trim() } : {}),
      ...(email.trim().length > 0 ? { email: email.trim() } : {}),
      ...(phone.trim().length > 0 ? { phone: phone.trim() } : {}),
      ...(professionalKind.length > 0 ? { professionalKind } : {}),
    });
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    setName('');
    setRelationship('');
    setEmail('');
    setPhone('');
    setProfessionalKind('');
    setAdding(false);
    // Render the SERVER's list, not a local append — the M10 consent rule.
    setState((current) =>
      current.kind === 'ready' ? { ...current, contacts: result.data.addContact } : current,
    );
  }

  if (state.kind === 'loading') {
    return <p className="text-sm text-ink-muted">Loading…</p>;
  }
  if (state.kind === 'signedOut') {
    return (
      <p className="text-sm text-ink-muted">
        Your session has ended.{' '}
        <Link className="underline" href="/login">
          Sign in
        </Link>{' '}
        to see the people in your estate.
      </p>
    );
  }
  if (state.kind === 'error') {
    return <FormStatus tone="error" message={messageFor('UNKNOWN')} />;
  }

  const withRoles = new Set(
    state.roles
      .filter((role) => state.contacts.some((contact) => contact.id === role.contactId))
      .map((role) => role.contactId),
  ).size;

  return (
    <section aria-labelledby="people-heading" className="card p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="people-heading" className="text-lg font-semibold">
            Estate contacts
          </h2>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            {summaryLine(state.contacts, withRoles)}
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary shrink-0"
          onClick={() => {
            setAdding((open) => !open);
            setError(null);
          }}
        >
          {adding ? 'Cancel' : 'Add a person'}
        </button>
      </div>

      {adding ? (
        <form
          className="mt-4 rounded-[var(--radius-card)] border border-line p-4"
          noValidate
          onSubmit={(event) => {
            void submit(event);
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="field-label" htmlFor="contact-name">
                Name
              </label>
              <input
                id="contact-name"
                className="field-input mt-1"
                value={name}
                onChange={(event) => {
                  setName(event.target.value);
                }}
              />
            </div>
            <div>
              <label className="field-label" htmlFor="contact-relationship">
                Relationship <span className="text-ink-muted">(optional)</span>
              </label>
              <input
                id="contact-relationship"
                className="field-input mt-1"
                placeholder="Daughter, brother, friend…"
                value={relationship}
                onChange={(event) => {
                  setRelationship(event.target.value);
                }}
              />
            </div>
            <div>
              <label className="field-label" htmlFor="contact-email">
                Email <span className="text-ink-muted">(optional)</span>
              </label>
              <input
                id="contact-email"
                className="field-input mt-1"
                type="email"
                value={email}
                onChange={(event) => {
                  setEmail(event.target.value);
                }}
              />
            </div>
            <div>
              <label className="field-label" htmlFor="contact-phone">
                Phone <span className="text-ink-muted">(optional)</span>
              </label>
              <input
                id="contact-phone"
                className="field-input mt-1"
                value={phone}
                onChange={(event) => {
                  setPhone(event.target.value);
                }}
              />
            </div>
            <div>
              <label className="field-label" htmlFor="contact-professional">
                Professional role <span className="text-ink-muted">(optional)</span>
              </label>
              <select
                id="contact-professional"
                className="field-input mt-1"
                value={professionalKind}
                onChange={(event) => {
                  setProfessionalKind(event.target.value);
                }}
              >
                <option value="">Not a professional adviser</option>
                {PROFESSIONAL_KINDS.map((kind) => (
                  <option key={kind} value={kind}>
                    {professionalLabel(kind)}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <p className="field-hint mt-3 max-w-prose">
            Everything except the relationship and professional role is encrypted under a key of
            your own. Adding someone here records no permission — you choose what they can see on
            their page.
          </p>
          <div className="mt-3">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Saving…' : 'Add person'}
            </button>
          </div>
          <FormStatus tone="error" message={error} />
        </form>
      ) : (
        <FormStatus tone="error" message={error} />
      )}

      {state.contacts.length === 0 ? (
        <p className="mt-4 text-sm text-ink-muted">
          Estate contacts are the people your plan names — trustees, executors, beneficiaries,
          guardians, and the professionals who advise you.
        </p>
      ) : (
        <ul className="mt-4">
          {state.contacts.map((contact) => (
            <ContactRow key={contact.id} contact={contact} roles={state.roles} />
          ))}
        </ul>
      )}
    </section>
  );
}
