'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import { useRouter } from 'next/navigation';
import { gqlRequest, type ContactDetailInfo, type ContactSummaryInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { professionalLabel, PROFESSIONAL_KINDS } from '../lib/people';
import { FormStatus } from './FormStatus';
import { RoleControls } from './RoleControls';

/**
 * One person: their details, their role in the estate, and what that role reads.
 *
 * THIS PAGE IS WHERE THE DECRYPTS HAPPEN, and that is the whole reason it exists
 * separately from the list. Reading this panel decrypts name, email, phone,
 * address and notes under the owner's DEK, one audited
 * `crypto.field.decrypted` each. The list deliberately spends one; opening a
 * person spends five, once, because somebody asked for that person. There is no
 * prefetch and no cache: a repeat read is a repeat event, which is what makes the
 * trail mean anything (M12's rule, docs/03 §4 TB4).
 *
 * A MISSING SUMMARY IS NOT AN EMPTY ONE. The panel needs the list row as well as
 * the detail, because `linked` — whether this person has an account, and so
 * whether any designation can be exercised — lives only on the summary. A BFF
 * that predates that field must read as NO DATA rather than as "no account",
 * which is a claim about someone's estate. Same shape as the version-skew defect
 * M11 and M12 each found by running the real app.
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'missing' }
  | { kind: 'error' }
  | { kind: 'ready'; contact: ContactDetailInfo; summary: ContactSummaryInfo | null };

export interface ContactDetailPanelProps {
  contactId: string;
}

export function ContactDetailPanel({ contactId }: ContactDetailPanelProps): ReactElement {
  const router = useRouter();
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [address, setAddress] = useState('');
  const [relationship, setRelationship] = useState('');
  const [professionalKind, setProfessionalKind] = useState('');
  const [notes, setNotes] = useState('');

  const fill = useCallback((contact: ContactDetailInfo): void => {
    setName(contact.name);
    setEmail(contact.email ?? '');
    setPhone(contact.phone ?? '');
    setAddress(contact.address ?? '');
    setRelationship(contact.relationship ?? '');
    setProfessionalKind(contact.professionalKind ?? '');
    setNotes(contact.notes ?? '');
  }, []);

  const load = useCallback(async (): Promise<void> => {
    const [detail, list] = await Promise.all([
      gqlRequest('Contact', { contactId }),
      gqlRequest('Contacts', {}),
    ]);
    if (!detail.ok) {
      if (detail.code === 'UNAUTHENTICATED') {
        setState({ kind: 'signedOut' });
        return;
      }
      // The uniform not-found: a contact that does not exist and one belonging
      // to somebody else answer identically, so an id cannot be probed.
      setState({ kind: detail.code === 'NOT_FOUND' ? 'missing' : 'error' });
      return;
    }
    fill(detail.data.contact);
    setState({
      kind: 'ready',
      contact: detail.data.contact,
      // A failed list read costs the linked badge, not the page.
      summary: list.ok
        ? (list.data.contacts.find((entry) => entry.id === contactId) ?? null)
        : null,
    });
  }, [contactId, fill]);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    if (name.trim().length === 0) {
      setError('A name is needed.');
      return;
    }
    setBusy(true);
    const result = await gqlRequest('UpdateContact', {
      contactId,
      name: name.trim(),
      // Blank means "not set" — contacts keep replace semantics downstream, and
      // their read returns every field they store, so this round-trips cleanly.
      ...(email.trim().length > 0 ? { email: email.trim() } : {}),
      ...(phone.trim().length > 0 ? { phone: phone.trim() } : {}),
      ...(address.trim().length > 0 ? { address: address.trim() } : {}),
      ...(relationship.trim().length > 0 ? { relationship: relationship.trim() } : {}),
      ...(professionalKind.length > 0 ? { professionalKind } : {}),
      ...(notes.trim().length > 0 ? { notes: notes.trim() } : {}),
    });
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    // The server's stored row, not an echo of the form.
    fill(result.data.updateContact);
    setState((current) =>
      current.kind === 'ready' ? { ...current, contact: result.data.updateContact } : current,
    );
    setEditing(false);
  }

  async function remove(): Promise<void> {
    setError(null);
    setBusy(true);
    const result = await gqlRequest('DeleteContact', { contactId });
    setBusy(false);
    if (!result.ok) {
      // CONTACT_IN_USE is the interesting one: it says a designation stands in
      // the way and what to do about it, rather than failing vaguely.
      setError(messageFor(result.code));
      return;
    }
    router.push('/people');
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
        to continue.
      </p>
    );
  }
  if (state.kind === 'missing') {
    return (
      <div>
        <p className="text-sm text-ink-muted">{messageFor('NOT_FOUND')}</p>
        <Link className="btn btn-secondary mt-4" href="/people">
          Back to people
        </Link>
      </div>
    );
  }
  if (state.kind === 'error') {
    return <FormStatus tone="error" message={messageFor('UNKNOWN')} />;
  }

  const { contact, summary } = state;
  const detail: ReadonlyArray<{ label: string; value: string | null }> = [
    { label: 'Relationship', value: contact.relationship },
    {
      label: 'Professional role',
      value: contact.professionalKind === null ? null : professionalLabel(contact.professionalKind),
    },
    { label: 'Email', value: contact.email },
    { label: 'Phone', value: contact.phone },
    { label: 'Address', value: contact.address },
    { label: 'Notes', value: contact.notes },
  ];

  return (
    <div className="grid gap-6">
      <section aria-labelledby="contact-heading" className="card p-6">
        <div className="flex flex-wrap items-start justify-between gap-3 sm:flex-nowrap">
          <div className="min-w-0">
            <h2 id="contact-heading" className="text-lg font-semibold">
              {contact.name}
            </h2>
            <p className="mt-1 text-[0.8125rem] text-ink-muted">
              These details were decrypted for this page under a key only you hold, and the read is
              recorded on your own activity trail.
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setEditing((open) => !open);
                setError(null);
                if (editing) {
                  fill(contact);
                }
              }}
            >
              {editing ? 'Cancel' : 'Edit'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy}
              onClick={() => {
                void remove();
              }}
            >
              Delete
            </button>
          </div>
        </div>

        {editing ? (
          <form
            className="mt-4"
            noValidate
            onSubmit={(event) => {
              void save(event);
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="field-label" htmlFor="edit-name">
                  Name
                </label>
                <input
                  id="edit-name"
                  className="field-input mt-1"
                  value={name}
                  onChange={(event) => {
                    setName(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="edit-relationship">
                  Relationship
                </label>
                <input
                  id="edit-relationship"
                  className="field-input mt-1"
                  value={relationship}
                  onChange={(event) => {
                    setRelationship(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="edit-email">
                  Email
                </label>
                <input
                  id="edit-email"
                  className="field-input mt-1"
                  type="email"
                  value={email}
                  onChange={(event) => {
                    setEmail(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="edit-phone">
                  Phone
                </label>
                <input
                  id="edit-phone"
                  className="field-input mt-1"
                  value={phone}
                  onChange={(event) => {
                    setPhone(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="edit-address">
                  Address
                </label>
                <input
                  id="edit-address"
                  className="field-input mt-1"
                  value={address}
                  onChange={(event) => {
                    setAddress(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="edit-professional">
                  Professional role
                </label>
                <select
                  id="edit-professional"
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
            <div className="mt-4">
              <label className="field-label" htmlFor="edit-notes">
                Notes
              </label>
              <textarea
                id="edit-notes"
                className="field-input mt-1"
                rows={3}
                value={notes}
                onChange={(event) => {
                  setNotes(event.target.value);
                }}
              />
            </div>
            <div className="mt-3">
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? 'Saving…' : 'Save changes'}
              </button>
            </div>
          </form>
        ) : (
          <dl className="mt-4 grid gap-3 sm:grid-cols-2">
            {detail
              .filter((row) => row.value !== null && row.value.length > 0)
              .map((row) => (
                <div key={row.label}>
                  <dt className="text-[0.75rem] uppercase tracking-wide text-ink-muted">
                    {row.label}
                  </dt>
                  <dd className="mt-0.5 text-sm">{row.value}</dd>
                </div>
              ))}
          </dl>
        )}

        <FormStatus tone="error" message={error} />
      </section>

      {/*
       * THREE VALUES, NOT TWO. `summary` is null when the list read failed or
       * when the row was absent from the response, so `linked` goes down as null
       * — "we do not know" — rather than collapsed to false. Defaulting to false
       * would tell someone their executor has no account, which is a claim about
       * their estate, on the strength of a failed request. Same shape as the
       * version-skew defects M11 and M12 each found by running the real app.
       */}
      <RoleControls
        contactId={contactId}
        contactName={contact.name}
        linked={summary === null ? null : summary.linked}
      />
    </div>
  );
}
