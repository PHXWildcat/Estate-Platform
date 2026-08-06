'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest, type FamilyMemberInfo, type ProfileInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { maritalLabel, relationLabel, MARITAL_STATUSES, RELATIONS } from '../lib/people';
import { FormStatus } from './FormStatus';

/**
 * Who you are and who is in your household (M13 PR2).
 *
 * THIS IS THE ANSWER TO TWO FINDINGS THE PRODUCT ALREADY SHOWS. The readiness
 * page emits `state_of_residence_unknown` and `minor_status_unknown` — the
 * platform telling someone it does not know a fact about them, with no way to
 * tell it. State of residence also drives which reviewed template a document
 * comes from, which is why M12's generator has to ask for it by hand.
 *
 * THE SSN IS SHOWN AND NEVER COLLECTED. `ssnLast4` is read-only here and there
 * is no field for the full number anywhere in this app — not on this form, not on
 * the GraphQL mutation, not in the BFF's client. An owner can see WHETHER we hold
 * one (transparency is why docs/02 stores the last four separately at all)
 * without this becoming the one page in the product worth phishing. Nothing
 * shipped reads the full value, so collecting it would be risk for no feature.
 *
 * SAVING IS A MERGE, WHICH IS LOAD-BEARING RATHER THAN CONVENIENT. This form
 * holds six of the profile's fields and the row has more, so it sends only what
 * it holds; the service leaves the rest alone. Under the replace semantics this
 * route shipped with, submitting this form would have wiped the SSN it cannot
 * even display in full (fixed in M13 PR1).
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'ready'; profile: ProfileInfo | null; family: FamilyMemberInfo[] };

export function HouseholdPanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [legalName, setLegalName] = useState('');
  const [dob, setDob] = useState('');
  const [address, setAddress] = useState('');
  const [phone, setPhone] = useState('');
  const [occupation, setOccupation] = useState('');
  const [maritalStatus, setMaritalStatus] = useState('');
  const [stateOfResidence, setStateOfResidence] = useState('');

  const [addingMember, setAddingMember] = useState(false);
  const [relation, setRelation] = useState<string>('child');
  const [memberName, setMemberName] = useState('');
  const [memberDob, setMemberDob] = useState('');
  const [memberIsMinor, setMemberIsMinor] = useState(false);
  const [memberError, setMemberError] = useState<string | null>(null);

  const fill = useCallback((profile: ProfileInfo | null): void => {
    setLegalName(profile?.legalName ?? '');
    setDob(profile?.dob ?? '');
    setAddress(profile?.address ?? '');
    setPhone(profile?.phone ?? '');
    setOccupation(profile?.occupation ?? '');
    setMaritalStatus(profile?.maritalStatus ?? '');
    setStateOfResidence(profile?.stateOfResidence ?? '');
  }, []);

  const load = useCallback(async (): Promise<void> => {
    const [profile, family] = await Promise.all([
      gqlRequest('Profile', {}),
      gqlRequest('FamilyMembers', {}),
    ]);
    if (!profile.ok || !family.ok) {
      const code = profile.ok ? (family.ok ? 'UNKNOWN' : family.code) : profile.code;
      setState({ kind: code === 'UNAUTHENTICATED' ? 'signedOut' : 'error' });
      return;
    }
    // A null profile is a REAL ANSWER — nothing on file — so the panel invites a
    // first save rather than showing a failure (the M10 lesson).
    fill(profile.data.profile);
    setState({ kind: 'ready', profile: profile.data.profile, family: family.data.familyMembers });
  }, [fill]);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    if (legalName.trim().length === 0) {
      setError('Your legal name is needed.');
      return;
    }
    setBusy(true);
    // A blank field is an explicit CLEAR (null), not an omission: the user
    // emptied a box they can see. Fields this form does not show are omitted
    // entirely and the service leaves them alone — which is what protects the
    // SSN this page can never send.
    const result = await gqlRequest('SaveProfile', {
      legalName: legalName.trim(),
      dob: dob.trim().length > 0 ? dob.trim() : null,
      address: address.trim().length > 0 ? address.trim() : null,
      phone: phone.trim().length > 0 ? phone.trim() : null,
      occupation: occupation.trim().length > 0 ? occupation.trim() : null,
      maritalStatus: maritalStatus.length > 0 ? maritalStatus : null,
      stateOfResidence: stateOfResidence.length > 0 ? stateOfResidence : null,
    });
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    fill(result.data.saveProfile);
    setState((current) =>
      current.kind === 'ready' ? { ...current, profile: result.data.saveProfile } : current,
    );
    setEditing(false);
  }

  async function addMember(event: FormEvent): Promise<void> {
    event.preventDefault();
    setMemberError(null);
    if (memberName.trim().length === 0) {
      setMemberError('A name is needed.');
      return;
    }
    const result = await gqlRequest('AddFamilyMember', {
      relation,
      name: memberName.trim(),
      ...(memberDob.trim().length > 0 ? { dob: memberDob.trim() } : {}),
      ...(relation === 'child' ? { isMinor: memberIsMinor } : {}),
    });
    if (!result.ok) {
      setMemberError(messageFor(result.code));
      return;
    }
    setMemberName('');
    setMemberDob('');
    setMemberIsMinor(false);
    setAddingMember(false);
    setState((current) =>
      current.kind === 'ready' ? { ...current, family: result.data.addFamilyMember } : current,
    );
  }

  async function removeMember(id: string): Promise<void> {
    setMemberError(null);
    const result = await gqlRequest('DeleteFamilyMember', { id });
    if (!result.ok) {
      setMemberError(messageFor(result.code));
      return;
    }
    setState((current) =>
      current.kind === 'ready' ? { ...current, family: result.data.deleteFamilyMember } : current,
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
        to continue.
      </p>
    );
  }
  if (state.kind === 'error') {
    return <FormStatus tone="error" message={messageFor('UNKNOWN')} />;
  }

  const { profile, family } = state;
  const rows: ReadonlyArray<{ label: string; value: string | null }> = [
    { label: 'Legal name', value: profile?.legalName ?? null },
    { label: 'Date of birth', value: profile?.dob ?? null },
    { label: 'State of residence', value: profile?.stateOfResidence ?? null },
    {
      label: 'Marital status',
      value: profile?.maritalStatus == null ? null : maritalLabel(profile.maritalStatus),
    },
    { label: 'Address', value: profile?.address ?? null },
    { label: 'Phone', value: profile?.phone ?? null },
    { label: 'Occupation', value: profile?.occupation ?? null },
    {
      label: 'Social Security number',
      value: profile?.ssnLast4 == null ? null : `Ends ${profile.ssnLast4}`,
    },
  ];

  return (
    <div className="grid gap-6">
      <section aria-labelledby="household-heading" className="card p-6">
        <div className="flex flex-wrap items-start justify-between gap-3 sm:flex-nowrap">
          <div className="min-w-0">
            <h2 id="household-heading" className="text-lg font-semibold">
              About you
            </h2>
            <p className="mt-1 max-w-prose text-sm text-ink-muted">
              Your state of residence decides which reviewed template your documents come from, and
              whether you have minor children decides whether a guardian designation belongs in your
              plan.
            </p>
          </div>
          <button
            type="button"
            className="btn btn-secondary shrink-0"
            onClick={() => {
              setEditing((open) => !open);
              setError(null);
              if (editing) {
                fill(profile);
              }
            }}
          >
            {editing ? 'Cancel' : profile === null ? 'Add your details' : 'Edit'}
          </button>
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
                <label className="field-label" htmlFor="profile-legal-name">
                  Legal name
                </label>
                <input
                  id="profile-legal-name"
                  className="field-input mt-1"
                  value={legalName}
                  onChange={(event) => {
                    setLegalName(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="profile-dob">
                  Date of birth
                </label>
                <input
                  id="profile-dob"
                  className="field-input mt-1"
                  type="date"
                  value={dob}
                  onChange={(event) => {
                    setDob(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="profile-state">
                  State of residence
                </label>
                <select
                  id="profile-state"
                  className="field-input mt-1"
                  value={stateOfResidence}
                  onChange={(event) => {
                    setStateOfResidence(event.target.value);
                  }}
                >
                  <option value="">Not set</option>
                  {US_STATES.map((code) => (
                    <option key={code} value={code}>
                      {code}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="field-label" htmlFor="profile-marital">
                  Marital status
                </label>
                <select
                  id="profile-marital"
                  className="field-input mt-1"
                  value={maritalStatus}
                  onChange={(event) => {
                    setMaritalStatus(event.target.value);
                  }}
                >
                  <option value="">Not set</option>
                  {MARITAL_STATUSES.map((status) => (
                    <option key={status} value={status}>
                      {maritalLabel(status)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="field-label" htmlFor="profile-address">
                  Address
                </label>
                <input
                  id="profile-address"
                  className="field-input mt-1"
                  value={address}
                  onChange={(event) => {
                    setAddress(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="profile-phone">
                  Phone
                </label>
                <input
                  id="profile-phone"
                  className="field-input mt-1"
                  value={phone}
                  onChange={(event) => {
                    setPhone(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="profile-occupation">
                  Occupation
                </label>
                <input
                  id="profile-occupation"
                  className="field-input mt-1"
                  value={occupation}
                  onChange={(event) => {
                    setOccupation(event.target.value);
                  }}
                />
              </div>
            </div>
            <p className="field-hint mt-3 max-w-prose">
              Every field except your state of residence is encrypted under a key of your own. We
              never ask for your Social Security number here.
            </p>
            <div className="mt-3">
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? 'Saving…' : 'Save'}
              </button>
            </div>
          </form>
        ) : profile === null ? (
          <p className="mt-4 text-sm text-ink-muted">
            Nothing on file yet. Adding your state of residence is what lets us offer the right
            documents for where you live.
          </p>
        ) : (
          <dl className="mt-4 grid gap-3 sm:grid-cols-2">
            {rows
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

      <section aria-labelledby="family-heading" className="card p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="family-heading" className="text-lg font-semibold">
              Your household
            </h2>
            <p className="mt-1 max-w-prose text-sm text-ink-muted">
              {family.length === 0
                ? 'Nobody recorded yet.'
                : `${family.length} ${family.length === 1 ? 'person' : 'people'} recorded.`}
            </p>
          </div>
          <button
            type="button"
            className="btn btn-primary shrink-0"
            onClick={() => {
              setAddingMember((open) => !open);
              setMemberError(null);
            }}
          >
            {addingMember ? 'Cancel' : 'Add someone'}
          </button>
        </div>

        {addingMember ? (
          <form
            className="mt-4 rounded-[var(--radius-card)] border border-line p-4"
            noValidate
            onSubmit={(event) => {
              void addMember(event);
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="field-label" htmlFor="member-relation">
                  Relation
                </label>
                <select
                  id="member-relation"
                  className="field-input mt-1"
                  value={relation}
                  onChange={(event) => {
                    setRelation(event.target.value);
                  }}
                >
                  {RELATIONS.map((token) => (
                    <option key={token} value={token}>
                      {relationLabel(token)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="field-label" htmlFor="member-name">
                  Name
                </label>
                <input
                  id="member-name"
                  className="field-input mt-1"
                  value={memberName}
                  onChange={(event) => {
                    setMemberName(event.target.value);
                  }}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="member-dob">
                  Date of birth <span className="text-ink-muted">(optional)</span>
                </label>
                <input
                  id="member-dob"
                  className="field-input mt-1"
                  type="date"
                  value={memberDob}
                  onChange={(event) => {
                    setMemberDob(event.target.value);
                  }}
                />
              </div>
              {relation === 'child' ? (
                <div className="flex items-end">
                  <label className="flex items-center gap-2 text-sm" htmlFor="member-minor">
                    <input
                      id="member-minor"
                      type="checkbox"
                      checked={memberIsMinor}
                      onChange={(event) => {
                        setMemberIsMinor(event.target.checked);
                      }}
                    />
                    Still a minor
                  </label>
                </div>
              ) : null}
            </div>
            <div className="mt-3">
              <button type="submit" className="btn btn-primary">
                Add
              </button>
            </div>
          </form>
        ) : null}

        {family.length > 0 ? (
          <ul className="mt-4">
            {family.map((member) => (
              <li
                key={member.id}
                className="flex flex-wrap items-center justify-between gap-3 border-b border-line py-3 last:border-b-0"
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium">{member.name}</p>
                  <p className="mt-0.5 text-[0.8125rem] text-ink-muted">
                    {[
                      relationLabel(member.relation),
                      member.isMinor === true ? 'minor' : null,
                      member.dob,
                    ]
                      .filter((part): part is string => part !== null && part.length > 0)
                      .join(' · ')}
                  </p>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary shrink-0"
                  onClick={() => {
                    void removeMember(member.id);
                  }}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        <FormStatus tone="error" message={memberError} />
      </section>
    </div>
  );
}

/** The 50 states plus DC, matching the template matrix the generator offers. */
const US_STATES: readonly string[] = [
  'AL',
  'AK',
  'AZ',
  'AR',
  'CA',
  'CO',
  'CT',
  'DE',
  'DC',
  'FL',
  'GA',
  'HI',
  'ID',
  'IL',
  'IN',
  'IA',
  'KS',
  'KY',
  'LA',
  'ME',
  'MD',
  'MA',
  'MI',
  'MN',
  'MS',
  'MO',
  'MT',
  'NE',
  'NV',
  'NH',
  'NJ',
  'NM',
  'NY',
  'NC',
  'ND',
  'OH',
  'OK',
  'OR',
  'PA',
  'RI',
  'SC',
  'SD',
  'TN',
  'TX',
  'UT',
  'VT',
  'VA',
  'WA',
  'WV',
  'WI',
  'WY',
];
