import type { INestApplication } from '@nestjs/common';
import { ACCESS_COOKIE } from '../src/cookies';
import { bffError } from '../src/identity-client';
import {
  CONTACT_DETAIL,
  CONTACT_SUMMARY,
  FakeProfileClient,
  PROFILE,
  ROLE_ASSIGNMENT,
  TOKENS,
  gql,
  gqlBody,
  makeApp,
} from './helpers';

/**
 * The people resolvers (M13 PR2). Same trust model as the peer downstreams — the
 * caller's own bearer goes downstream and nothing else — so what is worth
 * asserting here is the handful of decisions this layer actually makes:
 *
 *  - the profile save's THREE-WAY merge (absent ≠ null), which is the edge half
 *    of the defect PR1 fixed in the service;
 *  - that no query can produce contact PII the caller did not ask for;
 *  - that there is no way to write an SSN from here at all;
 *  - and that refusals with different remedies stay apart.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;

const PROFILE_QUERY =
  'query Profile { profile { userId legalName dob ssnLast4 address phone occupation maritalStatus stateOfResidence } }';
const CONTACTS_QUERY =
  'query Contacts { contacts { id name relationship professionalKind hasEmail hasPhone hasAddress hasNotes linked } }';
const CONTACT_QUERY =
  'query Contact($contactId: ID!) { contact(contactId: $contactId) { id name email phone address relationship professionalKind notes } }';
const ROLES_QUERY =
  'query RoleAssignments { roleAssignments { id contactId role scopeType scopeId effectiveCondition startsAt endsAt } }';
const SAVE_PROFILE =
  'mutation SaveProfile($legalName: String!, $dob: String, $address: String, $phone: String, $occupation: String, $maritalStatus: String, $stateOfResidence: String) { saveProfile(legalName: $legalName, dob: $dob, address: $address, phone: $phone, occupation: $occupation, maritalStatus: $maritalStatus, stateOfResidence: $stateOfResidence) { userId ssnLast4 stateOfResidence } }';
const SAVE_STATE_ONLY =
  'mutation SaveState($legalName: String!, $stateOfResidence: String) { saveProfile(legalName: $legalName, stateOfResidence: $stateOfResidence) { userId } }';
const DELETE_CONTACT =
  'mutation DeleteContact($contactId: ID!) { deleteContact(contactId: $contactId) { id name } }';
const GRANT_ROLE =
  'mutation GrantRole($contactId: ID!, $role: String!, $scopeType: String!, $effectiveCondition: String) { grantRole(contactId: $contactId, role: $role, scopeType: $scopeType, effectiveCondition: $effectiveCondition) { id role effectiveCondition } }';
const REVOKE_PERMISSION =
  'mutation RevokeRolePermission($roleAssignmentId: ID!, $grantId: ID!) { revokeRolePermission(roleAssignmentId: $roleAssignmentId, grantId: $grantId) { id resource action } }';

describe('people resolvers', () => {
  let app: INestApplication;
  let profile: FakeProfileClient;

  beforeEach(async () => {
    profile = new FakeProfileClient();
    app = await makeApp({ profile });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards the caller’s own bearer to every read', async () => {
    await gql(app, { query: PROFILE_QUERY }, { cookie: COOKIE });
    await gql(app, { query: CONTACTS_QUERY }, { cookie: COOKIE });
    await gql(app, { query: ROLES_QUERY }, { cookie: COOKIE });
    expect(profile.profileCalls).toEqual([TOKENS.accessToken]);
    expect(profile.contactsCalls).toEqual([TOKENS.accessToken]);
    expect(profile.roleAssignmentsCalls).toEqual([TOKENS.accessToken]);
  });

  it('returns null for a caller who has never saved a profile', async () => {
    // "Nothing on file" is a real answer, not an outage — the M10 lesson. The
    // household surface invites a first save on null and shows a failure only
    // for a failure.
    profile.profileResult = null;
    const res = await gql(app, { query: PROFILE_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).errors).toBeUndefined();
    expect(gqlBody(res).data?.['profile']).toBeNull();
  });

  describe('the profile save carries three values, not two', () => {
    it('omits what the operation omitted, so a partial save cannot wipe a field', async () => {
      const res = await gql(
        app,
        {
          query: SAVE_STATE_ONLY,
          variables: { legalName: PROFILE.legalName, stateOfResidence: 'AZ' },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeUndefined();
      // Only the two keys the operation supplied. `dob`, `address`, `phone` and
      // `occupation` are ABSENT — not null — so the service leaves them alone.
      // Collapsing absent into null here would re-create the PR1 defect one
      // layer up: every partial save would wipe everything the form did not hold.
      expect(profile.saveProfileCalls).toEqual([
        {
          accessToken: TOKENS.accessToken,
          input: { legalName: PROFILE.legalName, stateOfResidence: 'AZ' },
        },
      ]);
    });

    it('passes an explicit null through as a clear', async () => {
      await gql(
        app,
        {
          query: SAVE_PROFILE,
          variables: {
            legalName: PROFILE.legalName,
            dob: null,
            address: '2 Elm St',
            phone: null,
            occupation: null,
            maritalStatus: null,
            stateOfResidence: null,
          },
        },
        { cookie: COOKIE },
      );
      expect(profile.saveProfileCalls[0]?.input).toEqual({
        legalName: PROFILE.legalName,
        dob: null,
        address: '2 Elm St',
        phone: null,
        occupation: null,
        maritalStatus: null,
        stateOfResidence: null,
      });
    });

    it('renders the SAVED row rather than what was sent', async () => {
      const res = await gql(
        app,
        {
          query: SAVE_STATE_ONLY,
          variables: { legalName: 'Ignored By The Fake', stateOfResidence: 'NY' },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeUndefined();
      // The fake returns PROFILE regardless; the resolver re-reads, so the
      // response is the server's state and not an echo (the M10 consent rule).
      expect(profile.profileCalls).toEqual([TOKENS.accessToken]);
      expect(gqlBody(res).data?.['saveProfile']).toEqual({ userId: PROFILE.userId });
    });
  });

  describe('the SSN has no write path from a browser', () => {
    it('rejects an ssn argument on saveProfile at schema validation', async () => {
      const res = await gql(
        app,
        {
          query:
            'mutation Bad($legalName: String!, $ssn: String) { saveProfile(legalName: $legalName, ssn: $ssn) { userId } }',
          variables: { legalName: 'X', ssn: '123456789' },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.message).toMatch(/Unknown argument "ssn"/);
      expect(profile.saveProfileCalls).toEqual([]);
    });

    it('has no field for the full number on the way out either', async () => {
      const res = await gql(app, { query: 'query Bad { profile { ssn } }' }, { cookie: COOKIE });
      expect(gqlBody(res).errors?.[0]?.message).toMatch(/Cannot query field "ssn"/);
    });
  });

  describe('a list cannot produce contact PII', () => {
    it('serves summaries, and the summary type has no PII fields to ask for', async () => {
      const ok = await gql(app, { query: CONTACTS_QUERY }, { cookie: COOKIE });
      expect(gqlBody(ok).errors).toBeUndefined();
      expect(gqlBody(ok).data?.['contacts']).toEqual([
        {
          id: CONTACT_SUMMARY.id,
          name: CONTACT_SUMMARY.name,
          relationship: CONTACT_SUMMARY.relationship,
          professionalKind: CONTACT_SUMMARY.professionalKind,
          hasEmail: true,
          hasPhone: false,
          hasAddress: false,
          hasNotes: false,
          linked: false,
        },
      ]);

      // Not merely absent from the response — UNASKABLE. Each of these would be
      // an audited decrypt per row downstream (docs/03 §6f).
      for (const field of ['email', 'phone', 'address', 'notes']) {
        const bad = await gql(
          app,
          { query: `query Bad { contacts { ${field} } }` },
          {
            cookie: COOKIE,
          },
        );
        expect(gqlBody(bad).errors?.[0]?.message).toMatch(
          new RegExp(`Cannot query field "${field}" on type "ContactSummary"`),
        );
      }
    });

    it('the detail read is a separate, explicit call', async () => {
      const res = await gql(
        app,
        { query: CONTACT_QUERY, variables: { contactId: CONTACT_SUMMARY.id } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeUndefined();
      expect(gqlBody(res).data?.['contact']).toMatchObject({ email: CONTACT_DETAIL.email });
      expect(profile.contactCalls).toEqual([
        { accessToken: TOKENS.accessToken, contactId: CONTACT_SUMMARY.id },
      ]);
      // Asking for one person never lists the rest.
      expect(profile.contactsCalls).toEqual([]);
    });
  });

  describe('refusals with different remedies stay apart', () => {
    it('CONTACT_IN_USE says the roles must go first', async () => {
      profile.profileError = bffError('CONTACT_IN_USE');
      const res = await gql(
        app,
        { query: DELETE_CONTACT, variables: { contactId: CONTACT_SUMMARY.id } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('CONTACT_IN_USE');
    });

    it('STEPUP_REQUIRED reaches the client so it can elevate and retry', async () => {
      profile.profileError = bffError('STEPUP_REQUIRED');
      const res = await gql(
        app,
        {
          query: GRANT_ROLE,
          variables: {
            contactId: CONTACT_SUMMARY.id,
            role: 'trustee',
            scopeType: 'estate',
            effectiveCondition: 'immediate',
          },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('STEPUP_REQUIRED');
      expect(profile.roleAssignmentsCalls).toEqual([]); // nothing re-read after a refusal
    });

    it('withdrawing a permission returns what remains', async () => {
      profile.permissionsResult = [];
      const res = await gql(
        app,
        {
          query: REVOKE_PERMISSION,
          variables: {
            roleAssignmentId: ROLE_ASSIGNMENT.id,
            grantId: 'g0000000-0000-4000-8000-000000000001',
          },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeUndefined();
      expect(gqlBody(res).data?.['revokeRolePermission']).toEqual([]);
      expect(profile.revokePermissionCalls).toHaveLength(1);
    });
  });

  it('an unauthenticated caller never reaches the service', async () => {
    const res = await gql(app, { query: CONTACTS_QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(profile.contactsCalls).toEqual([]);
  });

  /**
   * Each remaining mutation returns EXACTLY WHAT ITS SURFACE RE-RENDERS, and
   * nothing more — the household and role lists, which the panel shows and which
   * for roles cost no decrypt at all, rather than a bare ok the client would have
   * to guess from. So the assertion for each is: it wrote, then it re-read the
   * one collection the caller needs.
   */
  describe('every mutation writes, then answers with the list its surface shows', () => {
    const cases: ReadonlyArray<{
      name: string;
      query: string;
      variables: Record<string, unknown>;
      field: string;
      wrote: (c: FakeProfileClient) => number;
      reread: (c: FakeProfileClient) => number;
    }> = [
      {
        name: 'addFamilyMember',
        query:
          'mutation AddFamilyMember($relation: String!, $name: String!, $dob: String, $isMinor: Boolean, $notes: String) { addFamilyMember(relation: $relation, name: $name, dob: $dob, isMinor: $isMinor, notes: $notes) { id relation name } }',
        variables: { relation: 'child', name: 'Kid', dob: null, isMinor: true, notes: null },
        field: 'addFamilyMember',
        wrote: (c) => c.createFamilyCalls.length,
        reread: (c) => c.familyCalls.length,
      },
      {
        name: 'updateFamilyMember',
        query:
          'mutation UpdateFamilyMember($id: ID!, $relation: String!, $name: String!) { updateFamilyMember(id: $id, relation: $relation, name: $name) { id name } }',
        variables: { id: 'c0000000-0000-4000-8000-000000000001', relation: 'child', name: 'Kid' },
        field: 'updateFamilyMember',
        wrote: (c) => c.updateFamilyCalls.length,
        reread: (c) => c.familyCalls.length,
      },
      {
        name: 'deleteFamilyMember',
        query: 'mutation DeleteFamilyMember($id: ID!) { deleteFamilyMember(id: $id) { id name } }',
        variables: { id: 'c0000000-0000-4000-8000-000000000001' },
        field: 'deleteFamilyMember',
        wrote: (c) => c.deleteFamilyCalls.length,
        reread: (c) => c.familyCalls.length,
      },
      {
        name: 'addContact',
        query:
          'mutation AddContact($name: String!, $email: String) { addContact(name: $name, email: $email) { id name linked } }',
        variables: { name: 'Alice Attorney', email: 'alice@law.example' },
        field: 'addContact',
        wrote: (c) => c.createContactCalls.length,
        reread: (c) => c.contactsCalls.length,
      },
      {
        name: 'updateContact',
        query:
          'mutation UpdateContact($contactId: ID!, $name: String!) { updateContact(contactId: $contactId, name: $name) { id name email } }',
        variables: { contactId: CONTACT_SUMMARY.id, name: 'Alice A.' },
        field: 'updateContact',
        wrote: (c) => c.updateContactCalls.length,
        // The one that re-reads the RECORD rather than the list: the user is
        // looking at that person's panel.
        reread: (c) => c.contactCalls.length,
      },
      {
        name: 'grantRole',
        query: GRANT_ROLE,
        variables: {
          contactId: CONTACT_SUMMARY.id,
          role: 'executor',
          scopeType: 'estate',
          effectiveCondition: 'on_death_verified',
        },
        field: 'grantRole',
        wrote: (c) => c.grantRoleCalls.length,
        reread: (c) => c.roleAssignmentsCalls.length,
      },
      {
        name: 'revokeRole',
        query:
          'mutation RevokeRole($roleAssignmentId: ID!) { revokeRole(roleAssignmentId: $roleAssignmentId) { id role } }',
        variables: { roleAssignmentId: ROLE_ASSIGNMENT.id },
        field: 'revokeRole',
        wrote: (c) => c.revokeRoleCalls.length,
        reread: (c) => c.roleAssignmentsCalls.length,
      },
      {
        name: 'grantRolePermission',
        query:
          'mutation GrantRolePermission($roleAssignmentId: ID!, $resource: String!, $action: String!) { grantRolePermission(roleAssignmentId: $roleAssignmentId, resource: $resource, action: $action) { id resource } }',
        variables: {
          roleAssignmentId: ROLE_ASSIGNMENT.id,
          resource: 'contact',
          action: 'read',
        },
        field: 'grantRolePermission',
        wrote: (c) => c.grantPermissionCalls.length,
        reread: (c) => c.permissionsCalls.length,
      },
    ];

    it.each(cases)('$name', async ({ query, variables, field, wrote, reread }) => {
      const res = await gql(app, { query, variables }, { cookie: COOKIE });
      expect(gqlBody(res).errors).toBeUndefined();
      expect(gqlBody(res).data?.[field]).toBeDefined();
      expect(wrote(profile)).toBe(1);
      expect(reread(profile)).toBe(1);
    });

    it.each(cases)(
      '$name forwards a refusal instead of an empty list',
      async ({ query, variables }) => {
        profile.profileError = bffError('STEPUP_REQUIRED');
        const res = await gql(app, { query, variables }, { cookie: COOKIE });
        // Never a successful-looking empty collection for a refused write.
        expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('STEPUP_REQUIRED');
      },
    );
  });

  describe('the contact link ceremony (PR3)', () => {
    it('mints a code and forwards the caller’s own bearer', async () => {
      const res = await gql(
        app,
        {
          query:
            'mutation InviteContactLink($contactId: ID!) { inviteContactLink(contactId: $contactId) { code expiresAt } }',
          variables: { contactId: CONTACT_SUMMARY.id },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeUndefined();
      expect(gqlBody(res).data?.['inviteContactLink']).toEqual(profile.inviteLinkResult);
      expect(profile.inviteLinkCalls).toEqual([
        { accessToken: TOKENS.accessToken, contactId: CONTACT_SUMMARY.id },
      ]);
    });

    it('withdraws a code and removes a link', async () => {
      for (const [query, calls] of [
        [
          'mutation RevokeContactLinkInvitation($contactId: ID!) { revokeContactLinkInvitation(contactId: $contactId) { ok } }',
          () => profile.revokeLinkInvitationCalls,
        ],
        [
          'mutation UnlinkContact($contactId: ID!) { unlinkContact(contactId: $contactId) { ok } }',
          () => profile.unlinkCalls,
        ],
      ] as const) {
        const res = await gql(
          app,
          { query, variables: { contactId: CONTACT_SUMMARY.id } },
          { cookie: COOKIE },
        );
        expect(gqlBody(res).errors).toBeUndefined();
        expect(calls()).toHaveLength(1);
      }
    });

    it('redeems by CODE ALONE — the mutation has no id to give it', async () => {
      const res = await gql(
        app,
        {
          query:
            'mutation RedeemContactLink($code: String!) { redeemContactLink(code: $code) { ok } }',
          variables: { code: 'ESL1-ABCD' },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeUndefined();
      expect(profile.redeemLinkCalls).toEqual([
        { accessToken: TOKENS.accessToken, code: 'ESL1-ABCD' },
      ]);

      // Not merely unused: there is no such argument, so no client can name an
      // account here (docs/03 §6b's anti-enumeration property).
      const bad = await gql(
        app,
        {
          query:
            'mutation Bad($code: String!, $ownerUserId: ID) { redeemContactLink(code: $code, ownerUserId: $ownerUserId) { ok } }',
          variables: { code: 'ESL1-ABCD', ownerUserId: PROFILE.userId },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(bad).errors?.[0]?.message).toMatch(/Unknown argument "ownerUserId"/);
    });

    it('forwards STEPUP_REQUIRED on the mint without minting anything', async () => {
      profile.profileError = bffError('STEPUP_REQUIRED');
      const res = await gql(
        app,
        {
          query:
            'mutation InviteContactLink($contactId: ID!) { inviteContactLink(contactId: $contactId) { code } }',
          variables: { contactId: CONTACT_SUMMARY.id },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('STEPUP_REQUIRED');
      expect(gqlBody(res).data?.['inviteContactLink']).toBeUndefined();
    });
  });

  it('never invents a profile row when a save reads back as absent', async () => {
    // A save that reports success and then reads back nothing is a skew, and the
    // one thing it must not do is manufacture a row to return.
    profile.profileResult = null;
    const res = await gql(
      app,
      { query: SAVE_STATE_ONLY, variables: { legalName: 'X', stateOfResidence: 'AZ' } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).data?.['saveProfile']).toBeUndefined();
    expect(gqlBody(res).errors?.[0]?.message).toBeDefined();
  });
});
