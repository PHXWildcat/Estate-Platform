import type { INestApplication } from '@nestjs/common';
import { ACCESS_COOKIE } from '../src/cookies';
import { bffError } from '../src/identity-client';
import {
  ASSET,
  CONTACT_SUMMARY,
  FakeAssetsClient,
  FakeProfileClient,
  TOKENS,
  gql,
  gqlBody,
  makeApp,
} from './helpers';

/**
 * The beneficiary-designation resolvers (M19 PR3). Three properties carry the
 * design and each is pinned here:
 *  - names are composed from the CALLER'S OWN contacts, and ONLY when a
 *    designation exists to name (contact names cost one audited decrypt per
 *    row — the M18 budget);
 *  - designate refuses a contactId that is not the caller's own BEFORE
 *    anything reaches the ledger (the BFF is the only layer that sees both
 *    clusters — docs/02 §8 forbids the cross-cluster FK service-side);
 *  - remove deliberately has NO membership check, because a designation
 *    whose contact was deleted must stay removable.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;

/**
 * HAND-COPIES of the web app's beneficiary documents (the assets.spec.ts /
 * helpers.ts hazard): the BFF does not depend on apps/web, so keep these in
 * step with apps/web/src/graphql/operations.ts.
 */
const BENEFICIARIES_QUERY =
  'query AssetBeneficiaries($assetId: ID!) { assetBeneficiaries(assetId: $assetId) { assetId beneficiaries { contactId name designation sharePct } totals { designation sharePct designationComplete } } }';
const DESIGNATE_MUTATION =
  'mutation DesignateBeneficiary($assetId: ID!, $expectedVersion: String!, $contactId: ID!, $designation: String!, $sharePct: Float!, $clientEventId: ID) { designateBeneficiary(assetId: $assetId, expectedVersion: $expectedVersion, contactId: $contactId, designation: $designation, sharePct: $sharePct, clientEventId: $clientEventId) { assetId eventId version replayed } }';
const REMOVE_MUTATION =
  'mutation RemoveBeneficiary($assetId: ID!, $expectedVersion: String!, $contactId: ID!, $designation: String!, $clientEventId: ID) { removeBeneficiary(assetId: $assetId, expectedVersion: $expectedVersion, contactId: $contactId, designation: $designation, clientEventId: $clientEventId) { assetId eventId version replayed } }';

const DANGLING_CONTACT = 'f0000000-0000-4000-8000-00000000dead';

describe('beneficiary resolvers', () => {
  let app: INestApplication;
  let assets: FakeAssetsClient;
  let profile: FakeProfileClient;

  beforeEach(async () => {
    assets = new FakeAssetsClient();
    profile = new FakeProfileClient();
    app = await makeApp({ assets, profile });
  });

  afterEach(async () => {
    await app.close();
  });

  it('composes names from the caller’s own contacts; a dangling contact is NULL', async () => {
    assets.beneficiariesResult = {
      assetId: ASSET.assetId,
      beneficiaries: [
        { contactId: CONTACT_SUMMARY.id, designation: 'primary', sharePct: 60 },
        { contactId: DANGLING_CONTACT, designation: 'primary', sharePct: 40 },
      ],
      totals: [{ designation: 'primary', sharePct: 100, designationComplete: true }],
    };
    const res = await gql(
      app,
      { query: BENEFICIARIES_QUERY, variables: { assetId: ASSET.assetId } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(gqlBody(res).data?.['assetBeneficiaries']).toEqual({
      assetId: ASSET.assetId,
      beneficiaries: [
        {
          contactId: CONTACT_SUMMARY.id,
          name: 'Alice Attorney',
          designation: 'primary',
          sharePct: 60,
        },
        // NULL, never a guess: the contact is no longer on file, and the row
        // must say so while staying removable.
        { contactId: DANGLING_CONTACT, name: null, designation: 'primary', sharePct: 40 },
      ],
      totals: [{ designation: 'primary', sharePct: 100, designationComplete: true }],
    });
    expect(profile.contactsCalls).toEqual([TOKENS.accessToken]);
  });

  it('a ZERO-designation asset never touches contacts (the decrypt budget)', async () => {
    const res = await gql(
      app,
      { query: BENEFICIARIES_QUERY, variables: { assetId: ASSET.assetId } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(gqlBody(res).data?.['assetBeneficiaries']).toEqual({
      assetId: ASSET.assetId,
      beneficiaries: [],
      totals: [],
    });
    // The whole point: contact names cost one audited decrypt per row, so an
    // asset with nothing to name costs NOTHING.
    expect(profile.contactsCalls).toEqual([]);
  });

  it('designate REFUSES a contactId that is not the caller’s own, before the ledger', async () => {
    const res = await gql(
      app,
      {
        query: DESIGNATE_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '3',
          contactId: DANGLING_CONTACT,
          designation: 'primary',
          sharePct: 50,
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('INVALID_REQUEST');
    expect(assets.designateCalls).toEqual([]);
  });

  it('designate forwards the caller’s own contact with version and idempotency key', async () => {
    const res = await gql(
      app,
      {
        query: DESIGNATE_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '3',
          contactId: CONTACT_SUMMARY.id,
          designation: 'contingent',
          sharePct: 25.5,
          clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(assets.designateCalls).toEqual([
      {
        accessToken: TOKENS.accessToken,
        assetId: ASSET.assetId,
        input: {
          contactId: CONTACT_SUMMARY.id,
          designation: 'contingent',
          sharePct: 25.5,
          clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
        },
        expectedVersion: '3',
      },
    ]);
  });

  it('surfaces STEPUP_REQUIRED and SHARE_SUM_EXCEEDED as their own codes', async () => {
    assets.beneficiaryError = bffError('STEPUP_REQUIRED');
    const refused = await gql(
      app,
      {
        query: DESIGNATE_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '3',
          contactId: CONTACT_SUMMARY.id,
          designation: 'primary',
          sharePct: 50,
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(refused).errors?.[0]?.extensions?.code).toBe('STEPUP_REQUIRED');

    assets.beneficiaryError = bffError('SHARE_SUM_EXCEEDED');
    const overAllocated = await gql(
      app,
      {
        query: DESIGNATE_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '3',
          contactId: CONTACT_SUMMARY.id,
          designation: 'primary',
          sharePct: 90,
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(overAllocated).errors?.[0]?.extensions?.code).toBe('SHARE_SUM_EXCEEDED');
  });

  it('remove works for a contact NOT in the caller’s contacts — dangling stays removable', async () => {
    const res = await gql(
      app,
      {
        query: REMOVE_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '4',
          contactId: DANGLING_CONTACT,
          designation: 'primary',
          clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000d',
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(assets.removeBeneficiaryCalls).toEqual([
      {
        accessToken: TOKENS.accessToken,
        assetId: ASSET.assetId,
        contactId: DANGLING_CONTACT,
        designation: 'primary',
        clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000d',
        expectedVersion: '4',
      },
    ]);
    // No membership question was ever asked.
    expect(profile.contactsCalls).toEqual([]);
  });

  it('remove without an idempotency key omits it from the wire', async () => {
    const res = await gql(
      app,
      {
        query: REMOVE_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '4',
          contactId: CONTACT_SUMMARY.id,
          designation: 'contingent',
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(assets.removeBeneficiaryCalls[0]).toMatchObject({
      contactId: CONTACT_SUMMARY.id,
      designation: 'contingent',
      clientEventId: undefined,
    });
  });

  it('refuses without a session cookie, before any downstream call', async () => {
    const res = await gql(app, {
      query: BENEFICIARIES_QUERY,
      variables: { assetId: ASSET.assetId },
    });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(assets.beneficiariesCalls).toEqual([]);
  });
});
