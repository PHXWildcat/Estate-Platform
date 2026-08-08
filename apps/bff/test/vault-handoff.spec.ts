import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { bffError } from '../src/identity-client';

const COOKIE = 'estate_access=the-access-token';

const HANDOFF_MUTATION =
  'mutation StartVaultHandoff { startVaultHandoff { code expiresAt vaultOrigin } }';

/**
 * `startVaultHandoff` (M15).
 *
 * The BFF adds no authority here — identity's StepUpGuard decides, and this
 * resolver forwards the caller's own bearer like every other one. What it
 * CONTRIBUTES is the vault origin, which only the deployment knows.
 *
 * The assertions are mostly about the two things that must not happen: the code
 * reaching anywhere other than the response body, and the BFF handing over an
 * origin when identity refused to mint anything to send there.
 */
describe('startVaultHandoff', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('mints on the caller’s own bearer and returns the vault origin', async () => {
    const res = await gql(app, { query: HANDOFF_MUTATION }, { cookie: COOKIE });

    expect(gqlBody(res)).toEqual({
      data: {
        startVaultHandoff: {
          code: 'handoff-code',
          expiresAt: '2026-08-08T00:01:00.000Z',
          vaultOrigin: 'http://vault.localhost:3010',
        },
      },
    });
    // The CALLER's token, forwarded. The BFF holds no credential for identity
    // and none for the vault origin.
    expect(identity.mintVaultHandoffCalls).toEqual(['the-access-token']);
  });

  it('requires a session, and asks identity nothing without one', async () => {
    const res = await gql(app, { query: HANDOFF_MUTATION });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(identity.mintVaultHandoffCalls).toEqual([]);
  });

  it('surfaces STEPUP_REQUIRED so the UI prompts rather than fails', async () => {
    identity.vaultHandoffError = bffError('STEPUP_REQUIRED');
    const res = await gql(app, { query: HANDOFF_MUTATION }, { cookie: COOKIE });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('STEPUP_REQUIRED');
    expect(gqlBody(res).data?.startVaultHandoff).toBeFalsy();
  });

  it('hands over NO origin when the mint failed', async () => {
    // The origin must never travel without a code. A page that received one
    // alone could render a form it cannot fill and post `code=` to the vault
    // origin — refused there, but a confusing way to arrive.
    identity.vaultHandoffError = bffError('VAULT_UNAVAILABLE');
    const res = await gql(app, { query: HANDOFF_MUTATION }, { cookie: COOKIE });
    expect(gqlBody(res).data?.startVaultHandoff).toBeFalsy();
    expect(JSON.stringify(gqlBody(res))).not.toContain('vault.localhost');
  });

  it('puts the code in the body and in no header', async () => {
    const res = await gql(app, { query: HANDOFF_MUTATION }, { cookie: COOKIE });
    // No Set-Cookie, no Location, nothing. The app origin's only job is to put
    // it in a hidden field and submit a top-level POST.
    expect(JSON.stringify(res.headers)).not.toContain('handoff-code');
  });
});
