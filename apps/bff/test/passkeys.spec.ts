/**
 * The passkey operations at the edge (M17 PR5).
 *
 * The BFF adds no authority and — the design fact under test — VALIDATES
 * NOTHING about the ceremony payloads: attestation semantics belong to
 * identity's library, so what the resolvers must prove is narrower and
 * sharper: the caller's own bearer went out, the payload crossed opaquely,
 * a cookie-less request called nothing, and refusals arrive as codes.
 */
import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { bffError } from '../src/identity-client';

const PASSKEYS = 'query Passkeys { passkeys { id nickname isHardwareKey createdAt lastUsedAt } }';
const REGISTER_OPTIONS = 'mutation WebauthnRegisterOptions { webauthnRegisterOptions }';
const REGISTER =
  'mutation WebauthnRegister($response: JSON!) { webauthnRegister(response: $response) { ok } }';
const STEP_UP =
  'mutation WebauthnStepUp($response: JSON!) { webauthnStepUp(response: $response) { stepupExpiresAt } }';
const REVOKE = 'mutation RevokePasskey($id: ID!) { revokePasskey(id: $id) { ok } }';
const RENAME =
  'mutation RenamePasskey($id: ID!, $nickname: String!) { renamePasskey(id: $id, nickname: $nickname) { ok } }';

const ACCESS_TOKEN = 'the-access-token';
const COOKIE = { cookie: `estate_access=${ACCESS_TOKEN}` };

describe('passkeys at the edge', () => {
  let identity: FakeIdentityClient;
  let app: INestApplication;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('lists on the caller’s own bearer and returns the projection verbatim', async () => {
    identity.passkeysRows = [
      {
        id: 'pk-1',
        nickname: 'MacBook',
        isHardwareKey: false,
        createdAt: '2026-08-01T00:00:00.000Z',
        lastUsedAt: null,
      },
    ];
    const res = await gql(app, { query: PASSKEYS }, COOKIE);
    expect(gqlBody(res).data).toEqual({ passkeys: identity.passkeysRows });
  });

  it('the ceremony payloads cross OPAQUELY in both directions', async () => {
    const optionsRes = await gql(app, { query: REGISTER_OPTIONS }, COOKIE);
    // Whatever identity minted is what the client gets — the edge reshapes
    // nothing (a reshape would be a second declaration of the wire).
    expect(gqlBody(optionsRes).data).toEqual({
      webauthnRegisterOptions: { challenge: 'AQID', rp: { id: 'localhost' } },
    });

    const attestation = {
      id: 'cred',
      rawId: 'cred',
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON: 'a', attestationObject: 'b' },
    };
    const registerSpy = jest.spyOn(identity, 'webauthnRegister');
    const registerRes = await gql(
      app,
      { query: REGISTER, variables: { response: attestation } },
      COOKIE,
    );
    expect(gqlBody(registerRes).data).toEqual({ webauthnRegister: { ok: true } });
    expect(registerSpy).toHaveBeenCalledWith(ACCESS_TOKEN, attestation);
  });

  it('step-up returns the elevation deadline the session now carries', async () => {
    const res = await gql(app, { query: STEP_UP, variables: { response: { id: 'x' } } }, COOKIE);
    expect(gqlBody(res).data).toEqual({
      webauthnStepUp: { stepupExpiresAt: '2026-08-13T12:05:00.000Z' },
    });
  });

  it('a refused ceremony arrives as WEBAUTHN_FAILED, never a masked error', async () => {
    jest.spyOn(identity, 'webauthnRegister').mockRejectedValue(bffError('WEBAUTHN_FAILED'));
    const res = await gql(app, { query: REGISTER, variables: { response: { id: 'x' } } }, COOKIE);
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('WEBAUTHN_FAILED');
  });

  it('revoke and rename forward the caller’s bearer and the path id', async () => {
    const revokeSpy = jest.spyOn(identity, 'revokePasskey');
    const renameSpy = jest.spyOn(identity, 'renamePasskey');
    await gql(app, { query: REVOKE, variables: { id: 'pk-1' } }, COOKIE);
    await gql(app, { query: RENAME, variables: { id: 'pk-1', nickname: 'YubiKey' } }, COOKIE);
    expect(revokeSpy).toHaveBeenCalledWith(ACCESS_TOKEN, 'pk-1');
    expect(renameSpy).toHaveBeenCalledWith(ACCESS_TOKEN, 'pk-1', 'YubiKey');
  });

  it('a cookie-less request calls NOTHING', async () => {
    const spy = jest.spyOn(identity, 'passkeys');
    const res = await gql(app, { query: PASSKEYS }, {});
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    expect(spy).not.toHaveBeenCalled();
  });
});
