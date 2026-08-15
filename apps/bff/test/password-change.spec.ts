import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { bffError } from '../src/identity-client';

const COOKIE = 'estate_access=the-access-token';

const CHANGE_MUTATION =
  'mutation ChangePassword($currentPassword: String!, $newPassword: String!) { ' +
  'changePassword(currentPassword: $currentPassword, newPassword: $newPassword) { ok } }';

const VARS = { currentPassword: 'old-passphrase', newPassword: 'a-much-longer-passphrase' };

/**
 * The M20 PR1 password change at the EDGE.
 *
 * The client spec pins the wire to identity; what belongs here is what only the
 * edge can get wrong: that both halves arrive in the right fields on the
 * caller's own bearer, that no value is re-validated or rewritten on the way
 * through, and that the four refusals whose remedies differ stay four codes.
 */
describe('password change at the edge', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards both halves on the caller’s own bearer', async () => {
    const res = await gql(app, { query: CHANGE_MUTATION, variables: VARS }, { cookie: COOKIE });

    expect(gqlBody(res)).toEqual({ data: { changePassword: { ok: true } } });
    // The BFF holds no credential of its own: whatever authority this call had
    // is the session the browser presented.
    expect(identity.changePasswordCalls).toEqual([
      {
        accessToken: 'the-access-token',
        currentPassword: 'old-passphrase',
        newPassword: 'a-much-longer-passphrase',
      },
    ]);
  });

  it('requires a session', async () => {
    const res = await gql(app, { query: CHANGE_MUTATION, variables: VARS });

    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(identity.changePasswordCalls).toEqual([]);
  });

  it('does NOT re-validate the new password — identity’s schema is the gate', async () => {
    // A second copy of a validation rule at the edge is a copy free to drift
    // from the one that decides (the M12 upload-client rule). A three-character
    // password must reach identity and be refused THERE, not be refused here
    // by a rule nobody is maintaining.
    const res = await gql(
      app,
      { query: CHANGE_MUTATION, variables: { currentPassword: 'old', newPassword: 'shrt' } },
      { cookie: COOKIE },
    );

    expect(gqlBody(res)).toEqual({ data: { changePassword: { ok: true } } });
    expect(identity.changePasswordCalls[0]?.newPassword).toBe('shrt');
  });

  it.each([
    ['INVALID_CREDENTIALS', 'the current password was wrong'],
    ['STEPUP_REQUIRED', 'a fresh factor is needed'],
    ['TOO_MANY_ATTEMPTS', 'M17’s bound fired'],
    ['INVALID_REQUEST', 'the new password was refused by identity'],
  ] as const)('surfaces %s (%s) as its own code', async (code, _why) => {
    // Four different remedies — re-check the password, find your authenticator,
    // wait, choose a longer password. Collapsing any pair would send someone to
    // do the wrong thing; TOO_MANY_ATTEMPTS in particular is a control firing,
    // and the M9 rule is that a control firing must not read as an outage.
    identity.changePasswordError = bffError(code);

    const res = await gql(app, { query: CHANGE_MUTATION, variables: VARS }, { cookie: COOKIE });

    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe(code);
  });
});
