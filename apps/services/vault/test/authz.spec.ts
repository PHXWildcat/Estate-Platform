import { ForbiddenException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { VAULT_ACTIONS, VaultAuthz, vaultItemResource, vaultResource } from '../src/authz.service';

const OWNER = 'b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e';
const STRANGER = '00000000-0000-4000-8000-000000000000';
const GRANTEE = 'c0ffee00-1111-4222-8333-444444444444';
const ITEM = '9f8e7d6c-5b4a-4392-8180-7f6e5d4c3b2a';

describe('VaultAuthz', () => {
  const authz = new VaultAuthz(new PolicyDecisionPoint(loadBundledPolicies()));

  // DERIVED FROM THE SERVICE'S OWN VOCABULARY, never restated. A hand-written
  // list here is a list that stops growing when the union does not — which is
  // exactly what happened to the three actions M27 PR1b added.
  it('covers every action the service can ask about', () => {
    // ANTI-VACUITY: an empty vocabulary would make both suites below run zero
    // cases and report a clean pass.
    expect(VAULT_ACTIONS.length).toBeGreaterThanOrEqual(9);
  });

  /**
   * THE NINTH ACTION, AND THE FIRST THAT IS NOT THE OWNER'S (M27 PR3b).
   *
   * `vault.cedar`'s own behaviour is proven in `packages/authz`; what these
   * prove is the half that lives HERE — that this service builds a resource
   * the policy can match, and that it cannot build one by accident.
   *
   * WHICH LAYER EACH REFUSAL COMES FROM matters and is stated per test: the
   * service ALSO refuses a non-released policy in `emergency.service.ts`, so a
   * test that only showed "a grantee cannot read" would not say which of the
   * two did the work, and either could rot with the other holding it up.
   */
  it('permits a NAMED grantee to read_by_grantee, at the Cedar layer', () => {
    expect(() =>
      authz.assertCan(GRANTEE, 'read_by_grantee', vaultItemResource(ITEM, OWNER, [GRANTEE])),
    ).not.toThrow();
  });

  it('denies a grantee the item does not name, at the Cedar layer', () => {
    expect(() =>
      authz.assertCan(STRANGER, 'read_by_grantee', vaultItemResource(ITEM, OWNER, [GRANTEE])),
    ).toThrow(ForbiddenException);
  });

  /**
   * THE OMISSION IS THE CONTROL. `vault.cedar` is guarded by `resource has
   * emergencyGrantees`, so a resource built without a grantee set cannot match
   * it at all — which means every owner-side call site in `vault.service.ts`
   * (all of which pass two arguments) produces a resource that is structurally
   * unreadable by a grantee. Passing `[]` instead would have left the guard
   * evaluating an empty set: the same answer today, and one `contains` bug
   * away from a different one.
   */
  it('omits the grantee attribute entirely when there are none', () => {
    expect(vaultItemResource(ITEM, OWNER)).toEqual({
      uid: { type: 'VaultItem', id: ITEM },
      attrs: { owner: { __entity: { type: 'User', id: OWNER } } },
    });
    expect(Object.keys(vaultItemResource(ITEM, OWNER).attrs ?? {})).not.toContain(
      'emergencyGrantees',
    );
    expect(() =>
      authz.assertCan(GRANTEE, 'read_by_grantee', vaultItemResource(ITEM, OWNER, [])),
    ).toThrow(ForbiddenException);
  });

  /**
   * `beneficiary.cedar` permits plain `read` on ANY resource whose
   * `namedBeneficiaries` contains the principal. If this service ever spelled
   * its grantee set that way, every named beneficiary would gain a Zone A read
   * — docs/03 §5.5's exact prohibition — and no test of `vault.cedar` would
   * notice, because the leak would be in the resource, not the policy.
   */
  it('never puts a grantee into the attribute beneficiary.cedar reads', () => {
    const attrs = vaultItemResource(ITEM, OWNER, [GRANTEE]).attrs ?? {};
    expect(attrs).toHaveProperty('emergencyGrantees');
    expect(attrs).not.toHaveProperty('namedBeneficiaries');
    // The consequence, driven rather than asserted about the shape: a grantee
    // named on a vault item gets no plain `read` from anywhere in the bundle.
    expect(() =>
      authz.assertCan(GRANTEE, 'read', vaultItemResource(ITEM, OWNER, [GRANTEE])),
    ).toThrow(ForbiddenException);
  });

  it.each(VAULT_ACTIONS)('permits the owner to %s their own vault', (action) => {
    expect(() => authz.assertCan(OWNER, action, vaultResource(OWNER))).not.toThrow();
  });

  it.each(VAULT_ACTIONS)('denies a stranger trying to %s', (action) => {
    expect(() => authz.assertCan(STRANGER, action, vaultResource(OWNER))).toThrow(
      ForbiddenException,
    );
  });

  it.each(VAULT_ACTIONS)('scopes %s on a single item to that item’s owner', (action) => {
    expect(() => authz.assertCan(OWNER, action, vaultItemResource(ITEM, OWNER))).not.toThrow();
    expect(() => authz.assertCan(STRANGER, action, vaultItemResource(ITEM, OWNER))).toThrow(
      ForbiddenException,
    );
  });

  it('scopes item access to the item owner', () => {
    expect(() => authz.assertCan(OWNER, 'read', vaultItemResource(ITEM, OWNER))).not.toThrow();
    expect(() => authz.assertCan(STRANGER, 'read', vaultItemResource(ITEM, OWNER))).toThrow(
      ForbiddenException,
    );
  });

  it('denies with a generic token that names nothing', () => {
    try {
      authz.assertCan(STRANGER, 'read', vaultItemResource(ITEM, OWNER));
      throw new Error('expected a denial');
    } catch (err) {
      expect(err).toBeInstanceOf(ForbiddenException);
      expect((err as ForbiddenException).getResponse()).toEqual({ error: 'forbidden' });
      expect(JSON.stringify((err as ForbiddenException).getResponse())).not.toContain(OWNER);
      expect(JSON.stringify((err as ForbiddenException).getResponse())).not.toContain(ITEM);
    }
  });

  it('builds resources that carry only ids', () => {
    expect(vaultResource(OWNER)).toEqual({
      uid: { type: 'Vault', id: OWNER },
      attrs: { owner: { __entity: { type: 'User', id: OWNER } } },
    });
    expect(vaultItemResource(ITEM, OWNER)).toEqual({
      uid: { type: 'VaultItem', id: ITEM },
      attrs: { owner: { __entity: { type: 'User', id: OWNER } } },
    });
  });

  it('denies by default when a resource carries no owner', () => {
    expect(() => authz.assertCan(OWNER, 'read', { uid: { type: 'Vault', id: OWNER } })).toThrow(
      ForbiddenException,
    );
  });
});
