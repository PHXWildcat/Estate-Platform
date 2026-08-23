import { ForbiddenException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { VAULT_ACTIONS, VaultAuthz, vaultItemResource, vaultResource } from '../src/authz.service';

const OWNER = 'b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e';
const STRANGER = '00000000-0000-4000-8000-000000000000';
const ITEM = '9f8e7d6c-5b4a-4392-8180-7f6e5d4c3b2a';

describe('VaultAuthz', () => {
  const authz = new VaultAuthz(new PolicyDecisionPoint(loadBundledPolicies()));

  // DERIVED FROM THE SERVICE'S OWN VOCABULARY, never restated. A hand-written
  // list here is a list that stops growing when the union does not — which is
  // exactly what happened to the three actions M27 PR1b added.
  it('covers every action the service can ask about', () => {
    // ANTI-VACUITY: an empty vocabulary would make both suites below run zero
    // cases and report a clean pass.
    expect(VAULT_ACTIONS.length).toBeGreaterThanOrEqual(8);
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
