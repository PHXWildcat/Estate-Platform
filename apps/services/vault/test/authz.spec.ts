import { ForbiddenException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { VaultAuthz, vaultItemResource, vaultResource } from '../src/authz.service';

const OWNER = 'b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e';
const STRANGER = '00000000-0000-4000-8000-000000000000';
const ITEM = '9f8e7d6c-5b4a-4392-8180-7f6e5d4c3b2a';

describe('VaultAuthz', () => {
  const authz = new VaultAuthz(new PolicyDecisionPoint(loadBundledPolicies()));

  it.each(['read', 'create', 'update', 'delete', 'manage'] as const)(
    'permits the owner to %s their own vault',
    (action) => {
      expect(() => authz.assertCan(OWNER, action, vaultResource(OWNER))).not.toThrow();
    },
  );

  it.each(['read', 'create', 'update', 'delete', 'manage'] as const)(
    'denies a stranger trying to %s',
    (action) => {
      expect(() => authz.assertCan(STRANGER, action, vaultResource(OWNER))).toThrow(
        ForbiddenException,
      );
    },
  );

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
