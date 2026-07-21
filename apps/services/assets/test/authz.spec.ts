import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { AssetsAuthz, assetResource } from '../src/authz.service';

const OWNER = randomUUID();
const STRANGER = randomUUID();
const BENEFICIARY_USER = randomUUID();
const ASSET = randomUUID();

describe('AssetsAuthz (Cedar PEP, deny by default)', () => {
  const authz = new AssetsAuthz(new PolicyDecisionPoint(loadBundledPolicies()));

  it('permits the owner any action', () => {
    const resource = assetResource(ASSET, OWNER);
    for (const action of ['read', 'create', 'update', 'delete', 'manage'] as const) {
      expect(authz.can(OWNER, action, resource)).toBe(true);
    }
  });

  it('denies a stranger everything', () => {
    const resource = assetResource(ASSET, OWNER);
    for (const action of ['read', 'create', 'update', 'delete', 'manage'] as const) {
      expect(authz.can(STRANGER, action, resource)).toBe(false);
    }
    expect(() => authz.assertCan(STRANGER, 'read', resource)).toThrow(ForbiddenException);
  });

  it('denies beneficiary principals in M3 (namedBeneficiaries is always empty)', () => {
    // Until the contact-link projection lands, the PEP never populates
    // namedBeneficiaries — so even a real beneficiary's user is denied reads.
    const resource = assetResource(ASSET, OWNER);
    expect(authz.can(BENEFICIARY_USER, 'read', resource)).toBe(false);
  });

  it('would permit read (and only read) once namedBeneficiaries is populated', () => {
    // Documents the intended post-follow-up behavior of beneficiary.cedar.
    const resource = assetResource(ASSET, OWNER, [BENEFICIARY_USER]);
    expect(authz.can(BENEFICIARY_USER, 'read', resource)).toBe(true);
    expect(authz.can(BENEFICIARY_USER, 'update', resource)).toBe(false);
    expect(authz.can(BENEFICIARY_USER, 'delete', resource)).toBe(false);
  });

  it('403 body is a generic token', () => {
    try {
      authz.assertCan(STRANGER, 'read', assetResource(ASSET, OWNER));
      fail('expected ForbiddenException');
    } catch (err) {
      expect((err as ForbiddenException).getResponse()).toEqual({ error: 'forbidden' });
    }
  });
});
