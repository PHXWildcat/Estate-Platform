import { ForbiddenException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { coreResource, ProfileAuthz } from '../src/authz.service';

const OWNER = 'a1111111-1111-4111-8111-111111111111';
const GRANTEE = 'b2222222-2222-4222-8222-222222222222';
const STRANGER = 'c3333333-3333-4333-8333-333333333333';
const CONTACT = 'd4444444-4444-4444-8444-444444444444';

const authz = new ProfileAuthz(new PolicyDecisionPoint(loadBundledPolicies()));

describe('ProfileAuthz PEP (deny by default)', () => {
  it('allows the owner to read their own resource (owner.cedar)', () => {
    expect(() =>
      authz.assertCan(OWNER, 'read', coreResource('Contact', CONTACT, OWNER)),
    ).not.toThrow();
  });

  it('allows the owner every write action', () => {
    for (const action of ['create', 'update', 'delete', 'manage'] as const) {
      expect(() =>
        authz.assertCan(OWNER, action, coreResource('Contact', CONTACT, OWNER)),
      ).not.toThrow();
    }
  });

  it('denies a non-owner with no grant (throws generic forbidden)', () => {
    expect(() =>
      authz.assertCan(STRANGER, 'read', coreResource('Contact', CONTACT, OWNER)),
    ).toThrow(ForbiddenException);
    // The thrown body is a stable token, never PII or the principal id.
    try {
      authz.assertCan(STRANGER, 'read', coreResource('Contact', CONTACT, OWNER));
    } catch (err) {
      expect((err as ForbiddenException).getResponse()).toEqual({ error: 'forbidden' });
    }
  });

  it('allows a grant-holder to READ a resource that names them (profile.cedar)', () => {
    expect(() =>
      authz.assertCan(GRANTEE, 'read', coreResource('Contact', CONTACT, OWNER, [GRANTEE])),
    ).not.toThrow();
    expect(authz.can(GRANTEE, 'read', coreResource('Contact', CONTACT, OWNER, [GRANTEE]))).toBe(
      true,
    );
  });

  it('denies a grant-holder any WRITE (grants are read-only)', () => {
    for (const action of ['update', 'delete', 'manage'] as const) {
      expect(() =>
        authz.assertCan(GRANTEE, action, coreResource('Contact', CONTACT, OWNER, [GRANTEE])),
      ).toThrow(ForbiddenException);
    }
  });

  it('denies a grant-holder reading a resource that does NOT name them (§5.5 boundary)', () => {
    // Grantee holds a grant on some other contact, but this resource names only STRANGER.
    expect(authz.can(GRANTEE, 'read', coreResource('Contact', CONTACT, OWNER, [STRANGER]))).toBe(
      false,
    );
  });

  it('denies by default when the grantee set is empty', () => {
    expect(authz.can(GRANTEE, 'read', coreResource('Contact', CONTACT, OWNER, []))).toBe(false);
  });
});
