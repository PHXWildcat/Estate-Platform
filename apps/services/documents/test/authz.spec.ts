import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { DocumentsAuthz, documentResource } from '../src/authz.service';

const OWNER = randomUUID();
const STRANGER = randomUUID();
const DOC = randomUUID();

describe('DocumentsAuthz (deny-by-default Cedar PEP)', () => {
  const authz = new DocumentsAuthz(new PolicyDecisionPoint(loadBundledPolicies()));
  const resource = documentResource(DOC, OWNER);

  it('permits the owner every document action', () => {
    for (const action of ['read', 'create', 'update', 'delete', 'manage'] as const) {
      expect(authz.can(OWNER, action, resource)).toBe(true);
    }
  });

  it('denies everyone else, with a generic 403', () => {
    for (const action of ['read', 'update', 'delete'] as const) {
      expect(authz.can(STRANGER, action, resource)).toBe(false);
    }
    try {
      authz.assertCan(STRANGER, 'read', resource);
      throw new Error('expected ForbiddenException');
    } catch (err) {
      expect(err).toBeInstanceOf(ForbiddenException);
      expect((err as ForbiddenException).getResponse()).toEqual({ error: 'forbidden' });
    }
  });
});
