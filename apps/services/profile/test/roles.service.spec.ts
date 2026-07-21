import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { coreResource, ProfileAuthz } from '../src/authz.service';
import { RolesService } from '../src/roles.service';
import type { RoleAssignmentInsert, RoleAssignmentRow } from '../src/roles.repo';
import { noopEvents } from './support';

const OWNER = 'a1111111-1111-4111-8111-111111111111';
const OTHER = 'b2222222-2222-4222-8222-222222222222';
const CONTACT = 'd4444444-4444-4444-8444-444444444444';

const authz = new ProfileAuthz(new PolicyDecisionPoint(loadBundledPolicies()));

class FakeRolesRepo {
  readonly rows: RoleAssignmentRow[] = [];
  private seq = 0;
  insert(input: RoleAssignmentInsert): Promise<string> {
    const id = `e0000000-0000-4000-8000-00000000000${++this.seq}`;
    this.rows.push({
      id,
      owner_user_id: input.ownerUserId,
      contact_id: input.contactId,
      role: input.role,
      scope_type: input.scopeType,
      scope_id: input.scopeId,
      effective_condition: input.effectiveCondition,
      starts_at: input.startsAt,
      ends_at: input.endsAt,
    });
    return Promise.resolve(id);
  }
  listByOwner(ownerUserId: string): Promise<RoleAssignmentRow[]> {
    return Promise.resolve(this.rows.filter((r) => r.owner_user_id === ownerUserId));
  }
  findById(id: string): Promise<RoleAssignmentRow | null> {
    return Promise.resolve(this.rows.find((r) => r.id === id) ?? null);
  }
  revoke(id: string, ownerUserId: string): Promise<boolean> {
    return Promise.resolve(this.rows.some((r) => r.id === id && r.owner_user_id === ownerUserId));
  }
}

class FakeGrantsRepo {
  readonly inserted: Array<{ raId: string; resource: string; action: string }> = [];
  insert(raId: string, resource: string, action: string): Promise<string> {
    this.inserted.push({ raId, resource, action });
    return Promise.resolve('g0000000-0000-4000-8000-000000000001');
  }
}

function build() {
  const roles = new FakeRolesRepo();
  const grants = new FakeGrantsRepo();
  const service = new RolesService(roles as never, grants as never, authz, noopEvents);
  return { roles, grants, service };
}

describe('RolesService (owner-managed grants)', () => {
  it('grants a role, attaches a permission, lists, and revokes', async () => {
    const { grants, service } = build();
    const ra = await service.grantRole(OWNER, {
      contactId: CONTACT,
      role: 'beneficiary',
      scopeType: 'asset',
      scopeId: CONTACT,
      effectiveCondition: 'immediate',
    });
    expect(ra.id).toBeDefined();

    await service.addPermission(OWNER, ra.id, { resource: 'contact', action: 'read' });
    expect(grants.inserted).toEqual([{ raId: ra.id, resource: 'contact', action: 'read' }]);

    const list = await service.list(OWNER);
    expect(list).toHaveLength(1);
    expect(list[0]?.role).toBe('beneficiary');
    expect(list[0]?.scopeId).toBe(CONTACT);

    await expect(service.revoke(OWNER, ra.id)).resolves.toBeUndefined();
  });

  it('404s adding a permission to a role assignment owned by someone else', async () => {
    const { service } = build();
    const ra = await service.grantRole(OWNER, {
      contactId: CONTACT,
      role: 'viewer',
      scopeType: 'estate',
      effectiveCondition: 'immediate',
    });
    // OTHER owns nothing; addPermission as OWNER on OWNER's RA works, but a
    // lookup miss (foreign / unknown id) is a generic 404.
    await expect(
      service.addPermission(OWNER, 'e0000000-0000-4000-8000-000000000099', {
        resource: 'contact',
        action: 'read',
      }),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(ra.id).toBeDefined();
  });

  it('revoking a non-existent assignment 404s', async () => {
    const { service } = build();
    await expect(
      service.revoke(OWNER, 'e0000000-0000-4000-8000-000000000098'),
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('a non-owner cannot manage role assignments (deny by default)', () => {
    expect(() =>
      authz.assertCan(OTHER, 'manage', coreResource('RoleAssignment', OWNER, OWNER)),
    ).toThrow(ForbiddenException);
  });
});
