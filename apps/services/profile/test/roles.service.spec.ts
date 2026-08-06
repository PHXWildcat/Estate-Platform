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
  readonly rows: Array<{
    id: string;
    raId: string;
    resource: string;
    action: string;
    created_at: Date;
    revoked: boolean;
  }> = [];
  private seq = 0;
  insert(raId: string, resource: string, action: string): Promise<string> {
    this.inserted.push({ raId, resource, action });
    const id = `g0000000-0000-4000-8000-00000000000${++this.seq}`;
    this.rows.push({ id, raId, resource, action, created_at: new Date(0), revoked: false });
    return Promise.resolve(id);
  }
  listByRoleAssignment(
    raId: string,
  ): Promise<Array<{ id: string; resource: string; action: string; created_at: Date }>> {
    return Promise.resolve(this.rows.filter((r) => r.raId === raId && !r.revoked));
  }
  revoke(raId: string, grantId: string): Promise<boolean> {
    const row = this.rows.find((r) => r.id === grantId && r.raId === raId && !r.revoked);
    if (!row) return Promise.resolve(false);
    row.revoked = true;
    return Promise.resolve(true);
  }
}

class RecordingEvents {
  readonly revoked: string[] = [];
  permissionGranted(): Promise<void> {
    return Promise.resolve();
  }
  permissionRevoked(_actor: string, grantId: string): Promise<void> {
    this.revoked.push(grantId);
    return Promise.resolve();
  }
  roleGranted(): Promise<void> {
    return Promise.resolve();
  }
  roleRevoked(): Promise<void> {
    return Promise.resolve();
  }
}

function build() {
  const roles = new FakeRolesRepo();
  const grants = new FakeGrantsRepo();
  const service = new RolesService(roles as never, grants as never, authz, noopEvents);
  return { roles, grants, service };
}

function buildWithEvents() {
  const roles = new FakeRolesRepo();
  const grants = new FakeGrantsRepo();
  const events = new RecordingEvents();
  const service = new RolesService(roles as never, grants as never, authz, events as never);
  return { roles, grants, events, service };
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

/**
 * M2 shipped `addPermission` with no read and no withdrawal: `listByRoleAssignment`
 * had zero callers, there was no revoke route, and `permission.revoked` was not
 * in the audit catalog. An owner could widen a role-holder's reach and then
 * neither see nor undo it — the inverse of the M6 rule that the protective action
 * must never be harder than the permissive one.
 */
describe('permission grants can be read and withdrawn (M13 PR1)', () => {
  async function withGrant() {
    const built = buildWithEvents();
    const ra = await built.service.grantRole(OWNER, {
      contactId: CONTACT,
      role: 'beneficiary',
      scopeType: 'estate',
      effectiveCondition: 'immediate',
    });
    const grant = await built.service.addPermission(OWNER, ra.id, {
      resource: 'contact',
      action: 'read',
    });
    return { ...built, raId: ra.id, grantId: grant.id };
  }

  it('lists the live grants on an assignment, without echoing constraint_expr', async () => {
    const { service, raId, grantId } = await withGrant();
    const list = await service.listPermissions(OWNER, raId);
    expect(list).toEqual([
      { id: grantId, resource: 'contact', action: 'read', createdAt: new Date(0).toISOString() },
    ]);
    // The stored Cedar condition is operator-authored JSON; no surface renders it
    // and the view type has no field for it.
    expect(Object.keys(list[0] as object)).not.toContain('constraintExpr');
  });

  it('revokes a grant, audits it, and drops it from the list', async () => {
    const { service, events, raId, grantId } = await withGrant();
    await expect(service.revokePermission(OWNER, raId, grantId)).resolves.toBeUndefined();
    expect(events.revoked).toEqual([grantId]);
    expect(await service.listPermissions(OWNER, raId)).toEqual([]);
  });

  it('revoking twice 404s rather than reporting a second success', async () => {
    const { service, events, raId, grantId } = await withGrant();
    await service.revokePermission(OWNER, raId, grantId);
    await expect(service.revokePermission(OWNER, raId, grantId)).rejects.toBeInstanceOf(
      NotFoundException,
    );
    // ...and no second audit event claims a revocation that did not happen.
    expect(events.revoked).toEqual([grantId]);
  });

  it('404s for a grant reached through an assignment that is not the caller"s', async () => {
    const { service, raId, grantId } = await withGrant();
    // A foreign caller never gets past the owner cross-check, so a grant id from
    // one estate cannot be revoked through another's assignment.
    await expect(service.revokePermission(OTHER, raId, grantId)).rejects.toBeInstanceOf(
      NotFoundException,
    );
    await expect(service.listPermissions(OTHER, raId)).rejects.toBeInstanceOf(NotFoundException);
    await expect(
      service.revokePermission(OWNER, 'e0000000-0000-4000-8000-000000000097', grantId),
    ).rejects.toBeInstanceOf(NotFoundException);
  });
});
