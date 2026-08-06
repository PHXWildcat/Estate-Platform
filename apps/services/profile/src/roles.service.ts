import { Injectable, NotFoundException } from '@nestjs/common';
import { coreResource, ProfileAuthz } from './authz.service';
import { ContactsRepo } from './contacts.repo';
import { EventsService } from './events.service';
import { PermissionGrantsRepo, RolesRepo, type RoleAssignmentRow } from './roles.repo';
import type { PermissionGrantInput, RoleAssignmentInput } from './schemas';

export interface RoleAssignmentView {
  id: string;
  contactId: string;
  role: string;
  scopeType: string;
  scopeId: string | null;
  effectiveCondition: string;
  startsAt: string | null;
  endsAt: string | null;
}

/** A live permission grant, as the owner sees it. */
export interface PermissionGrantView {
  id: string;
  resource: string;
  action: string;
  createdAt: string;
}

/**
 * Role assignments and permission grants — the owner-managed authorization
 * objects that later drive the ABAC read boundary. Every mutation is owner-only
 * (owner.cedar) and audited; per docs/01 §5 each grant is itself a versioned,
 * audited object.
 */
@Injectable()
export class RolesService {
  constructor(
    private readonly roles: RolesRepo,
    private readonly grants: PermissionGrantsRepo,
    private readonly contacts: ContactsRepo,
    private readonly authz: ProfileAuthz,
    private readonly events: EventsService,
  ) {}

  async grantRole(callerUserId: string, input: RoleAssignmentInput): Promise<{ id: string }> {
    // Only the owner may grant a role over their estate.
    this.authz.assertCan(
      callerUserId,
      'manage',
      coreResource('RoleAssignment', callerUserId, callerUserId),
    );
    // The named contact must be the CALLER'S, and live. The FK proves only that
    // some contact exists; without this check an owner could hang a designation
    // on another owner's contact id (self-inflicted — every resolver scopes by
    // owner — but it resurrects the silent-retirement shape PR1 closed: the
    // OTHER owner's `contact_in_use` check is owner-scoped and would never see
    // this assignment, so their delete would silently un-resolve it) or on a
    // soft-deleted one, minting a designation that never resolves anywhere.
    // Uniform not_found: a foreign contact id must read exactly like a wrong one.
    const contact = await this.contacts.findById(input.contactId);
    if (!contact || contact.owner_user_id !== callerUserId) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const id = await this.roles.insert({
      ownerUserId: callerUserId,
      contactId: input.contactId,
      role: input.role,
      scopeType: input.scopeType,
      scopeId: input.scopeId ?? null,
      effectiveCondition: input.effectiveCondition,
      startsAt: input.startsAt ? new Date(input.startsAt) : null,
      endsAt: input.endsAt ? new Date(input.endsAt) : null,
    });
    await this.events.roleGranted(callerUserId, id, {
      role: input.role,
      scopeType: input.scopeType,
    });
    return { id };
  }

  async addPermission(
    callerUserId: string,
    roleAssignmentId: string,
    input: PermissionGrantInput,
  ): Promise<{ id: string }> {
    this.authz.assertCan(
      callerUserId,
      'manage',
      coreResource('RoleAssignment', roleAssignmentId, callerUserId),
    );
    const ra = await this.roles.findById(roleAssignmentId);
    if (!ra || ra.owner_user_id !== callerUserId) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const id = await this.grants.insert(
      roleAssignmentId,
      input.resource,
      input.action,
      input.constraintExpr ?? null,
    );
    await this.events.permissionGranted(callerUserId, id, {
      resource: input.resource,
      action: input.action,
    });
    return { id };
  }

  /**
   * The grants attached to one role assignment — the read half M2 never shipped.
   *
   * Authorization is the same `manage` check the write path uses plus the same
   * owner cross-check, so a grant id belonging to another estate is a uniform
   * `not_found`. `constraint_expr` is deliberately NOT projected: it is
   * operator-authored JSON that no surface renders, and echoing arbitrary stored
   * JSON back through an API is how a column becomes an exfiltration channel.
   */
  async listPermissions(
    callerUserId: string,
    roleAssignmentId: string,
  ): Promise<PermissionGrantView[]> {
    this.authz.assertCan(
      callerUserId,
      'read',
      coreResource('RoleAssignment', roleAssignmentId, callerUserId),
    );
    const ra = await this.roles.findById(roleAssignmentId);
    if (!ra || ra.owner_user_id !== callerUserId) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const rows = await this.grants.listByRoleAssignment(roleAssignmentId);
    return rows.map((row) => ({
      id: row.id,
      resource: row.resource,
      action: row.action,
      createdAt: row.created_at.toISOString(),
    }));
  }

  /**
   * Withdraw one grant. NOT step-up gated, deliberately — see the controller.
   */
  async revokePermission(
    callerUserId: string,
    roleAssignmentId: string,
    grantId: string,
  ): Promise<void> {
    this.authz.assertCan(
      callerUserId,
      'manage',
      coreResource('RoleAssignment', roleAssignmentId, callerUserId),
    );
    const ra = await this.roles.findById(roleAssignmentId);
    if (!ra || ra.owner_user_id !== callerUserId) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const ok = await this.grants.revoke(roleAssignmentId, grantId);
    if (!ok) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.events.permissionRevoked(callerUserId, grantId);
  }

  async list(callerUserId: string): Promise<RoleAssignmentView[]> {
    this.authz.assertCan(
      callerUserId,
      'read',
      coreResource('RoleAssignment', callerUserId, callerUserId),
    );
    const rows = await this.roles.listByOwner(callerUserId);
    return rows.map(toView);
  }

  async revoke(callerUserId: string, id: string): Promise<void> {
    this.authz.assertCan(callerUserId, 'manage', coreResource('RoleAssignment', id, callerUserId));
    const ok = await this.roles.revoke(id, callerUserId);
    if (!ok) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.events.roleRevoked(callerUserId, id);
  }
}

function toView(row: RoleAssignmentRow): RoleAssignmentView {
  return {
    id: row.id,
    contactId: row.contact_id,
    role: row.role,
    scopeType: row.scope_type,
    scopeId: row.scope_id,
    effectiveCondition: row.effective_condition,
    startsAt: row.starts_at ? row.starts_at.toISOString() : null,
    endsAt: row.ends_at ? row.ends_at.toISOString() : null,
  };
}
