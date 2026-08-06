import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import { RolesService, type PermissionGrantView, type RoleAssignmentView } from './roles.service';
import { parse, PermissionGrantSchema, RoleAssignmentSchema, UuidSchema } from './schemas';

/**
 * Owner-managed role assignments and their permission grants. All mutations are
 * owner-only (owner.cedar) and audited; these objects drive the ABAC read
 * boundary the contacts endpoints enforce.
 *
 * MUTATIONS REQUIRE STEP-UP (docs/01 §5: "trustee/executor changes, beneficiary
 * changes"). M2 shipped this controller before `@estate/auth-guard` existed and
 * it stayed `CallerGuard`-only afterwards, so the sibling route in assets
 * (`beneficiaries.controller.ts`) complied with the same requirement while the
 * route that grants someone the trustee of an entire estate did not — and no
 * decision-log entry ever exempted it.
 *
 * THE GATE IS UNIFORM ACROSS ALL TWELVE ROLES, not just the three docs/01 §5
 * names. A guard cannot branch on the body without becoming a second, weaker
 * copy of the schema, and a table of "which roles are sensitive" is a table that
 * drifts — `agent_financial` is a power of attorney and `viewer` still reads an
 * estate. One gate, no exceptions to keep in sync.
 *
 * REVOKING A ROLE IS GATED TOO, and that is not a contradiction of the M6 rule
 * that the protective action must never be HARDER than the permissive one: they
 * are equal here, which the rule permits. It is gated because revoking is not
 * purely protective in this domain — it destroys the executor-resolution path
 * (M7) and can strip the last linked contact who could report a death or rescue
 * a §5.1 case, so a stolen bearer that revokes is running an isolation attack,
 * not a safety measure. Revoking a PERMISSION GRANT is different and is
 * deliberately left ungated below.
 */
@Controller('v1/role-assignments')
@UseGuards(CallerGuard)
export class RolesController {
  constructor(private readonly roles: RolesService) {}

  @Post()
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  grant(@Req() req: CallerRequest, @Body() body: unknown): Promise<{ id: string }> {
    return this.roles.grantRole(requireCaller(req).userId, parse(RoleAssignmentSchema, body));
  }

  @Get()
  @HttpCode(200)
  list(@Req() req: CallerRequest): Promise<RoleAssignmentView[]> {
    return this.roles.list(requireCaller(req).userId);
  }

  @Post(':id/permissions')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  addPermission(
    @Req() req: CallerRequest,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<{ id: string }> {
    return this.roles.addPermission(
      requireCaller(req).userId,
      parse(UuidSchema, id),
      parse(PermissionGrantSchema, body),
    );
  }

  /** The grants on one assignment. Reading what you granted is not a sensitive act. */
  @Get(':id/permissions')
  @HttpCode(200)
  listPermissions(
    @Req() req: CallerRequest,
    @Param('id') id: string,
  ): Promise<PermissionGrantView[]> {
    return this.roles.listPermissions(requireCaller(req).userId, parse(UuidSchema, id));
  }

  /**
   * Withdraw one grant. CallerGuard ONLY, unlike its granting counterpart above.
   *
   * This is the M6 emergency-access-denial rule applied literally: narrowing a
   * role-holder's reach is the protective act, and a protective act must never be
   * harder to perform than the permissive one it undoes. An owner who suspects a
   * grant was a mistake must be able to pull it without first finding their
   * authenticator — the worst case of an ungated revoke is that an attacker with
   * a stolen bearer removes access they were never able to use, while the worst
   * case of a gated one is an owner who cannot close a hole they can see.
   *
   * Revoking the whole ASSIGNMENT stays gated (see the class docstring): that
   * destroys a designation the estate depends on, which is a different act from
   * narrowing what a designation may read.
   */
  @Delete(':id/permissions/:grantId')
  @HttpCode(204)
  async revokePermission(
    @Req() req: CallerRequest,
    @Param('id') id: string,
    @Param('grantId') grantId: string,
  ): Promise<void> {
    await this.roles.revokePermission(
      requireCaller(req).userId,
      parse(UuidSchema, id),
      parse(UuidSchema, grantId),
    );
  }

  @Delete(':id')
  @UseGuards(StepUpGuard)
  @HttpCode(204)
  async revoke(@Req() req: CallerRequest, @Param('id') id: string): Promise<void> {
    await this.roles.revoke(requireCaller(req).userId, parse(UuidSchema, id));
  }
}
