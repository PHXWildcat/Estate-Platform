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
import { CallerGuard, requireCaller, type CallerRequest } from './caller.guard';
import { RolesService, type RoleAssignmentView } from './roles.service';
import { parse, PermissionGrantSchema, RoleAssignmentSchema, UuidSchema } from './schemas';

/**
 * Owner-managed role assignments and their permission grants. All mutations are
 * owner-only (owner.cedar) and audited; these objects drive the ABAC read
 * boundary the contacts endpoints enforce.
 */
@Controller('v1/role-assignments')
@UseGuards(CallerGuard)
export class RolesController {
  constructor(private readonly roles: RolesService) {}

  @Post()
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

  @Delete(':id')
  @HttpCode(204)
  async revoke(@Req() req: CallerRequest, @Param('id') id: string): Promise<void> {
    await this.roles.revoke(requireCaller(req).userId, parse(UuidSchema, id));
  }
}
