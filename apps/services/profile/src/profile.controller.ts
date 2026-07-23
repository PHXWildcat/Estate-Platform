import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { CallerGuard, requireCaller, type CallerRequest } from '@estate/auth-guard';
import { FamilyService, type FamilyMemberView } from './family.service';
import { ProfileService, type ProfileView } from './profile.service';
import { FamilyMemberSchema, parse, ProfileUpsertSchema, UuidSchema } from './schemas';

/**
 * Own profile + family-member endpoints. The caller is resolved from their
 * verified session (CallerGuard → identity introspection); every operation is
 * scoped to that caller's own data and enforced through the ProfileAuthz PEP.
 */
@Controller('v1/profile')
@UseGuards(CallerGuard)
export class ProfileController {
  constructor(
    private readonly profile: ProfileService,
    private readonly family: FamilyService,
  ) {}

  @Get()
  @HttpCode(200)
  getProfile(@Req() req: CallerRequest): Promise<ProfileView> {
    return this.profile.getOwn(requireCaller(req).userId);
  }

  @Put()
  @HttpCode(200)
  async upsertProfile(
    @Req() req: CallerRequest,
    @Body() body: unknown,
  ): Promise<{ status: string }> {
    await this.profile.upsert(requireCaller(req).userId, parse(ProfileUpsertSchema, body));
    return { status: 'ok' };
  }

  @Get('family')
  @HttpCode(200)
  listFamily(@Req() req: CallerRequest): Promise<FamilyMemberView[]> {
    return this.family.list(requireCaller(req).userId);
  }

  @Post('family')
  @HttpCode(201)
  createFamily(@Req() req: CallerRequest, @Body() body: unknown): Promise<{ id: string }> {
    return this.family.create(requireCaller(req).userId, parse(FamilyMemberSchema, body));
  }

  @Put('family/:id')
  @HttpCode(200)
  async updateFamily(
    @Req() req: CallerRequest,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<{ status: string }> {
    await this.family.update(
      requireCaller(req).userId,
      parse(UuidSchema, id),
      parse(FamilyMemberSchema, body),
    );
    return { status: 'ok' };
  }

  @Delete('family/:id')
  @HttpCode(204)
  async deleteFamily(@Req() req: CallerRequest, @Param('id') id: string): Promise<void> {
    await this.family.remove(requireCaller(req).userId, parse(UuidSchema, id));
  }
}
