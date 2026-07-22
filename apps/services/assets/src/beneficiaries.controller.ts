import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ifMatchOf } from './assets.controller';
import { AssetsService, type BeneficiariesDto, type CommandResult } from './assets.service';
import { CallerGuard, requireCaller, type CallerRequest } from './caller.guard';
import { StepUpGuard } from './stepup.guard';
import { DesignateBeneficiarySchema, parse, RemoveBeneficiarySchema, UuidSchema } from './schemas';

/**
 * Beneficiary designations per asset. MUTATIONS REQUIRE STEP-UP (docs/01 §5:
 * beneficiary changes are step-up actions) — asserted via StepUpGuard on the
 * gateway-verified step-up header; see stepup.guard.ts for the trust model.
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class BeneficiariesController {
  constructor(private readonly assets: AssetsService) {}

  @Get('assets/:assetId/beneficiaries')
  @HttpCode(200)
  list(@Req() req: CallerRequest, @Param('assetId') assetId: string): Promise<BeneficiariesDto> {
    return this.assets.getBeneficiaries(requireCaller(req).userId, parse(UuidSchema, assetId));
  }

  @Post('assets/:assetId/beneficiaries')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  designate(
    @Req() req: CallerRequest,
    @Param('assetId') assetId: string,
    @Body() body: unknown,
  ): Promise<CommandResult> {
    return this.assets.designateBeneficiary(
      requireCaller(req).userId,
      parse(UuidSchema, assetId),
      parse(DesignateBeneficiarySchema, body),
      ifMatchOf(req),
    );
  }

  @Delete('assets/:assetId/beneficiaries/:contactId')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  remove(
    @Req() req: CallerRequest,
    @Param('assetId') assetId: string,
    @Param('contactId') contactId: string,
    @Query('designation') designation?: string,
  ): Promise<CommandResult> {
    return this.assets.removeBeneficiary(
      requireCaller(req).userId,
      parse(UuidSchema, assetId),
      parse(UuidSchema, contactId),
      parse(RemoveBeneficiarySchema, { designation }),
      ifMatchOf(req),
    );
  }
}
