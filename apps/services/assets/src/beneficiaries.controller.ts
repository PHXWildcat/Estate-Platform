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
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import { DesignateBeneficiarySchema, parse, RemoveBeneficiarySchema, UuidSchema } from './schemas';

/**
 * Beneficiary designations per asset. MUTATIONS REQUIRE STEP-UP (docs/01 §5:
 * beneficiary changes are step-up actions) — enforced by StepUpGuard, which
 * checks the VERIFIED session's step-up freshness (@estate/auth-guard).
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
    @Query('eventId') eventId?: string,
  ): Promise<CommandResult> {
    // eventId rides the query string (a DELETE carries no body): the schema
    // accepted it since M3 and the controller never passed it through, so a
    // retried remove was a 404 instead of an idempotent no-op (found wiring
    // the first consumer, M19 PR3 — the zero-callers shape in miniature).
    return this.assets.removeBeneficiary(
      requireCaller(req).userId,
      parse(UuidSchema, assetId),
      parse(UuidSchema, contactId),
      parse(RemoveBeneficiarySchema, { designation, eventId }),
      ifMatchOf(req),
    );
  }
}
