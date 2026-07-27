import { Body, Controller, Get, HttpCode, Param, Post, Put, Req, UseGuards } from '@nestjs/common';
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import type { ReportableEstate } from './core-reads.repo';
import { SettlementService, type CaseDto } from './settlement.service';
import { AddEvidenceSchema, parse, ReportCaseSchema, SettingsSchema, UuidSchema } from './schemas';

/**
 * User-facing settlement routes: reporters and the case subject.
 *
 * Step-up placement (docs/01 §5): the owner VOID is step-up-gated because the
 * step-up IS the liveness proof that kills the case — a bare bearer token
 * must never be able to void (that would let a token thief keep a victim's
 * fraudulent case alive... or kill a legitimate one). The waiting-period
 * setting is step-up-gated as emergency-access-configuration-class. Intake is
 * CallerGuard-only: filing a report ADDS scrutiny (a case that locks nothing
 * and notifies the owner) and must stay one tap for a grieving contact —
 * the controls sit on what a report can CAUSE, not on filing it.
 */
@Controller('v1/settlement')
@UseGuards(CallerGuard)
export class SettlementController {
  constructor(private readonly settlement: SettlementService) {}

  @Get('reportable-estates')
  @HttpCode(200)
  reportableEstates(@Req() req: CallerRequest): Promise<ReportableEstate[]> {
    return this.settlement.reportableEstates(requireCaller(req).userId);
  }

  @Post('cases')
  @HttpCode(201)
  report(@Req() req: CallerRequest, @Body() body: unknown): Promise<CaseDto> {
    const caller = requireCaller(req);
    return this.settlement.report(caller.userId, caller.sessionId, parse(ReportCaseSchema, body));
  }

  @Get('cases')
  @HttpCode(200)
  listMine(@Req() req: CallerRequest): Promise<CaseDto[]> {
    return this.settlement.listMyCases(requireCaller(req).userId);
  }

  @Get('cases/:caseId')
  @HttpCode(200)
  getCase(@Req() req: CallerRequest, @Param('caseId') caseId: string): Promise<CaseDto> {
    return this.settlement.getCase(requireCaller(req).userId, parse(UuidSchema, caseId));
  }

  @Post('cases/:caseId/evidence')
  @HttpCode(200)
  addEvidence(
    @Req() req: CallerRequest,
    @Param('caseId') caseId: string,
    @Body() body: unknown,
  ): Promise<CaseDto> {
    const caller = requireCaller(req);
    const input = parse(AddEvidenceSchema, body);
    return this.settlement.addEvidence(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, caseId),
      input.evidence,
    );
  }

  @Post('cases/:caseId/void')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  void(@Req() req: CallerRequest, @Param('caseId') caseId: string): Promise<CaseDto> {
    const caller = requireCaller(req);
    return this.settlement.void(caller.userId, caller.sessionId, parse(UuidSchema, caseId));
  }

  @Get('settings')
  @HttpCode(200)
  getSettings(@Req() req: CallerRequest): Promise<{ waitingPeriodDays: number }> {
    return this.settlement.getSettings(requireCaller(req).userId);
  }

  @Put('settings')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  updateSettings(
    @Req() req: CallerRequest,
    @Body() body: unknown,
  ): Promise<{ waitingPeriodDays: number }> {
    const caller = requireCaller(req);
    return this.settlement.updateSettings(
      caller.userId,
      caller.sessionId,
      parse(SettingsSchema, body),
    );
  }
}
