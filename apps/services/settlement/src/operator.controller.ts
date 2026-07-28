import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import { SettlementService, type CaseDto, type EvidenceReadAnswer } from './settlement.service';
import {
  EvidenceReadQuerySchema,
  parse,
  ProviderReportSchema,
  ReviewDecisionSchema,
  UuidSchema,
} from './schemas';

/**
 * Operator routes (the mandatory-human-review surface, docs/03 §5.1 control
 * 2). Operators are ordinary platform users on the CLI-managed allowlist;
 * every route verifies the caller's session like any other, then the service
 * resolves operator-ness and Cedar decides. State-advancing decisions
 * (approve/reject, verify) and operator-filed intake are step-up-gated;
 * claiming a review and reading the queue are not — they move nothing toward
 * access.
 *
 * The authority route answers the documents service's evidence-read question.
 * It is CallerGuard-ed: documents forwards the OPERATOR's own bearer, so the
 * answer is about a verified caller, never about an unauthenticated asker.
 */
@Controller('v1/settlement')
@UseGuards(CallerGuard)
export class OperatorController {
  constructor(private readonly settlement: SettlementService) {}

  @Get('queue')
  @HttpCode(200)
  queue(@Req() req: CallerRequest): Promise<CaseDto[]> {
    return this.settlement.queue(requireCaller(req).userId);
  }

  @Post('cases/report-provider')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  reportProvider(@Req() req: CallerRequest, @Body() body: unknown): Promise<CaseDto> {
    const caller = requireCaller(req);
    return this.settlement.reportProviderSignal(
      caller.userId,
      caller.sessionId,
      parse(ProviderReportSchema, body),
    );
  }

  @Post('cases/:caseId/review/start')
  @HttpCode(200)
  startReview(@Req() req: CallerRequest, @Param('caseId') caseId: string): Promise<CaseDto> {
    const caller = requireCaller(req);
    return this.settlement.startReview(caller.userId, caller.sessionId, parse(UuidSchema, caseId));
  }

  @Post('cases/:caseId/review')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  decideReview(
    @Req() req: CallerRequest,
    @Param('caseId') caseId: string,
    @Body() body: unknown,
  ): Promise<CaseDto> {
    const caller = requireCaller(req);
    return this.settlement.decideReview(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, caseId),
      parse(ReviewDecisionSchema, body),
    );
  }

  @Post('cases/:caseId/verify')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  verify(@Req() req: CallerRequest, @Param('caseId') caseId: string): Promise<CaseDto> {
    const caller = requireCaller(req);
    return this.settlement.confirmVerification(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, caseId),
    );
  }

  @Get('authority/evidence-read')
  @HttpCode(200)
  evidenceRead(@Req() req: CallerRequest, @Query() query: unknown): Promise<EvidenceReadAnswer> {
    const caller = requireCaller(req);
    const parsed = parse(EvidenceReadQuerySchema, query);
    return this.settlement.evidenceReadAuthority(caller.userId, parsed.documentId, parsed.version);
  }
}
