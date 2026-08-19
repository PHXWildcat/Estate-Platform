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
    const caller = requireCaller(req);
    return this.settlement.queue(caller.userId, caller.sessionId);
  }

  /**
   * The post-verification worklist (M21 PR3b).
   *
   * A SEPARATE path from `queue` rather than a `?status=` filter on it: the
   * operator edge deliberately drops the query string (a case id names
   * somebody's death, and a query string is the part intermediaries log by
   * default — the M12 document-search rule), so a filter would have to be a
   * path segment anyway. Two paths, two status sets, and the sets are pinned
   * disjoint.
   *
   * A SIBLING OF `queue` rather than `cases/administrable`, which would be a
   * literal segment competing with `SettlementController`'s `cases/:caseId`
   * in another controller entirely — Nest resolves those in module
   * registration order, so the two would work or not work depending on the
   * order of `app.module.ts`'s `controllers` array. A path that cannot
   * collide beats a path whose correctness is a property of a list.
   */
  @Get('administrable')
  @HttpCode(200)
  administrable(@Req() req: CallerRequest): Promise<CaseDto[]> {
    const caller = requireCaller(req);
    return this.settlement.administrable(caller.userId, caller.sessionId);
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
