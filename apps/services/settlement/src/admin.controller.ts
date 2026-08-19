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
import {
  AllowSessionAudiences,
  CallerGuard,
  requireCaller,
  ServiceCredentialGuard,
  StepUpGuard,
  type CallerRequest,
} from '@estate/auth-guard';
import {
  SettlementAdminService,
  type DistributionDto,
  type StageDto,
  type TaskDto,
  type TimelineEntry,
} from './admin.service';
import {
  CompleteTaskSchema,
  DistributionStatusSchema,
  parse,
  RecordDistributionSchema,
  StageAccessQuerySchema,
  StageDecisionSchema,
  StageRequestSchema,
  UuidSchema,
  VaultReleaseQuerySchema,
} from './schemas';

/**
 * Post-verification administration (docs/03 §5.1 control 5).
 *
 * Step-up placement: everything that MOVES access or money is step-up gated —
 * requesting a stage, deciding one, recording and approving a distribution,
 * closing the case. Reads and task ticks are not: they neither widen access
 * nor transfer value, and a grieving executor should not face an MFA prompt to
 * look at a checklist.
 */
@Controller('v1/settlement')
@UseGuards(CallerGuard)
export class SettlementAdminController {
  constructor(private readonly admin: SettlementAdminService) {}

  // ------------------------------------------------------------ staged access

  @Post('cases/:caseId/stages')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  requestStage(
    @Req() req: CallerRequest,
    @Param('caseId') caseId: string,
    @Body() body: unknown,
  ): Promise<StageDto> {
    const caller = requireCaller(req);
    const input = parse(StageRequestSchema, body);
    return this.admin.requestStage(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, caseId),
      input.stage,
    );
  }

  @Get('cases/:caseId/stages')
  @AllowSessionAudiences('operator')
  @HttpCode(200)
  listStages(@Req() req: CallerRequest, @Param('caseId') caseId: string): Promise<StageDto[]> {
    const caller = requireCaller(req);
    return this.admin.listStages(caller.userId, caller.sessionId, parse(UuidSchema, caseId));
  }

  @Post('stages/:stageId/decision')
  @AllowSessionAudiences('operator')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  decideStage(
    @Req() req: CallerRequest,
    @Param('stageId') stageId: string,
    @Body() body: unknown,
  ): Promise<StageDto> {
    const caller = requireCaller(req);
    const input = parse(StageDecisionSchema, body);
    return this.admin.decideStage(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, stageId),
      input.decision,
    );
  }

  @Post('stages/:stageId/revoke')
  @AllowSessionAudiences('operator')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  revokeStage(@Req() req: CallerRequest, @Param('stageId') stageId: string): Promise<StageDto> {
    const caller = requireCaller(req);
    return this.admin.revokeStage(caller.userId, caller.sessionId, parse(UuidSchema, stageId));
  }

  // ------------------------------------------------------------------- tasks

  @Get('cases/:caseId/tasks')
  @HttpCode(200)
  listTasks(@Req() req: CallerRequest, @Param('caseId') caseId: string): Promise<TaskDto[]> {
    const caller = requireCaller(req);
    return this.admin.listTasks(caller.userId, caller.sessionId, parse(UuidSchema, caseId));
  }

  @Post('tasks/:taskId/completion')
  @HttpCode(200)
  completeTask(
    @Req() req: CallerRequest,
    @Param('taskId') taskId: string,
    @Body() body: unknown,
  ): Promise<TaskDto> {
    const caller = requireCaller(req);
    return this.admin.completeTask(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, taskId),
      parse(CompleteTaskSchema, body),
    );
  }

  // ----------------------------------------------------------- distributions

  @Post('cases/:caseId/distributions')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  recordDistribution(
    @Req() req: CallerRequest,
    @Param('caseId') caseId: string,
    @Body() body: unknown,
  ): Promise<DistributionDto> {
    const caller = requireCaller(req);
    const input = parse(RecordDistributionSchema, body);
    return this.admin.recordDistribution(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, caseId),
      {
        beneficiaryContactId: input.beneficiaryContactId,
        ...(input.assetId ? { assetId: input.assetId } : {}),
        amount: input.amount ?? null,
      },
    );
  }

  @Get('cases/:caseId/distributions')
  @AllowSessionAudiences('operator')
  @HttpCode(200)
  listDistributions(
    @Req() req: CallerRequest,
    @Param('caseId') caseId: string,
  ): Promise<DistributionDto[]> {
    const caller = requireCaller(req);
    return this.admin.listDistributions(caller.userId, caller.sessionId, parse(UuidSchema, caseId));
  }

  @Post('distributions/:distributionId/approval')
  @AllowSessionAudiences('operator')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  approveDistribution(
    @Req() req: CallerRequest,
    @Param('distributionId') distributionId: string,
  ): Promise<DistributionDto> {
    const caller = requireCaller(req);
    return this.admin.approveDistribution(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, distributionId),
    );
  }

  @Post('distributions/:distributionId/status')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  setDistributionStatus(
    @Req() req: CallerRequest,
    @Param('distributionId') distributionId: string,
    @Body() body: unknown,
  ): Promise<DistributionDto> {
    const caller = requireCaller(req);
    const input = parse(DistributionStatusSchema, body);
    return this.admin.setDistributionStatus(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, distributionId),
      input.status,
    );
  }

  // ------------------------------------------------------- timeline + close

  @Get('cases/:caseId/timeline')
  @AllowSessionAudiences('operator')
  @HttpCode(200)
  timeline(@Req() req: CallerRequest, @Param('caseId') caseId: string): Promise<TimelineEntry[]> {
    const caller = requireCaller(req);
    return this.admin.timeline(caller.userId, caller.sessionId, parse(UuidSchema, caseId));
  }

  @Post('cases/:caseId/close')
  @AllowSessionAudiences('operator')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  closeCase(
    @Req() req: CallerRequest,
    @Param('caseId') caseId: string,
  ): Promise<{ status: string }> {
    const caller = requireCaller(req);
    return this.admin.closeCase(caller.userId, caller.sessionId, parse(UuidSchema, caseId));
  }

  // --------------------------------------------------- caller-scoped authority

  /** Asked by assets on the executor's own forwarded bearer. */
  @Get('authority/stage-access')
  @HttpCode(200)
  stageAccess(
    @Req() req: CallerRequest,
    @Query() query: unknown,
  ): Promise<{ allowed: boolean; caseId: string | null }> {
    const caller = requireCaller(req);
    const parsed = parse(StageAccessQuerySchema, query);
    return this.admin.stageAccessAuthority(caller.userId, parsed.ownerUserId, parsed.stage);
  }
}

/**
 * The Zone A gate (docs/03 §6a). Service-credential guarded, NOT CallerGuard:
 * this asks about the OWNER's settlement state, and the caller is the vault
 * acting on behalf of a grantee whose token must never be able to mint the
 * answer. A separate controller because the guard differs — mixing a
 * service-authenticated route into a user-authenticated controller is exactly
 * the kind of wiring mistake that quietly opens a hole.
 */
@Controller('v1/settlement/authority')
@UseGuards(ServiceCredentialGuard)
export class SettlementVaultGateController {
  constructor(private readonly admin: SettlementAdminService) {}

  @Get('vault-release')
  @HttpCode(200)
  vaultRelease(@Query() query: unknown): Promise<{ permitted: boolean; caseId: string | null }> {
    const parsed = parse(VaultReleaseQuerySchema, query);
    return this.admin.vaultReleaseAuthority(parsed.ownerUserId);
  }
}
