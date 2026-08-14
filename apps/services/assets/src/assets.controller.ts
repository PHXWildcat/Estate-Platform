import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  AssetsService,
  type AssetDto,
  type AssetSummaryDto,
  type CommandResult,
  type HistoryEntryDto,
  type NetWorthDto,
} from './assets.service';
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import {
  AsOfQuerySchema,
  ChangeOwnershipSchema,
  CreateAssetSchema,
  IfMatchSchema,
  IncludeRetiredSchema,
  parse,
  RecordValuationSchema,
  RetireAssetSchema,
  UpdateDetailsSchema,
  UuidSchema,
} from './schemas';

/** Optional If-Match version token from the request headers. */
export function ifMatchOf(req: CallerRequest): bigint | undefined {
  const raw = req.headers['if-match'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return parse(IfMatchSchema, value);
}

/** Raw bearer token, re-extracted for forwarding to settlement. CallerGuard
 * already validated the header shape; '' only means a wiring anomaly and fails
 * closed inside the settlement client. */
function bearerTokenOf(req: CallerRequest): string {
  const raw = req.headers['authorization'];
  const header = Array.isArray(raw) ? raw[0] : raw;
  return typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
}

/**
 * Asset commands + queries (owner-only in M3). Commands return a thin
 * acknowledgement — CQRS reads come from the GET endpoints, which decrypt
 * (audited) from the projection. `?asOf=` replays the ledger: "what did the
 * estate hold on date X" (docs/01 §2.3).
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class AssetsController {
  constructor(private readonly assets: AssetsService) {}

  @Post('assets')
  @HttpCode(201)
  create(@Req() req: CallerRequest, @Body() body: unknown): Promise<CommandResult> {
    return this.assets.createAsset(requireCaller(req).userId, parse(CreateAssetSchema, body));
  }

  @Get('assets')
  @HttpCode(200)
  list(
    @Req() req: CallerRequest,
    @Query('asOf') asOf?: string,
    @Query('includeRetired') includeRetired?: string,
  ): Promise<AssetSummaryDto[]> {
    return this.assets.listAssets(
      requireCaller(req).userId,
      parse(AsOfQuerySchema, asOf),
      parse(IncludeRetiredSchema, includeRetired),
    );
  }

  /**
   * The estate inventory for an executor (M7 PR2, docs/03 §5.1 control 5).
   * A DELIBERATELY separate route from `/v1/assets`: the owner path stays
   * exactly as it was, and this one carries its own authorization model
   * (settlement's staged grant) plus its own audit action. Merging them would
   * put a non-owner branch inside the hot owner path.
   */
  @Get('estates/:ownerUserId/assets')
  @HttpCode(200)
  listEstate(
    @Req() req: CallerRequest,
    @Param('ownerUserId') ownerUserId: string,
  ): Promise<AssetDto[]> {
    return this.assets.listEstateAssets(
      requireCaller(req).userId,
      bearerTokenOf(req),
      parse(UuidSchema, ownerUserId),
    );
  }

  @Get('net-worth')
  @HttpCode(200)
  netWorth(@Req() req: CallerRequest, @Query('asOf') asOf?: string): Promise<NetWorthDto> {
    return this.assets.getNetWorth(requireCaller(req).userId, parse(AsOfQuerySchema, asOf));
  }

  @Get('assets/:assetId')
  @HttpCode(200)
  get(@Req() req: CallerRequest, @Param('assetId') assetId: string): Promise<AssetDto> {
    return this.assets.getAsset(requireCaller(req).userId, parse(UuidSchema, assetId));
  }

  @Get('assets/:assetId/events')
  @HttpCode(200)
  history(
    @Req() req: CallerRequest,
    @Param('assetId') assetId: string,
  ): Promise<HistoryEntryDto[]> {
    return this.assets.getHistory(requireCaller(req).userId, parse(UuidSchema, assetId));
  }

  @Patch('assets/:assetId')
  @HttpCode(200)
  update(
    @Req() req: CallerRequest,
    @Param('assetId') assetId: string,
    @Body() body: unknown,
  ): Promise<CommandResult> {
    return this.assets.updateDetails(
      requireCaller(req).userId,
      parse(UuidSchema, assetId),
      parse(UpdateDetailsSchema, body),
      ifMatchOf(req),
    );
  }

  @Post('assets/:assetId/valuations')
  @HttpCode(201)
  recordValuation(
    @Req() req: CallerRequest,
    @Param('assetId') assetId: string,
    @Body() body: unknown,
  ): Promise<CommandResult> {
    return this.assets.recordValuation(
      requireCaller(req).userId,
      parse(UuidSchema, assetId),
      parse(RecordValuationSchema, body),
      ifMatchOf(req),
    );
  }

  @Post('assets/:assetId/ownership')
  @HttpCode(200)
  changeOwnership(
    @Req() req: CallerRequest,
    @Param('assetId') assetId: string,
    @Body() body: unknown,
  ): Promise<CommandResult> {
    return this.assets.changeOwnership(
      requireCaller(req).userId,
      parse(UuidSchema, assetId),
      parse(ChangeOwnershipSchema, body),
      ifMatchOf(req),
    );
  }

  /**
   * RETIREMENT IS THE SERVICE'S DELETION-CLASS ACTION, so it is step-up gated
   * (docs/01 §5, "deletion requests"). It is also the only IRREVERSIBLE verb
   * here — every other command appends a correction, while a retired asset has
   * no un-retire route in the ledger or the API, drops out of every total, and
   * refuses all further commands.
   *
   * Found by the M19 PR4 review and proven live: on ONE non-elevated session,
   * naming a beneficiary on an asset answered 403 stepup_required while
   * retiring that same asset answered 200 and really retired it. The weaker
   * gate sat on the stronger action, which is the M6 asymmetry backwards.
   */
  @Post('assets/:assetId/retire')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  retire(
    @Req() req: CallerRequest,
    @Param('assetId') assetId: string,
    @Body() body: unknown,
  ): Promise<CommandResult> {
    return this.assets.retireAsset(
      requireCaller(req).userId,
      parse(UuidSchema, assetId),
      parse(RetireAssetSchema, body ?? {}),
      ifMatchOf(req),
    );
  }
}
