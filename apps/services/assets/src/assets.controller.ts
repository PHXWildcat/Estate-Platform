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
  type CommandResult,
  type HistoryEntryDto,
  type NetWorthDto,
} from './assets.service';
import { CallerGuard, requireCaller, type CallerRequest } from './caller.guard';
import {
  AsOfQuerySchema,
  ChangeOwnershipSchema,
  CreateAssetSchema,
  IfMatchSchema,
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
  list(@Req() req: CallerRequest, @Query('asOf') asOf?: string): Promise<AssetDto[]> {
    return this.assets.listAssets(requireCaller(req).userId, parse(AsOfQuerySchema, asOf));
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

  @Post('assets/:assetId/retire')
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
