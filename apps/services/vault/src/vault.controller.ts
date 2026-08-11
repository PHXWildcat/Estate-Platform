import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  AllowSessionAudiences,
  CallerGuard,
  requireCaller,
  StepUpGuard,
  type CallerRequest,
} from '@estate/auth-guard';
import {
  CreateItemSchema,
  CreateKeysetSchema,
  IfMatchSchema,
  ListItemsQuerySchema,
  parse,
  ReplaceKeysetSchema,
  SrpVerifySchema,
  UpdateItemSchema,
  UuidSchema,
} from './schemas';
import { requireVaultSession, VaultSessionGuard, type VaultRequest } from './vault-session.guard';
import {
  VaultService,
  type KeysetStatus,
  type SrpChallenge,
  type VaultItemDto,
  type VaultItemPage,
  type VaultOpened,
} from './vault.service';

/** Required If-Match version token from the request headers. */
function ifMatchOf(req: CallerRequest): number {
  const raw = req.headers['if-match'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return parse(IfMatchSchema, value);
}

/**
 * The vault's HTTP surface.
 *
 * Two gates stack here, and the split is the whole access-control story:
 *
 *  - StepUpGuard covers everything that opens or replaces a vault, because
 *    docs/01 §5 makes vault open and its key material a mandatory step-up
 *    action. Both SRP legs carry it, so a stale session cannot even start a
 *    handshake.
 *  - VaultSessionGuard covers item traffic. It is not a weaker gate: a vault
 *    session only exists because someone completed SRP under a step-up-fresh
 *    account session within the last 15 minutes, so item reads inherit that
 *    freshness rather than re-proving it on every keystroke.
 *
 * Deletion of an item takes BOTH, matching the deletion-class rule the document
 * service follows.
 *
 * M16 ADDS A THIRD GATE, and it runs across the other two rather than beside
 * them: the SESSION AUDIENCE. This service admits `account` and `vault`
 * service-wide, and five handlers here additionally admit `extension` —
 * `keysetStatus`, both SRP legs, `listItems` and `lock`. That set is not a
 * subset of either guard above, which is exactly why it is declared per handler:
 * the step-up-alone routes include both `reset` and the two SRP legs, so no
 * guard-shaped rule could admit an extension to the second without handing it
 * the first.
 *
 * Read the decorators as a bound on a COMPROMISED CLIENT rather than as
 * permissions for a trusted one. A browser extension is delivered by a vendor
 * store that can update it silently, so what matters is that everything it can
 * reach yields ciphertext — `listItems` sits behind VaultSessionGuard, which
 * only a completed SRP unlock satisfies, and that needs the vault password and
 * the device Secret Key, neither of which this platform holds. The declaration
 * lives in `AUDIENCE_ROUTE_ADMITTERS`; `test/session-audience.spec.ts` names
 * every route that must refuse it.
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class VaultController {
  constructor(private readonly vault: VaultService) {}

  /** Has this user enrolled a vault yet? Drives the client's first screen. */
  @Get('vault/keyset')
  @AllowSessionAudiences('extension')
  @HttpCode(200)
  keysetStatus(@Req() req: CallerRequest): Promise<KeysetStatus> {
    return this.vault.keysetStatus(requireCaller(req).userId);
  }

  @Post('vault/keyset')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  createKeyset(@Req() req: CallerRequest, @Body() body: unknown): Promise<KeysetStatus> {
    const caller = requireCaller(req);
    return this.vault.createKeyset(
      caller.userId,
      caller.sessionId,
      parse(CreateKeysetSchema, body),
    );
  }

  /**
   * Vault password change. Needs step-up, an open vault, AND a proof computed
   * from the SRP session key - see VaultService.replaceKeyset for why tokens
   * alone must not be able to replace key material.
   */
  @Put('vault/keyset')
  @UseGuards(StepUpGuard, VaultSessionGuard)
  @HttpCode(200)
  replaceKeyset(@Req() req: VaultRequest, @Body() body: unknown): Promise<KeysetStatus> {
    const caller = requireCaller(req);
    const { proof, ...payload } = parse(ReplaceKeysetSchema, body);
    return this.vault.replaceKeyset(
      caller.userId,
      caller.sessionId,
      requireVaultSession(req),
      payload,
      proof,
    );
  }

  @Post('vault/srp/start')
  @AllowSessionAudiences('extension')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  startUnlock(@Req() req: CallerRequest): Promise<SrpChallenge> {
    const caller = requireCaller(req);
    return this.vault.startUnlock(caller.userId, caller.sessionId);
  }

  @Post('vault/srp/verify')
  @AllowSessionAudiences('extension')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  finishUnlock(@Req() req: CallerRequest, @Body() body: unknown): Promise<VaultOpened> {
    const caller = requireCaller(req);
    return this.vault.finishUnlock(caller.userId, caller.sessionId, parse(SrpVerifySchema, body));
  }

  @Post('vault/lock')
  @AllowSessionAudiences('extension')
  @UseGuards(VaultSessionGuard)
  @HttpCode(204)
  lock(@Req() req: VaultRequest): Promise<void> {
    const caller = requireCaller(req);
    return this.vault.lock(caller.userId, caller.sessionId, requireVaultSession(req));
  }

  /**
   * Destroys every item and replaces the keyset. The escape hatch for a
   * forgotten vault password, and the only route that can lose data without
   * proving knowledge of the current one - because a lost password cannot be
   * proven. Step-up gated, distinctly audited.
   */
  @Post('vault/reset')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  reset(@Req() req: CallerRequest, @Body() body: unknown): Promise<{ itemsDestroyed: number }> {
    const caller = requireCaller(req);
    return this.vault.reset(caller.userId, caller.sessionId, parse(CreateKeysetSchema, body));
  }

  @Get('vault/items')
  @AllowSessionAudiences('extension')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  listItems(@Req() req: VaultRequest, @Query() query: unknown): Promise<VaultItemPage> {
    const caller = requireCaller(req);
    return this.vault.listItems(
      caller.userId,
      caller.sessionId,
      parse(ListItemsQuerySchema, query),
    );
  }

  @Post('vault/items')
  @UseGuards(VaultSessionGuard)
  @HttpCode(201)
  createItem(@Req() req: VaultRequest, @Body() body: unknown): Promise<VaultItemDto> {
    const caller = requireCaller(req);
    return this.vault.createItem(caller.userId, caller.sessionId, parse(CreateItemSchema, body));
  }

  @Get('vault/items/:itemId')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  getItem(@Req() req: VaultRequest, @Param('itemId') itemId: string): Promise<VaultItemDto> {
    const caller = requireCaller(req);
    return this.vault.getItem(caller.userId, caller.sessionId, parse(UuidSchema, itemId));
  }

  @Put('vault/items/:itemId')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  updateItem(
    @Req() req: VaultRequest,
    @Param('itemId') itemId: string,
    @Body() body: unknown,
  ): Promise<VaultItemDto> {
    const caller = requireCaller(req);
    return this.vault.updateItem(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, itemId),
      ifMatchOf(req),
      parse(UpdateItemSchema, body),
    );
  }

  @Delete('vault/items/:itemId')
  @UseGuards(StepUpGuard, VaultSessionGuard)
  @HttpCode(204)
  deleteItem(@Req() req: VaultRequest, @Param('itemId') itemId: string): Promise<void> {
    const caller = requireCaller(req);
    return this.vault.deleteItem(caller.userId, caller.sessionId, parse(UuidSchema, itemId));
  }
}
