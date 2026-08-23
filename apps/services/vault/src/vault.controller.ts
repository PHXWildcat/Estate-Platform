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
  ListRestorableQuerySchema,
  ListVersionsQuerySchema,
  RestoreVersionSchema,
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
  type VaultVersionPage,
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
 * service-wide, and seven handlers here additionally admit `extension` —
 * `keysetStatus`, both SRP legs, `listItems`, `createItem`, `updateItem` and
 * `lock`. `createItem` and `updateItem` arrived with M16 PR4a; `deleteItem` did
 * NOT and does not, because it is the destructive verb. That set is not a
 * subset of either guard above, which is exactly why it is declared per handler:
 * the step-up-alone routes include both `reset` and the two SRP legs, so no
 * guard-shaped rule could admit an extension to the second without handing it
 * the first.
 *
 * Read the decorators as a bound on a COMPROMISED CLIENT rather than as
 * permissions for a trusted one. A browser extension is delivered by a vendor
 * store that can update it silently, so what matters is WHAT THE CREDENTIAL
 * ALONE BUYS: nothing. Every item route it reaches — read or write — sits
 * behind VaultSessionGuard, which only a completed SRP unlock satisfies, and
 * that needs the vault password, the device Secret Key and a fresh step-up,
 * none of which this platform holds.
 *
 * WHAT AN UNLOCKED VAULT BUYS IS LARGER SINCE PR4a, and the docstring said
 * "everything it can reach yields ciphertext" until then. It no longer does: an
 * unlocked extension can overwrite an item's blob with any bytes, so the
 * contents are at risk even though the KEYSET is not (`reset` and both keyset
 * routes stay refused, as do all eleven emergency routes). `vault_items_versions`
 * keeps the prior image, but nothing in the product reads it — see docs/03 §6j.
 * The declaration
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
  @AllowSessionAudiences('extension')
  @UseGuards(VaultSessionGuard)
  @HttpCode(201)
  createItem(@Req() req: VaultRequest, @Body() body: unknown): Promise<VaultItemDto> {
    const caller = requireCaller(req);
    return this.vault.createItem(caller.userId, caller.sessionId, parse(CreateItemSchema, body));
  }

  /**
   * DECLARED BEFORE `:itemId`, AND THAT ORDER IS LOAD-BEARING (M27 PR1b).
   *
   * Nest matches within a controller in declaration order, so if
   * `@Get('vault/items/:itemId')` came first it would capture `restorable` as
   * an item id and the route would answer 400 `invalid_request` — a live route
   * that reads as a client bug. `vault.int.spec.ts` drives this path and
   * asserts a 200 list, so a reordering of these methods fails there rather
   * than in somebody's browser.
   */
  @Get('vault/items/restorable')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  listRestorable(@Req() req: VaultRequest, @Query() query: unknown): Promise<VaultItemPage> {
    const caller = requireCaller(req);
    return this.vault.listRestorableItems(caller.userId, parse(ListRestorableQuerySchema, query));
  }

  @Get('vault/items/:itemId')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  getItem(@Req() req: VaultRequest, @Param('itemId') itemId: string): Promise<VaultItemDto> {
    const caller = requireCaller(req);
    return this.vault.getItem(caller.userId, caller.sessionId, parse(UuidSchema, itemId));
  }

  @Put('vault/items/:itemId')
  @AllowSessionAudiences('extension')
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

  /**
   * M27 PR1b's three restore routes, and NONE of them carries `StepUpGuard`.
   *
   * `deleteItem` above is the one item route that does, and the asymmetry is
   * the point rather than an oversight: a step-up between an owner and the
   * recovery of their own data would make the protective action harder than
   * the permissive one. `updateItem` — which destroys the previous content of
   * an item — carries `VaultSessionGuard` alone and is open to the `extension`
   * audience; putting a fresh factor in front of the UNDO of that write while
   * the write itself needs none is the inversion this repo's design rules
   * forbid, in the milestone that exists to close the gap those rules opened.
   *
   * None of the three is admitted to the `extension` audience. That audience
   * is deliberately minimal (`packages/auth-guard/src/session.ts`), and a
   * restore surface is the owner's, not an autofill client's.
   */
  @Get('vault/items/:itemId/versions')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  listVersions(
    @Req() req: VaultRequest,
    @Param('itemId') itemId: string,
    @Query() query: unknown,
  ): Promise<VaultVersionPage> {
    const caller = requireCaller(req);
    return this.vault.listItemVersions(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, itemId),
      parse(ListVersionsQuerySchema, query),
    );
  }

  @Post('vault/items/:itemId/undelete')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  undeleteItem(@Req() req: VaultRequest, @Param('itemId') itemId: string): Promise<VaultItemDto> {
    const caller = requireCaller(req);
    return this.vault.undeleteItem(caller.userId, caller.sessionId, parse(UuidSchema, itemId));
  }

  /**
   * `If-Match` is REQUIRED here and NOT on undelete, and the two are different
   * questions rather than an inconsistency. This overwrites live content, so a
   * stale writer can lose an update through it exactly as through `PUT`.
   * Undelete writes no content onto a row nobody could have been editing.
   */
  @Post('vault/items/:itemId/restore')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  restoreVersion(
    @Req() req: VaultRequest,
    @Param('itemId') itemId: string,
    @Body() body: unknown,
  ): Promise<VaultItemDto> {
    const caller = requireCaller(req);
    return this.vault.restoreItemVersion(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, itemId),
      { ...parse(RestoreVersionSchema, body), ifMatch: ifMatchOf(req) },
    );
  }
}
