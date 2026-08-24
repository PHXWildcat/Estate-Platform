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
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import {
  ConfigureEmergencyAccessSchema,
  ListItemsQuerySchema,
  parse,
  PublishRecoveryKeySchema,
  UuidSchema,
} from './schemas';
import { VaultSessionGuard, type VaultRequest } from './vault-session.guard';
import {
  EmergencyAccessService,
  type EscrowDto,
  type GranteePolicyDto,
  type PolicyDto,
  type ReleaseDto,
} from './emergency.service';
import type { VaultItemPage } from './vault.service';

/**
 * Emergency access (docs/03 §5.2).
 *
 * The guard pattern here encodes the threat model rather than a uniform policy:
 *
 *  - Owner actions that arm or widen access - publishing a key, configuring an
 *    escrow, re-arming a denied policy, revoking one - are step-up gated,
 *    because docs/01 §5 lists emergency-access configuration as a mandatory
 *    step-up action.
 *  - **Denial is CallerGuard only, on purpose.** It has to be one tap from a
 *    push notification, possibly on a locked phone, possibly by someone elderly
 *    and alarmed. A step-up challenge standing between an owner and "no" would
 *    be a control that defeats itself.
 *  - Grantee actions are authorized by designation, recorded on the policy row,
 *    not by Cedar - the grantee is deliberately not the resource owner.
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class EmergencyAccessController {
  constructor(private readonly emergency: EmergencyAccessService) {}

  /** Publish this user's public key so others can name them as a contact. */
  @Post('vault/recovery-key')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  publishRecoveryKey(
    @Req() req: CallerRequest,
    @Body() body: unknown,
  ): Promise<{ published: boolean }> {
    const caller = requireCaller(req);
    return this.emergency.publishRecoveryKey(
      caller.userId,
      caller.sessionId,
      parse(PublishRecoveryKeySchema, body),
    );
  }

  /**
   * The caller's OWN recovery keypair (M15 PR3), so a grantee can open a share
   * that was sealed to them. Behind an OPEN VAULT: the private half is wrapped
   * under the caller's master key, so a session alone is not enough to use it
   * and should not be enough to fetch it either.
   */
  @Get('vault/recovery-key')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  ownRecoveryKey(
    @Req() req: CallerRequest,
  ): Promise<{ publicKey: string; wrappedPrivateKey: string }> {
    return this.emergency.ownRecoveryKey(requireCaller(req).userId);
  }

  /**
   * Fetch a prospective grantee's public key. The owner's client must confirm
   * the fingerprint out of band before sealing a share to it.
   */
  @Get('vault/recovery-key/:granteeUserId')
  @HttpCode(200)
  granteePublicKey(
    @Req() req: CallerRequest,
    @Param('granteeUserId') granteeUserId: string,
  ): Promise<{ granteeUserId: string; publicKey: string }> {
    return this.emergency.granteePublicKey(
      requireCaller(req).userId,
      parse(UuidSchema, granteeUserId),
    );
  }

  @Get('vault/emergency-access')
  @HttpCode(200)
  describe(@Req() req: CallerRequest): Promise<EscrowDto> {
    return this.emergency.describe(requireCaller(req).userId);
  }

  @Post('vault/emergency-access')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  configure(@Req() req: CallerRequest, @Body() body: unknown): Promise<EscrowDto> {
    const caller = requireCaller(req);
    return this.emergency.configure(
      caller.userId,
      caller.sessionId,
      parse(ConfigureEmergencyAccessSchema, body),
    );
  }

  /** What this caller has been designated for, by other people. */
  @Get('vault/emergency-access/granted-to-me')
  @HttpCode(200)
  grantedToMe(@Req() req: CallerRequest): Promise<readonly GranteePolicyDto[]> {
    return this.emergency.listForGrantee(requireCaller(req).userId);
  }

  /** A grantee starts the waiting period. Grants nothing by itself. */
  @Post('vault/emergency-access/:policyId/request')
  @HttpCode(200)
  request(@Req() req: CallerRequest, @Param('policyId') policyId: string): Promise<PolicyDto> {
    const caller = requireCaller(req);
    return this.emergency.request(caller.userId, caller.sessionId, parse(UuidSchema, policyId));
  }

  /**
   * The owner stops it. No step-up: see the class docstring - this is the
   * one-tap deny docs/03 §5.2 asks for.
   */
  @Post('vault/emergency-access/:policyId/deny')
  @HttpCode(200)
  deny(@Req() req: CallerRequest, @Param('policyId') policyId: string): Promise<PolicyDto> {
    const caller = requireCaller(req);
    return this.emergency.deny(caller.userId, caller.sessionId, parse(UuidSchema, policyId));
  }

  /** Clear a denial. Widening access again, so step-up applies. */
  @Post('vault/emergency-access/:policyId/rearm')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  rearm(@Req() req: CallerRequest, @Param('policyId') policyId: string): Promise<PolicyDto> {
    const caller = requireCaller(req);
    return this.emergency.rearm(caller.userId, caller.sessionId, parse(UuidSchema, policyId));
  }

  @Delete('vault/emergency-access/:policyId')
  @UseGuards(StepUpGuard)
  @HttpCode(204)
  revoke(@Req() req: CallerRequest, @Param('policyId') policyId: string): Promise<void> {
    const caller = requireCaller(req);
    return this.emergency.revoke(caller.userId, caller.sessionId, parse(UuidSchema, policyId));
  }

  /**
   * The grantee collects the escrow material after the waiting period. The only
   * moment the platform half of the recovery key leaves this service.
   *
   * REPEATABLE since M27 PR3a. This docstring used to end by promising the
   * collection happened a single time per escrow, and it was corrected here
   * only after the identical sentence had been fixed on the service method it
   * calls — the same rule half-applied that this PR kept finding, arriving
   * once more between a route and its handler. `EmergencyService.release`
   * admits `status IN ('waiting','released')`; nothing about that is visible
   * from this file, which is exactly why the sentence rotted.
   */
  @Post('vault/emergency-access/:policyId/release')
  @HttpCode(200)
  release(@Req() req: CallerRequest, @Param('policyId') policyId: string): Promise<ReleaseDto> {
    const caller = requireCaller(req);
    return this.emergency.release(caller.userId, caller.sessionId, parse(UuidSchema, policyId));
  }

  /**
   * THE READING SURFACE (M27 PR3b): a released grantee reads the owner's live
   * items. Everything about what may pass is decided in
   * `EmergencyAccessService.listItemsForGrantee`; the two facts that live HERE
   * are the guard and the audience.
   *
   * `VaultSessionGuard` — the GRANTEE'S OWN vault session, not the owner's.
   * The guard is unchanged and unwidened: it proves the caller unlocked their
   * own vault, which is a bar an attacker holding only an account session
   * cannot clear, and the authority to read somebody ELSE's rows comes from
   * the policy row instead (docs/03 §6uu).
   *
   * NO `@AllowSessionAudiences('extension')`, unlike the owner's own
   * `vault/items`. The browser extension exists to fill the caller's own
   * credentials; there is no autofill story for an estate you are recovering,
   * and an emergency collection is the last capability that should be
   * reachable from a surface with that much page contact.
   *
   * NO `StepUpGuard`. Opening the grantee's own vault already required a fresh
   * step-up, and the collection this read depends on required the full §5.2
   * ceremony — a waiting period the owner could interrupt. Adding another
   * factor here would put the heaviest gate in front of the person acting for
   * an owner who cannot act, which is the one moment the ceremony is FOR.
   *
   * AND THERE IS NO SINGLE-ITEM SIBLING, unlike the owner's own surface. One
   * was written and removed before this shipped, because the route↔consumer
   * fence reported it had no caller and the honest reading of that was not
   * "wire one up". The list serves every blob, and the grantee's client opens
   * them all on arrival — so by the time any detail screen renders, the
   * content has already left the server. A per-item route would therefore emit
   * a `vault.emergency.items_read` event meaning "opened item X" for a read
   * that had already happened, which is an audit trail that overstates what it
   * knows on the one surface where the owner needs it to be exact. Prefer the
   * absence: the route you never added cannot lie.
   */
  @Get('vault/emergency-access/:policyId/items')
  @UseGuards(VaultSessionGuard)
  @HttpCode(200)
  granteeItems(
    @Req() req: VaultRequest,
    @Param('policyId') policyId: string,
    @Query() query: unknown,
  ): Promise<VaultItemPage> {
    const caller = requireCaller(req);
    return this.emergency.listItemsForGrantee(
      caller.userId,
      caller.sessionId,
      parse(UuidSchema, policyId),
      parse(ListItemsQuerySchema, query),
    );
  }
}
