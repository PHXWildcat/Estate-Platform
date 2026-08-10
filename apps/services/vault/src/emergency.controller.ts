import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import {
  ConfigureEmergencyAccessSchema,
  parse,
  PublishRecoveryKeySchema,
  UuidSchema,
} from './schemas';
import { VaultSessionGuard } from './vault-session.guard';
import {
  EmergencyAccessService,
  type EscrowDto,
  type GranteePolicyDto,
  type PolicyDto,
  type ReleaseDto,
} from './emergency.service';

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
   * moment the platform half of the recovery key leaves this service, and it
   * happens exactly once per escrow.
   */
  @Post('vault/emergency-access/:policyId/release')
  @HttpCode(200)
  release(@Req() req: CallerRequest, @Param('policyId') policyId: string): Promise<ReleaseDto> {
    const caller = requireCaller(req);
    return this.emergency.release(caller.userId, caller.sessionId, parse(UuidSchema, policyId));
  }
}
