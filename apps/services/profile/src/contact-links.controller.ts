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
  ContactLinksService,
  type LinkedEstate,
  type MintedInvitation,
} from './contact-links.service';
import { parse, RedeemLinkSchema, UuidSchema } from './schemas';

/**
 * The contact link ceremony (M13 PR3) — the only write path to
 * `contacts.linked_user_id` in the platform.
 *
 * THE GATES ARE ASYMMETRIC IN BOTH DIRECTIONS, and each asymmetry has a reason:
 *
 *  - MINTING a code is STEP-UP GATED. It hands out a capability whose endpoint
 *    is an authorization edge on the docs/03 §5.1 chain — a linked contact can
 *    open a death case — so it belongs in the same class as naming a fiduciary,
 *    not in the same class as editing a phone number.
 *  - RETIRING an unused code and REMOVING a live link are `CallerGuard` ONLY.
 *    Both take capability away, and the M6 rule is that a protective action must
 *    never be harder than the permissive one. An owner who realises they sent a
 *    code to the wrong person must be able to kill it from whatever session is in
 *    front of them.
 *  - REDEEMING is `CallerGuard` only, and the caller is the person being linked
 *    rather than the owner. The authority is the CODE; there is nothing a step-up
 *    on the redeemer's account would attest to about the owner's estate.
 *
 * REDEMPTION TAKES NO ID AT ALL — not the owner's, not the contact's. The code is
 * the whole request. That is what keeps docs/03 §6b's anti-enumeration property
 * intact: there is no parameter here in which to name an account and therefore no
 * way to learn whether one exists.
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class ContactLinksController {
  constructor(private readonly links: ContactLinksService) {}

  /** Mint a single-use code. The owner is shown it ONCE; only its hash is kept. */
  @Post('contacts/:id/link-invitation')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  invite(@Req() req: CallerRequest, @Param('id') id: string): Promise<MintedInvitation> {
    return this.links.invite(requireCaller(req).userId, parse(UuidSchema, id));
  }

  /** Withdraw an unredeemed code. No step-up: protective. */
  @Delete('contacts/:id/link-invitation')
  @HttpCode(204)
  async revokeInvitation(@Req() req: CallerRequest, @Param('id') id: string): Promise<void> {
    await this.links.revokeInvitation(requireCaller(req).userId, parse(UuidSchema, id));
  }

  /** Remove a live link. No step-up: protective, and see the service. */
  @Delete('contacts/:id/link')
  @HttpCode(204)
  async unlink(@Req() req: CallerRequest, @Param('id') id: string): Promise<void> {
    await this.links.unlink(requireCaller(req).userId, parse(UuidSchema, id));
  }

  /**
   * The estates that name the caller (M22 PR4a). No parameters — there is
   * nowhere to name an estate, only to be named by one.
   */
  @Get('contact-links/estates')
  @HttpCode(200)
  estates(@Req() req: CallerRequest): Promise<LinkedEstate[]> {
    return this.links.estatesNaming(requireCaller(req).userId);
  }

  /**
   * Redeem a code, as the person being linked. Returns `{status:'ok'}` and
   * NOTHING about the estate — not the owner, not the contact's name. The
   * redeemer learned who invited them from the person who handed them the code.
   *
   * THIS USED TO SAY "because a stolen code must not become a read", and M22
   * PR4a made that sentence half true, so it says less now. The RESPONSE still
   * discloses nothing — that part is unchanged and still worth having, because
   * it keeps redemption from being an oracle. But the LINK a redemption creates
   * is enumerable from the route above, so a thief who redeems a stolen code
   * can learn the owner's legal name on the next request.
   *
   * That was accepted rather than overlooked. A stolen code already confers the
   * far heavier capability this whole ceremony is careful about — opening a
   * death case against the owner (docs/03 §6b) — so a name is not the thing
   * standing between a thief and harm. What stands there is unchanged: the
   * owner is NOTIFIED on claim (a production precondition, not a courtesy), and
   * unlinking is one click with no step-up. The control is revocation, not
   * concealment.
   */
  @Post('contact-links/redeem')
  @HttpCode(200)
  async redeem(@Req() req: CallerRequest, @Body() body: unknown): Promise<{ status: string }> {
    await this.links.redeem(requireCaller(req).userId, parse(RedeemLinkSchema, body).code);
    return { status: 'ok' };
  }
}
