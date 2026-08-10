import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import type { SessionAudience } from '@estate/auth-guard';
import { CLOCK, type Clock } from './di-tokens';
import { EventsService } from './events.service';
import { HandoffsRepo } from './handoffs.repo';
import { SessionsRepo } from './sessions.repo';
import { ACCESS_TOKEN_TTL_MS } from './stepup';
import { generateOpaqueToken, hashToken } from './tokens';

/**
 * How long a handoff code stays redeemable.
 *
 * SIXTY SECONDS, and this is not a usability number. Every other code in this
 * product is retyped by a human — M13's link code travels by phone, M14's
 * verification code by email — so both are measured in minutes or hours
 * against what a person needs. This one is never seen by a person: it is
 * written into a hidden field, submitted by a top-level form POST from the app
 * origin to the vault origin, and redeemed server-side in the same request.
 * The window is therefore pure exposure, and it is set to the smallest value
 * that survives a slow network rather than to anyone's convenience.
 */
export const HANDOFF_TTL_MS = 60 * 1000;

/** 160 bits, the M13/M14 width. */
const HANDOFF_CODE_BYTES = 20;

export interface MintedHandoff {
  readonly code: string;
  readonly expiresAt: Date;
}

export interface RedeemedHandoff {
  readonly accessToken: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly expiresAt: Date;
}

/**
 * THE CROSS-ORIGIN HANDOFF (M15).
 *
 * Zone A lives on an isolated origin (docs/03 TB6). The app origin's session
 * cookies are host-only and are not sent there — measured in a browser, along
 * with the fact that a port-only split would NOT have isolated them — so
 * authority has to cross deliberately, exactly once, in a shape that is worth
 * as little as possible if it leaks.
 *
 * WHAT A STOLEN CODE BUYS, stated plainly because it is the only reason any of
 * the parameters below are what they are:
 *
 *   · 60 seconds to redeem, and the code is burned by the ATTEMPT, so a race
 *     with the legitimate redemption is winner-takes-all rather than both.
 *   · On success, ONE access token, valid 15 minutes, WITH NO REFRESH TOKEN.
 *     The session's `refresh_token_h` is the digest of a value generated here
 *     and immediately discarded, so no refresh token for it exists anywhere to
 *     be presented — the column is NOT NULL, and this is how that constraint is
 *     satisfied without minting a credential nobody should hold. Fifteen
 *     minutes is the whole life of the session; it cannot be extended.
 *   · That token carries the `vault` audience, so it opens the vault service
 *     and is refused by every other service and by all but three of identity's
 *     own routes (see `session-audience.decorator.ts`).
 *   · And it still decrypts nothing. Reaching the vault API is not opening a
 *     vault: that needs the vault password and the Secret Key, neither of
 *     which this platform has ever held.
 *
 * Minting requires a FRESH STEP-UP (the route's StepUpGuard). It does NOT
 * follow that the redeemed session should inherit one, and the M15 review
 * found that giving it one opened a step-up bypass:
 *
 *   `POST /v1/auth/handoff/redeem` is unauthenticated by construction — the
 *   code IS the authority — and `POST /v1/vault/reset` is gated on step-up
 *   ALONE, deliberately, because a lost vault password cannot be proven. So a
 *   redeemed session that arrived step-up-fresh could crypto-shred every item,
 *   the emergency-access escrow and the recovery keypair, with no vault
 *   password and no Secret Key. Script running on the APP origin cannot mint a
 *   handoff (minting is step-up gated) but could read one out of the hidden
 *   field it is posted in — so stealing a code converted app-origin script
 *   with no step-up into step-up authority over Zone A. That is precisely the
 *   boundary this origin exists to create, crossed in the destructive
 *   direction while holding in the confidential one.
 *
 * The redeemed session therefore carries NO step-up. The vault origin proves
 * its own factor when it needs one, through `POST /v1/auth/stepup` — which is
 * one of the three routes a `vault` audience is admitted to, widened in PR1
 * for exactly this and then left unwired. Step-up strengthens the session
 * presenting it and confers nothing else, so this is the design PR1 described
 * rather than a new one. docs/03 TB6 asks for re-auth on vault open; it is
 * paid on the vault origin now, where the user can see what they are
 * authorising.
 */
@Injectable()
export class HandoffService {
  constructor(
    private readonly handoffs: HandoffsRepo,
    private readonly sessions: SessionsRepo,
    private readonly events: EventsService,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  private static digest(code: string): Buffer {
    return createHash('sha256').update(code, 'utf8').digest();
  }

  /**
   * Mint a code for the vault origin. Step-up gated at the route.
   *
   * Retires the caller's outstanding handoff first, so pressing the button
   * twice leaves one live credential rather than two — see `retireLive`.
   */
  async mint(
    userId: string,
    sessionId: string,
    audience: SessionAudience = 'vault',
  ): Promise<MintedHandoff> {
    const now = this.clock();
    // base64url: this value only ever travels inside a form field, so it needs
    // no human-legible alphabet and no canonical fold. What it must not be is
    // shorter than the 160 bits the other ceremonies use.
    const code = randomBytes(HANDOFF_CODE_BYTES).toString('base64url');
    const expiresAt = new Date(now.getTime() + HANDOFF_TTL_MS);

    const retired = await this.handoffs.retireLive(userId, now);
    await this.handoffs.insert({
      userId,
      codeSha256: HandoffService.digest(code),
      audience,
      mintedFrom: sessionId,
      expiresAt,
    });

    await this.events.handoffMinted(userId, sessionId, { audience, retired });
    return { code, expiresAt };
  }

  /**
   * Spend a code for a vault-audience session.
   *
   * UNAUTHENTICATED by construction: the code IS the authority, and there is
   * nowhere in this method to name an account — no user id, no session id, no
   * email. That is what keeps the redeem route from becoming an oracle, and it
   * is the same shape as M13's redemption for the same reason (docs/03 §6g).
   *
   * ONE ANSWER for unknown, expired, already-spent and raced, on the wire AND
   * in the audit trail: the failure event carries no reason and no user, since
   * a trail that named which refusal fired would re-create through the audit
   * stream exactly the oracle the uniform answer removes from the wire (the
   * M14 PR1 rule).
   */
  async redeem(code: string): Promise<RedeemedHandoff> {
    const now = this.clock();
    const handoff = await this.handoffs.claim(HandoffService.digest(code), now);
    if (!handoff) {
      await this.events.handoffFailed();
      throw new UnauthorizedException({ error: 'invalid_code' });
    }

    const accessToken = generateOpaqueToken();
    const sessionId = randomUUID();
    const expiresAt = new Date(now.getTime() + ACCESS_TOKEN_TTL_MS);

    await this.sessions.create({
      id: sessionId,
      userId: handoff.user_id,
      // NEVER ISSUED. `refresh_token_h` is NOT NULL, so the row needs a value;
      // this is the digest of a token that is generated, hashed, and dropped on
      // the floor in the same expression. No refresh token for this session
      // exists to be stolen, and `POST /v1/auth/refresh` therefore cannot
      // extend it — a vault session lives 15 minutes and then it is gone.
      refreshTokenH: hashToken(generateOpaqueToken()),
      accessTokenH: hashToken(accessToken),
      accessExpiresAt: expiresAt,
      // The session dies with its access token rather than outliving it for 30
      // days as an account session does. There is no second credential that
      // could revive it, so a longer `expires_at` would only widen the window
      // in which a leaked access token still resolves.
      expiresAt,
      audience: handoff.audience,
    });
    // NO STEP-UP IS GRANTED HERE. See the class docstring: the code is the only
    // authority on this route, and `POST /v1/vault/reset` is gated on step-up
    // alone, so a step-up-fresh redeemed session let whoever held a stolen code
    // destroy the vault. The vault origin re-proves a factor itself.
    await this.handoffs.recordSession(handoff.id, sessionId);

    await this.events.handoffRedeemed(handoff.user_id, sessionId, { audience: handoff.audience });
    return { accessToken, userId: handoff.user_id, sessionId, expiresAt };
  }
}
