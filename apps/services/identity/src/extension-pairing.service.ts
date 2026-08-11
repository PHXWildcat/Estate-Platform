import { randomUUID } from 'node:crypto';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { CLOCK, type Clock } from './di-tokens';
import { EventsService } from './events.service';
import { ExtensionPairingsRepo } from './extension-pairings.repo';
import { canonicalCode, canonicalLengthFor, readableCode, sha256 } from './readable-code';
import { SessionsRepo } from './sessions.repo';
import { ACCESS_TOKEN_TTL_MS, SESSION_TTL_MS } from './stepup';
import { generateOpaqueToken, hashToken } from './tokens';

/** This ceremony's prefix. Constant, so it folds identically for every code. */
const EP_PREFIX = 'EP1-';

/** What a minted pairing code folds to. Checked before any lookup. */
export const CANONICAL_PAIRING_CODE_LENGTH = canonicalLengthFor(EP_PREFIX);

/**
 * How long a pairing code stays redeemable.
 *
 * TEN MINUTES, and the number comes from the journey rather than from a policy.
 * This code is read off the Estate web app and typed into an extension popup in
 * one sitting; it does not travel by mailbox (M14's is 30 minutes) or by phone
 * call (M13's is measured in days). It is also not M15's sixty seconds, because
 * a person is in the loop — that window is for a code no human ever sees.
 */
export const PAIRING_TTL_MS = 10 * 60 * 1000;

export interface MintedPairing {
  readonly code: string;
  readonly expiresAt: Date;
}

export interface PairedExtension {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly expiresAt: Date;
}

/**
 * EXTENSION PAIRING (M16).
 *
 * WHERE THIS RUNS, because it is the decision that changed during planning. The
 * mint is an APP-ORIGIN ceremony under a fresh step-up, not a vault-origin one.
 * The vault edge allowlists three exact identity routes and deliberately
 * excludes `/v1/auth/handoff` so that a vault session cannot mint another
 * credential — "a leaked one cannot chain itself forward". Minting here from
 * the vault origin would need that allowlist widened and would make the
 * sentence false, chaining a 15-minute no-refresh session into a 30-day
 * refreshing one, which is the M15 PR4 shape re-committed. So the route is
 * account-audience only, exactly like `mintHandoff`.
 *
 * A TYPED CODE RATHER THAN A CHANNEL. The browser can hand a page's value to an
 * extension through `externally_connectable`, and that was rejected: for a
 * ceremony performed once per browser, the control is an ABSENCE. A typed code
 * leaves no permanent page-to-extension channel for any script on the origin to
 * address, and puts no extension id into the app's configuration.
 *
 * WHAT A STOLEN PAIRING CODE BUYS, stated because it is the only reason the
 * parameters are what they are. Ten minutes, single use, burned on the ATTEMPT.
 * On success: an `extension`-audience session, which reaches five vault routes
 * and three identity ones and NOTHING ELSE — it cannot reset a vault, replace a
 * keyset, delete an item, touch emergency access, or mint another handoff. And
 * it still decrypts nothing: every item read sits behind `VaultSessionGuard`,
 * which only a completed SRP unlock satisfies, and that needs the vault
 * password and the device Secret Key, neither of which this platform holds.
 * Script on the app origin can read the code out of the DOM it is displayed in
 * — the residual recorded in docs/03 §6j — and what it gets is that.
 *
 * ONE ANSWER FOR EVERY FAILURE, on the wire and in the trail. Unknown, expired,
 * already spent, revoked, raced and mis-shaped are one `invalid_code`, and the
 * failure event carries no user and no reason, because a trail that separated
 * them would re-create through the audit stream the oracle the uniform answer
 * removes from the wire (the M14 PR1 rule).
 */
@Injectable()
export class ExtensionPairingService {
  constructor(
    private readonly pairings: ExtensionPairingsRepo,
    private readonly sessions: SessionsRepo,
    private readonly events: EventsService,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * Mint a pairing code. Step-up gated at the route, account audience only.
   *
   * Retires the caller's outstanding pairing first, so pressing the button
   * twice leaves ONE live credential rather than two — and unconditionally, so
   * a lapsed row can never wedge the slot (see `retireLive`).
   */
  async mint(userId: string, sessionId: string): Promise<MintedPairing> {
    const now = this.clock();
    const code = readableCode(EP_PREFIX);
    const expiresAt = new Date(now.getTime() + PAIRING_TTL_MS);

    const retired = await this.pairings.retireLive(userId, now);
    await this.pairings.insert({
      userId,
      // The CANONICAL form is hashed, so a code retyped the way a human retypes
      // it — lowercase, dashes dropped, an O for a zero — still resolves.
      codeSha256: sha256(canonicalCode(code)),
      mintedFrom: sessionId,
      expiresAt,
    });

    await this.events.extensionPairingMinted(userId, sessionId, retired);
    return { code, expiresAt };
  }

  /**
   * Spend a code for an `extension`-audience session.
   *
   * UNAUTHENTICATED by construction: the code IS the authority and there is
   * nowhere in this method to name an account. The session it creates carries a
   * REAL refresh token, unlike the vault handoff's — that is the whole
   * difference between the two ceremonies, and it is why the audience is
   * admitted per handler to a set that yields ciphertext and cannot destroy.
   *
   * NO STEP-UP IS GRANTED, for the reason the M15 review established: an
   * unauthenticated redeem route must not produce a step-up-fresh session,
   * because `POST /v1/vault/reset` is gated on step-up ALONE. The extension
   * proves its own factor through `POST /v1/auth/stepup` when it needs one —
   * which it does on every unlock, both SRP legs being step-up gated.
   */
  async redeem(code: string): Promise<PairedExtension> {
    const now = this.clock();
    const canonical = canonicalCode(code);
    if (canonical.length !== CANONICAL_PAIRING_CODE_LENGTH) {
      // Measured on the CANONICAL form, never the raw submission — M13 round 3
      // found a `min(8)` bound that separators alone satisfied while folding to
      // nothing. Refused before any lookup, with the same uniform answer, so
      // the shape check is not itself a distinguisher.
      await this.events.extensionPairingFailed();
      throw new UnauthorizedException({ error: 'invalid_code' });
    }

    const pairing = await this.pairings.claim(sha256(canonical), now);
    if (!pairing) {
      await this.events.extensionPairingFailed();
      throw new UnauthorizedException({ error: 'invalid_code' });
    }

    const accessToken = generateOpaqueToken();
    const refreshToken = generateOpaqueToken();
    const sessionId = randomUUID();

    await this.sessions.create({
      id: sessionId,
      userId: pairing.user_id,
      refreshTokenH: hashToken(refreshToken),
      accessTokenH: hashToken(accessToken),
      accessExpiresAt: new Date(now.getTime() + ACCESS_TOKEN_TTL_MS),
      /*
       * THIRTY DAYS, and it is a HARD CAP rather than a sliding one.
       * `rotateTokens` does not write `expires_at`, so refreshing rotates the
       * tokens on this row and cannot extend its life — a paired extension
       * therefore expires and must be re-paired, which costs a fresh step-up on
       * the app origin. Matching the account session's existing lifetime keeps
       * one number in the product rather than two, and this credential is
       * weaker than an account session in every other respect.
       */
      expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
      audience: 'extension',
    });
    await this.pairings.recordSession(pairing.id, sessionId);

    await this.events.extensionPaired(pairing.user_id, sessionId);
    return {
      accessToken,
      refreshToken,
      userId: pairing.user_id,
      sessionId,
      expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
    };
  }
}
