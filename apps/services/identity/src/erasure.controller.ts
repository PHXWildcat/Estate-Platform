import { Controller, Delete, Get, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import { ErasureService, type ErasureState } from './erasure.service';
import { requireAuth, SessionGuard, type AuthedRequest } from './session.guard';
import { StepUpGuard } from './stepup.guard';

/**
 * Account erasure, the owner's own ceremony (M25 PR2).
 *
 * ACCOUNT AUDIENCE ONLY — undecorated, which is deny by default. A vault,
 * extension or operator session must not be able to reach the verb that marks
 * an account for destruction: the vault origin's script-src is the weaker one
 * (M11), the extension lives in a browser this platform does not control, and
 * an operator erasing somebody's account is a capability M25 deliberately does
 * not ship (docs/03 §6kk).
 *
 * THE ASYMMETRY IS THE CONTROL, and it is written here as well as in the
 * service because a reviewer reads the decorators first. `POST` carries
 * `StepUpGuard`; `DELETE` does not. That is the repo's rule — the protective
 * action must never be harder than the permissive one — in the shape it takes
 * when the permissive action is the destructive one. An owner who armed this by
 * accident, or whose session was briefly taken, must be able to disarm it with
 * nothing but the session they already have.
 *
 * NO CONSUMER YET. These three routes are declared in the route↔consumer fence
 * with an exemption naming M25 PR4, which builds the surface. The fence's own
 * discipline is that the exemption goes away in the same change as the first
 * caller.
 */
@Controller('v1/account/erasure')
export class ErasureController {
  constructor(private readonly erasure: ErasureService) {}

  /** The caller's live request, or null. Ungated beyond the session: reading
   *  whether you asked to be erased must not itself need a factor. */
  @Get()
  @UseGuards(SessionGuard)
  async get(@Req() request: AuthedRequest): Promise<{ erasure: ErasureState | null }> {
    const auth = requireAuth(request);
    return { erasure: await this.erasure.get(auth.userId) };
  }

  /**
   * Ask for the account to be erased. Step-up fresh ≤5 min (docs/01 §5 names
   * deletion requests explicitly). Idempotent — a second press answers with the
   * request the first one made.
   */
  @Post()
  @HttpCode(201)
  @UseGuards(SessionGuard, StepUpGuard)
  async request(@Req() request: AuthedRequest): Promise<{ erasure: ErasureState }> {
    const auth = requireAuth(request);
    return { erasure: await this.erasure.request(auth.userId, auth.sessionId) };
  }

  /**
   * Withdraw the request. NO `StepUpGuard`, and that is not an omission — see
   * the class docstring. Safe to press twice.
   *
   * ANSWERS WHAT IS STILL OUTSTANDING (M25 PR3). `null` means nothing is live —
   * either the request was withdrawn or there was none, and a client has no
   * reason to tell those apart. A STATE means the cancel did not take, which
   * since PR3 has exactly one cause: the driver has claimed the request and is
   * destroying keys. Reporting it as data rather than as a second error token
   * keeps the protective verb ungated and non-failing while still refusing to
   * tell an owner "withdrawn" about an erasure already in progress.
   */
  @Delete()
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async cancel(@Req() request: AuthedRequest): Promise<{ erasure: ErasureState | null }> {
    const auth = requireAuth(request);
    return { erasure: await this.erasure.cancel(auth.userId, auth.sessionId) };
  }
}
