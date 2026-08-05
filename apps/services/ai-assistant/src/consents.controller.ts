import {
  BadRequestException,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import { isConsentScope, type ConsentScope } from './consent';
import { ConsentsRepo } from './consents.repo';
import { Db } from './db';
import { EventsService } from './events.service';

/** What every route here answers with: the caller's live grants, sorted. */
export interface ConsentsDto {
  granted: ConsentScope[];
}

/**
 * Per-feature consent for the AI assistant (docs/01 §2.8, docs/03 §4 TB5:
 * "per-feature user consent flags"). Three routes, and the asymmetry between
 * two of them is the design.
 *
 * GRANTING IS STEP-UP GATED. A grant widens what estate data may leave the
 * platform for a third-party model provider — that is data egress, and docs/01
 * §5 lists data export among the actions requiring a fresh (≤5 min) step-up.
 * The threat it answers is concrete: an attacker holding a stolen bearer token
 * could otherwise grant `assistant.documents.content` to themselves and read a
 * user's will through the conversation surface, turning a session theft into an
 * estate disclosure without ever touching the documents service's own gates.
 *
 * REVOKING IS NOT. The asymmetry is deliberate and follows the M6
 * emergency-access denial precedent verbatim: denial "is the one owner action
 * deliberately NOT step-up gated — it must be one tap". THE PROTECTIVE ACTION
 * MUST NEVER BE HARDER THAN THE PERMISSIVE ONE. A user who suspects something
 * is wrong must be able to shut the assistant's access off immediately, from
 * whatever session they have in front of them, without finding their
 * authenticator; requiring a step-up to switch a capability OFF only ever
 * protects the attacker's grant. The worst an attacker achieves with the
 * asymmetry is revoking a consent — which costs the user a re-grant and denies
 * the attacker the same data.
 *
 * Revoking `assistant.enabled` alone turns everything off, because `permits`
 * requires the master switch in addition to the specific scope — the one-tap
 * kill switch is a property of `consent.ts`, not something this controller has
 * to assemble.
 *
 * The transaction is opened here rather than behind a service class: each route
 * is one repo call plus its audit event, and a service that only forwarded them
 * would be a file with no decision in it. The ORDER is the part with a rule
 * behind it — the audit event is emitted after the commit, so no event ever
 * asserts a consent change that rolled back (the M9 ordering rule applied to
 * append-only evidence).
 */
@Controller('v1/consents')
@UseGuards(CallerGuard)
export class ConsentsController {
  constructor(
    private readonly db: Db,
    private readonly consents: ConsentsRepo,
    private readonly events: EventsService,
  ) {}

  @Get()
  @HttpCode(200)
  list(@Req() req: CallerRequest): Promise<ConsentsDto> {
    return this.read(requireCaller(req).userId);
  }

  /**
   * Grant a scope. `@UseGuards(CallerGuard, StepUpGuard)` restates the class
   * guard on purpose: this is the one route in the service whose authorization
   * differs from every other, and it should read completely on its own line
   * rather than by subtracting the class decorator. CallerGuard running twice
   * costs nothing — the session verifier's short-TTL positive cache answers the
   * second call — and StepUpGuard needs the context the first one attaches.
   */
  @Put(':scope')
  @UseGuards(CallerGuard, StepUpGuard)
  @HttpCode(200)
  async grant(@Req() req: CallerRequest, @Param('scope') scope: string): Promise<ConsentsDto> {
    const userId = requireCaller(req).userId;
    const known = this.knownScope(scope);
    // The owner grants for themselves; there is no delegated path into this
    // service, so granted_by is always the caller.
    const changed = await this.db.withTransaction(userId, (tx) =>
      this.consents.grant(tx, userId, known, userId),
    );
    if (changed) {
      // A no-op re-grant of a live scope is not a consent change and is not
      // audited as one — the repo's partial unique index makes that answerable.
      await this.events.consentGranted(userId, { scope: known });
    }
    return this.read(userId);
  }

  /** Revoke a scope. CallerGuard only — see the class comment. */
  @Delete(':scope')
  @HttpCode(200)
  async revoke(@Req() req: CallerRequest, @Param('scope') scope: string): Promise<ConsentsDto> {
    const userId = requireCaller(req).userId;
    const known = this.knownScope(scope);
    const changed = await this.db.withTransaction(userId, (tx) =>
      this.consents.revoke(tx, userId, known, userId),
    );
    if (changed) {
      await this.events.consentRevoked(userId, { scope: known });
    }
    return this.read(userId);
  }

  /**
   * Narrow the path parameter against the closed vocabulary BEFORE the database
   * is touched. The CHECK constraint would refuse an unknown scope anyway, but
   * as a 500 from a rolled-back transaction rather than as a 400 — and a
   * constraint violation is a poor place to learn that a client is sending a
   * scope this build does not know about.
   */
  private knownScope(scope: string): ConsentScope {
    if (!isConsentScope(scope)) {
      throw new BadRequestException({ error: 'unknown_scope' });
    }
    return scope;
  }

  /** Read back the committed state, so a client never renders an optimistic grant. */
  private async read(userId: string): Promise<ConsentsDto> {
    const granted = await this.consents.grantedScopes(userId);
    return { granted: [...granted].sort() };
  }
}
