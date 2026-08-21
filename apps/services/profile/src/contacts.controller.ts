import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  AllowSessionAudiences,
  CallerGuard,
  requireCaller,
  type CallerRequest,
} from '@estate/auth-guard';
import {
  ContactsService,
  type ContactSummary,
  type ContactView,
  type GranteeCandidate,
} from './contacts.service';
import { ContactSchema, parse, UuidSchema } from './schemas';

/** Raw bearer token, re-extracted for forwarding to settlement. CallerGuard
 * already validated the header shape; '' only means a wiring anomaly and fails
 * closed inside the settlement client. Same helper, same words, as
 * `assets.controller.ts` — the two forward to the same route. */
function bearerTokenOf(req: CallerRequest): string {
  const raw = req.headers['authorization'];
  const header = Array.isArray(raw) ? raw[0] : raw;
  return typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
}

/**
 * Contact endpoints. Writes (`/v1/contacts`) are owner-only. The cross-owner
 * reads under `/v1/profiles/:ownerUserId/contacts` are the docs/03 §5.5 ABAC
 * boundary: they return data only when the ProfileAuthz PEP allows — owner, or
 * a role-holder whose effective grant names the resource.
 *
 * `/v1/estates/:ownerUserId/contacts` is a THIRD thing and deliberately not on
 * either path above: a different authority (settlement's staged grant, not a
 * permission grant), a different audit action, and a different reason to
 * exist. Assets made the same split for the same reason — merging a non-owner
 * branch into the owner path is how one route ends up carrying two
 * authorization models.
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class ContactsController {
  constructor(private readonly contacts: ContactsService) {}

  @Post('contacts')
  @HttpCode(201)
  createContact(@Req() req: CallerRequest, @Body() body: unknown): Promise<{ id: string }> {
    return this.contacts.create(requireCaller(req).userId, parse(ContactSchema, body));
  }

  /**
   * The caller's OWN contacts, owner-relative — no id in the path.
   *
   * `/v1/profiles/:ownerUserId/contacts` below is the CROSS-owner ABAC route and
   * always was; using it for "my contacts" would make every client discover and
   * send its own user id to ask a question that is only ever about itself. The
   * rest of this service is already owner-relative (`GET /v1/profile`,
   * `GET /v1/profile/family`, `GET /v1/role-assignments`, and the `/v1/contacts`
   * writes right here) — contacts was the odd one out because one route doubled
   * as the §5.5 demonstrator. Same service method, same PEP, caller as owner.
   */
  @Get('contacts')
  @HttpCode(200)
  listOwnContacts(@Req() req: CallerRequest): Promise<ContactSummary[]> {
    const { userId } = requireCaller(req);
    return this.contacts.listForOwner(userId, userId);
  }

  /**
   * THE ONE PROFILE ROUTE A `vault` SESSION MAY REACH (M15 PR3).
   *
   * Zone A's emergency-access ceremony runs on an isolated origin holding a
   * `vault`-audience session, and choosing a grantee needs contact names — so
   * some contact data has to cross. Widening profile SERVICE-WIDE would have
   * handed a leaked vault handoff the owner's PII, every contact's decrypted
   * detail, the family tree and the role assignments; this widens ONE route
   * whose entire response is a contact id, an account id and a name.
   *
   * Declared in `AUDIENCE_ROUTE_ADMITTERS` and checked against this decorator
   * in both directions, so neither the table nor the route can drift alone.
   *
   * Declared BEFORE `contacts/:id` so the literal path is not captured as an id.
   */
  @Get('contacts/grantee-candidates')
  @AllowSessionAudiences('vault')
  @HttpCode(200)
  granteeCandidates(@Req() req: CallerRequest): Promise<GranteeCandidate[]> {
    return this.contacts.granteeCandidates(requireCaller(req).userId);
  }

  /** One of the caller's own contacts, decrypted in full. An audited decrypt. */
  @Get('contacts/:id')
  @HttpCode(200)
  getOwnContact(@Req() req: CallerRequest, @Param('id') id: string): Promise<ContactView> {
    const { userId } = requireCaller(req);
    return this.contacts.getOne(userId, userId, parse(UuidSchema, id));
  }

  @Put('contacts/:id')
  @HttpCode(200)
  async updateContact(
    @Req() req: CallerRequest,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<{ status: string }> {
    await this.contacts.update(
      requireCaller(req).userId,
      parse(UuidSchema, id),
      parse(ContactSchema, body),
    );
    return { status: 'ok' };
  }

  @Delete('contacts/:id')
  @HttpCode(204)
  async deleteContact(@Req() req: CallerRequest, @Param('id') id: string): Promise<void> {
    await this.contacts.remove(requireCaller(req).userId, parse(UuidSchema, id));
  }

  /**
   * ABAC list: owner sees all; a grant-holder sees only granted contacts.
   *
   * SUMMARIES, not full contacts — one audited decrypt per row instead of five.
   * See `ContactSummary`; the per-contact detail read below is where email,
   * phone, address and notes come from, one deliberate read at a time.
   */
  @Get('profiles/:ownerUserId/contacts')
  @HttpCode(200)
  listOwnerContacts(
    @Req() req: CallerRequest,
    @Param('ownerUserId') ownerUserId: string,
  ): Promise<ContactSummary[]> {
    return this.contacts.listForOwner(requireCaller(req).userId, parse(UuidSchema, ownerUserId));
  }

  /**
   * THE ESTATE'S CONTACTS, for a verified executor (M23 PR4a).
   *
   * The path says `estates`, not `profiles`, because the subject is an estate
   * under administration rather than a living person's profile — the same
   * distinction `GET /v1/estates/:ownerUserId/assets` draws in the assets
   * service, which is the route this one is modelled on down to the bearer
   * forwarding.
   *
   * NO `@AllowSessionAudiences`: the service-wide `account` is right. An
   * operator has no business in a decedent's address book, and there is no
   * console surface that asks.
   *
   * NO STEP-UP. It is a read, and a read that an operator has already reviewed
   * and approved as a whole rung — putting a second factor in front of it would
   * gate the same disclosure twice while leaving the first gate's decision
   * untouched.
   */
  @Get('estates/:ownerUserId/contacts')
  @HttpCode(200)
  listEstateContacts(
    @Req() req: CallerRequest,
    @Param('ownerUserId') ownerUserId: string,
  ): Promise<ContactSummary[]> {
    return this.contacts.listEstateContacts(
      requireCaller(req).userId,
      bearerTokenOf(req),
      parse(UuidSchema, ownerUserId),
    );
  }

  /** ABAC single read: allowed only for the owner or a named grant-holder. */
  @Get('profiles/:ownerUserId/contacts/:contactId')
  @HttpCode(200)
  getOwnerContact(
    @Req() req: CallerRequest,
    @Param('ownerUserId') ownerUserId: string,
    @Param('contactId') contactId: string,
  ): Promise<ContactView> {
    return this.contacts.getOne(
      requireCaller(req).userId,
      parse(UuidSchema, ownerUserId),
      parse(UuidSchema, contactId),
    );
  }
}
