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
import { CallerGuard, requireCaller, type CallerRequest } from '@estate/auth-guard';
import { ContactsService, type ContactSummary, type ContactView } from './contacts.service';
import { ContactSchema, parse, UuidSchema } from './schemas';

/**
 * Contact endpoints. Writes (`/v1/contacts`) are owner-only. The cross-owner
 * reads under `/v1/profiles/:ownerUserId/contacts` are the docs/03 §5.5 ABAC
 * boundary: they return data only when the ProfileAuthz PEP allows — owner, or
 * a role-holder whose effective grant names the resource.
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
