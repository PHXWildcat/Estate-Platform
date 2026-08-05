import { Body, Controller, HttpCode, Post, Put, UseGuards } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { NotificationsService } from './notifications.service';
import { RecipientsCredentialGuard } from './recipients-credential.guard';
import { parseBody, RecipientSchema, SendSchema } from './schemas';

/**
 * Internal-only surface, split into TWO credential-guarded controllers because
 * its routes are two different capabilities with two different legitimate
 * holders (credential-graph.ts). There are deliberately NO user-facing routes
 * in this service — a bearer token must never be able to make the platform
 * speak.
 *
 * SENDING (NOTIFICATIONS_INTERNAL_TOKEN; holders vault + settlement): pick
 * which of nine closed template kinds fires, for a user, now. The wire has no
 * text field, so a holder never chooses the words and never chooses the
 * destination.
 */
@Controller('internal/v1/notifications')
@UseGuards(ServiceCredentialGuard)
export class InternalController {
  constructor(private readonly notifications: NotificationsService) {}

  @Post('send')
  @HttpCode(200)
  send(@Body() body: unknown): Promise<{ delivered: boolean; channel: string }> {
    return this.notifications.send(parseBody(SendSchema, body));
  }
}

/**
 * RECIPIENTS (NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN; holder identity ALONE):
 * set the address a user's notifications are delivered to.
 *
 * Separated from sending by the M9 security review. This route decides where
 * every future owner alert lands, so holding it is the power to silence the
 * §5.1 death-case sweep and the §5.2 emergency-access waiting period by
 * pointing them at a mailbox the owner never reads. Identity is the only
 * service that legitimately knows an address — it watches the user type it at
 * registration and login — and it is the only holder.
 */
@Controller('internal/v1/notifications')
@UseGuards(RecipientsCredentialGuard)
export class RecipientsController {
  constructor(private readonly notifications: NotificationsService) {}

  @Put('recipients')
  @HttpCode(200)
  upsertRecipient(@Body() body: unknown): Promise<{ ok: true }> {
    return this.notifications.upsertRecipient(parseBody(RecipientSchema, body));
  }
}
