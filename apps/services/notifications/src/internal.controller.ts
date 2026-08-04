import { Body, Controller, HttpCode, Post, Put, UseGuards } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { NotificationsService } from './notifications.service';
import { parseBody, RecipientSchema, SendSchema } from './schemas';

/**
 * Internal-only surface, service-credential-guarded (NOTIFICATIONS_INTERNAL_TOKEN;
 * holders per credential-graph.ts: vault + settlement send, identity feeds the
 * recipient store). There are deliberately NO user-facing routes in this
 * service — a bearer token must never be able to make the platform speak.
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

  @Put('recipients')
  @HttpCode(200)
  upsertRecipient(@Body() body: unknown): Promise<{ ok: true }> {
    return this.notifications.upsertRecipient(parseBody(RecipientSchema, body));
  }
}
