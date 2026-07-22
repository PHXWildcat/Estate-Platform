import { Controller, HttpCode, Post, Req, UnauthorizedException } from '@nestjs/common';
import { EventsService } from './events.service';
import { PlaidService } from './plaid.service';
import { WebhookBody } from './schemas';
import { WebhookVerifier } from './webhook-verifier';

/** The slice of the express request the webhook route reads. */
interface WebhookRequest {
  headers: Record<string, string | string[] | undefined>;
  /** Exact bytes of the request body (NestFactory { rawBody: true }). */
  rawBody?: Buffer;
  body?: unknown;
}

/**
 * Plaid's inbound webhook. Deliberately OUTSIDE CallerGuard — the caller is
 * Plaid, not a user — so signature verification is the entire trust decision:
 * an unverifiable request is audited and answered 401 with no detail. A
 * verified body is still untrusted DATA (blind-index lookup, unknown items
 * ignored, unknown codes ignored), and the response is always shapeless so
 * the endpoint cannot be used as an item-existence oracle.
 */
@Controller('v1/plaid')
export class WebhookController {
  constructor(
    private readonly verifier: WebhookVerifier,
    private readonly service: PlaidService,
    private readonly events: EventsService,
  ) {}

  @Post('webhook')
  @HttpCode(204)
  async receive(@Req() req: WebhookRequest): Promise<void> {
    const jwtHeader = req.headers['plaid-verification'];
    const jwt = Array.isArray(jwtHeader) ? jwtHeader[0] : jwtHeader;
    const verdict = await this.verifier.verify(jwt, req.rawBody ?? Buffer.alloc(0));
    if (!verdict.valid) {
      await this.events.webhookRejected(verdict.reason);
      // 401 with no body detail: reject reasons live in the audit stream only.
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    const parsed = WebhookBody.safeParse(req.body);
    if (!parsed.success) {
      return; // verified but shapeless — ignore silently (204)
    }
    await this.service.handleWebhook({
      webhookCode: parsed.data.webhook_code,
      plaidItemId: parsed.data.item_id,
    });
  }
}
