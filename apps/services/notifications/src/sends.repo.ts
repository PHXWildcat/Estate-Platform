import { Injectable } from '@nestjs/common';
import { Db } from './db';

/**
 * `sent` means delivered to an address the user PROVED they own;
 * `sent_unverified` means delivered to one they never confirmed (M14). Both are
 * deliveries — the distinction is evidence for a §5.1 investigation, not a
 * transport outcome a caller should retry on.
 */
export type SendOutcomeToken = 'sent' | 'sent_unverified' | 'no_recipient' | 'carrier_failure';

/**
 * Append-only send log: ids and enums only — never an address, never content
 * (docs/01 Zone C "notifications metadata"). REVOKE UPDATE/DELETE in the DDL.
 */
@Injectable()
export class SendsRepo {
  constructor(private readonly db: Db) {}

  async record(input: {
    userId: string;
    kind: string;
    requestedChannel: string;
    channel: string;
    outcome: SendOutcomeToken;
    providerMessageId: string | null;
  }): Promise<string> {
    const rows = await this.db.query<{ id: string }>(
      `INSERT INTO notification_sends
         (user_id, kind, requested_channel, channel, outcome, provider_message_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [
        input.userId,
        input.kind,
        input.requestedChannel,
        input.channel,
        input.outcome,
        input.providerMessageId,
      ],
    );
    if (!rows[0]) {
      throw new Error('notification_sends insert returned no row');
    }
    return rows[0].id;
  }
}
