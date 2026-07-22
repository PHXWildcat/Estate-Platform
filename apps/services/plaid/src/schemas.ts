import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

/** Parse a request body; validation failure is a generic 400 (no echo). */
export function parseBody<T extends z.ZodTypeAny>(schema: T, body: unknown): z.infer<T> {
  const result = schema.safeParse(body);
  if (!result.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return result.data as z.infer<T>;
}

export const LinkItemBody = z.object({
  publicToken: z.string().min(1).max(256),
});

/**
 * The verified webhook body's shape — parsed only AFTER signature
 * verification, and still treated as untrusted data (unknown fields dropped,
 * item resolved via blind index, unknown items ignored).
 */
export const WebhookBody = z.object({
  webhook_type: z.string().min(1).max(64),
  webhook_code: z.string().min(1).max(64),
  item_id: z.string().min(1).max(128),
});
