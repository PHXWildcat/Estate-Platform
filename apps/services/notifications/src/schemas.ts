import { BadRequestException } from '@nestjs/common';
import { NOTIFICATION_CHANNELS, NOTIFICATION_KINDS } from '@estate/notifications-client';
import { z } from 'zod';

/** Payloads are ids, enums, a timestamp, and (on upsert) one address. */
export const BODY_LIMIT = '64kb';

/**
 * The send wire: content-free BY SCHEMA. `.strict()` means a caller that
 * tries to smuggle a subject, a body, or a template variable is refused with
 * invalid_request — the closed template registry is the only source of words.
 */
export const SendSchema = z
  .object({
    userId: z.string().uuid(),
    kind: z.enum(NOTIFICATION_KINDS),
    channel: z.enum(NOTIFICATION_CHANNELS),
    deadline: z.string().datetime().optional(),
  })
  .strict();
export type SendInput = z.infer<typeof SendSchema>;

/** RFC 5321 caps the path at 320 octets; anything longer is not an address. */
export const RecipientSchema = z
  .object({
    userId: z.string().uuid(),
    email: z.string().email().max(320),
  })
  .strict();
export type RecipientInput = z.infer<typeof RecipientSchema>;

export function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    // Never echo the payload back: an upsert body carries an address.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data;
}
