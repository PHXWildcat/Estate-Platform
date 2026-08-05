import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

/** One typed prompt plus its framed retrieved context — orders below documents' 16 MiB upload cap. */
export const BODY_LIMIT = '256kb';

/**
 * Ceiling on a single user turn, in characters.
 *
 * Two different limits, deliberately: BODY_LIMIT is a TRANSPORT guard the
 * express parser applies before any of our code runs, and this one is a DOMAIN
 * guard the schema applies to the field that will be sealed under the user's
 * DEK and then shipped to a model provider. The transport number has to leave
 * room for the whole envelope; this one bounds the thing that actually leaves
 * the platform, and every character of it is estate content the user is
 * choosing to send across the docs/03 §4 TB5 boundary.
 */
export const MAX_TURN_CHARS = 8000;

/**
 * Parse-or-400, and the ONE rule that matters here: the rejected value is
 * discarded, never reflected.
 *
 * Every other service's parser says "never echo submitted values" because a
 * body may carry PII. In this service the body is a PROMPT — free text a user
 * wrote about their own estate, and the single most sensitive request payload
 * in the product. zod's issue list carries the offending input for some issue
 * codes, so the parsed error object is dropped entirely rather than mapped: the
 * response is a bare `{ error: 'invalid_request' }`, and the exception carries
 * no fragment of the prompt into a log line or an error tracker either.
 */
export function parseBody<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}

/** Path-parameter ids. UUIDs everywhere; sequential ids are never exposed. */
export const UuidSchema = z.string().uuid();

/**
 * Opening a conversation takes NO input, and `.strict()` is what makes that a
 * control rather than a shrug.
 *
 * `assistant_conversations` has no title and no summary column on purpose (see
 * the migration: a user-authored title would be a plaintext free-text column,
 * and the only one of those in the product had to be argued for in the M4
 * review). A client that sends `{ "title": "..." }` is refused here rather than
 * having the field silently stripped, so the absence of the column cannot be
 * mistaken for an oversight by whoever writes the next client.
 */
export const CreateConversationSchema = z.object({}).strict();

/**
 * One user turn.
 *
 * `.strict()` is load-bearing rather than tidy. The subject of every read this
 * turn can trigger comes from the VERIFIED session (`req.caller.userId`), and
 * the structural guarantee that a request body cannot nominate a different one
 * is that no field for it exists — the same rule `assertSubjectFree` enforces
 * on tool inputs, applied at the HTTP edge. A body carrying `userId`,
 * `onBehalfOf` or `conversationOwner` is a 400, not a stripped key.
 *
 * `.trim()` runs before `.min(1)`, so a whitespace-only turn is refused rather
 * than sealed, billed and sent to a provider as an empty prompt.
 */
export const TurnSchema = z.object({ text: z.string().trim().min(1).max(MAX_TURN_CHARS) }).strict();
export type TurnInput = z.infer<typeof TurnSchema>;
