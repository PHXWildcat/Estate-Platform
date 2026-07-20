import { z } from 'zod';

export const ActorTypeSchema = z.enum(['user', 'service', 'operator', 'system']);
export type ActorType = z.infer<typeof ActorTypeSchema>;

/**
 * Common envelope for every domain event on Kafka. Payloads are defined per
 * event via `defineEvent` and must carry entity IDs and enums only — the
 * audit pipeline and search indexer consume these, and neither may ever see
 * plaintext PII (docs/01 §6).
 */
export const EventEnvelopeSchema = z.object({
  eventId: z.string().uuid(),
  type: z.string().min(1),
  version: z.number().int().positive(),
  occurredAt: z.string().datetime(),
  actor: z.object({
    id: z.string().uuid().nullable(),
    type: ActorTypeSchema,
  }),
  payload: z.unknown(),
});
export type EventEnvelope = z.infer<typeof EventEnvelopeSchema>;

/** Build a concrete event schema with a literal type tag and typed payload. */
export function defineEvent<TType extends string, TPayload extends z.ZodTypeAny>(
  type: TType,
  version: number,
  payload: TPayload,
): z.ZodObject<{
  eventId: z.ZodString;
  type: z.ZodLiteral<TType>;
  version: z.ZodLiteral<number>;
  occurredAt: z.ZodString;
  actor: (typeof EventEnvelopeSchema)['shape']['actor'];
  payload: TPayload;
}> {
  return z.object({
    eventId: z.string().uuid(),
    type: z.literal(type),
    version: z.literal(version),
    occurredAt: z.string().datetime(),
    actor: EventEnvelopeSchema.shape.actor,
    payload,
  });
}
