import { BadRequestException } from '@nestjs/common';
import { DocTypeSchema, ExecutionStatusSchema, UsStateSchema } from '@estate/contracts';
import { z } from 'zod';
import { IsoDateSchema } from './template-model';

/**
 * Request body/param schemas. Validation here is shape + length only; the
 * `variables` payload is validated a second time against the resolved
 * template's typed intake schema (intakeSchemaFor) before it can touch a
 * render. Values are sensitive PII and are NEVER echoed back — a parse
 * failure is a single generic `invalid_request`, with field names withheld.
 */

export const UuidSchema = z.string().uuid();

/** Shape-level bound on intake values; the template schema tightens further. */
const IntakeValueSchema = z.union([z.string().min(1).max(2000), z.boolean()]);
const IntakeVariablesSchema = z.record(z.string().min(1).max(64), IntakeValueSchema);

export const GenerateDocumentSchema = z
  .object({
    docType: DocTypeSchema,
    state: UsStateSchema,
    /** Pin a specific template; defaults to the active one for (docType, state). */
    templateId: UuidSchema.optional(),
    /** Display title override; defaults to the template's title. */
    title: z.string().min(1).max(200).optional(),
    variables: IntakeVariablesSchema.default({}),
  })
  .strict();
export type GenerateDocumentInput = z.infer<typeof GenerateDocumentSchema>;

export const NewVersionSchema = z
  .object({
    /** Re-render with a different (active, same-docType) template version. */
    templateId: UuidSchema.optional(),
    title: z.string().min(1).max(200).optional(),
    variables: IntakeVariablesSchema.default({}),
  })
  .strict();
export type NewVersionInput = z.infer<typeof NewVersionSchema>;

export const StatusTransitionSchema = z
  .object({
    status: ExecutionStatusSchema,
    /** Required when (and only when) attesting `executed`. */
    executedAt: IsoDateSchema.optional(),
  })
  .strict();
export type StatusTransitionInput = z.infer<typeof StatusTransitionSchema>;

export const StateQuerySchema = UsStateSchema;

export const VersionParamSchema = z.coerce.number().int().positive().max(1_000_000);

/** Optional If-Match version token (the document's current_version). */
export const IfMatchSchema = z.coerce.number().int().positive().optional();

export function parse<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}
