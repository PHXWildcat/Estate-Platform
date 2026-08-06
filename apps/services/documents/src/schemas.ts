import { BadRequestException } from '@nestjs/common';
import {
  DocTypeSchema,
  DocumentKindSchema,
  ExecutionStatusSchema,
  UsStateSchema,
} from '@estate/contracts';
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

/** Hard cap on decoded upload size (docs/03: bounded untrusted input). */
export const UPLOAD_MAX_BYTES = 10 * 1024 * 1024;

// Base64 of UPLOAD_MAX_BYTES, with padding slack. The regex is strict —
// whitespace/newline-tolerant base64 would make decoded length unpredictable.
const MAX_BASE64_CHARS = Math.ceil(UPLOAD_MAX_BYTES / 3) * 4 + 4;
const Base64Schema = z
  .string()
  .min(4)
  .max(MAX_BASE64_CHARS)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/, 'strict base64 required');

export const UploadDocumentSchema = z
  .object({
    /** Instrument type (e.g. a scanned executed will) or a vault category. */
    kind: DocumentKindSchema,
    title: z.string().min(1).max(200),
    /** Declared mime — cross-checked against the sniffed magic bytes. */
    mime: z.string().min(1).max(100),
    contentBase64: Base64Schema,
  })
  .strict();
export type UploadDocumentInput = z.infer<typeof UploadDocumentSchema>;

export const SearchQuerySchema = z.string().min(3).max(200);

/**
 * The search term travels in a POST BODY, not a query string.
 *
 * A query string is the one part of an HTTP request intermediaries record by
 * default — CloudFront and WAF access logs capture the full request URI in the
 * topology docs/01 §2 describes — and this term is by construction a word out
 * of the user's own estate: a beneficiary's name, a property address, an
 * account nickname. That is plaintext PII on a logging path, which this repo
 * forbids everywhere else. The route was a GET from M4, when nothing called
 * it; M12 is its first caller, so this is the change that makes the exposure
 * real, and the moment to close it (M12 review).
 *
 * Nothing else about the design changes: the term is still reduced to per-user
 * HMAC tokens and matched ciphertext-side, and no decrypt happens to serve it.
 */
export const SearchRequestSchema = z.object({ query: SearchQuerySchema }).strict();
export type SearchRequestInput = z.infer<typeof SearchRequestSchema>;

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
