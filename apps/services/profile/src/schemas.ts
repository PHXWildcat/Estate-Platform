import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

/**
 * Request body/param schemas. Validation is shape + length only; the values
 * themselves are PII and are NEVER echoed back — a parse failure is a single
 * generic `invalid_request`, with field names withheld.
 */

export const UuidSchema = z.string().uuid();

const OptionalText = (max: number): z.ZodOptional<z.ZodString> =>
  z.string().min(1).max(max).optional();

/**
 * A field that may be left alone or explicitly cleared.
 *
 * ABSENT means UNCHANGED; `null` means CLEAR. The distinction is what makes
 * `PUT /v1/profile` safe to call from a form that does not hold every field.
 * Under the old "absent ⇒ NULL" replace semantics the SSN could not survive a
 * round trip at all: `GET /v1/profile` returns `ssnLast4` and never `ssn` (by
 * design — the full value is the most sensitive column in the product), so no
 * client could echo it back, and any edit to any other field silently destroyed
 * `ssn_ct` and `ssn_last4_ct`. Applied to every optional field OF THE PROFILE
 * rather than special-cased for the SSN, because a special case is the thing
 * that drifts.
 *
 * Contacts and family members deliberately KEEP replace semantics: their reads
 * return every field they store, so a client can round-trip them, and absent
 * genuinely can mean "the owner removed this". The profile is the one row with a
 * field it will never hand back, which is exactly why it is the one row that
 * cannot be replaced wholesale.
 */
const Clearable = <T extends z.ZodTypeAny>(schema: T): z.ZodOptional<z.ZodNullable<T>> =>
  schema.nullable().optional();

export const ProfileUpsertSchema = z.object({
  legalName: z.string().min(1).max(200),
  dob: Clearable(z.string().min(1).max(40)),
  ssn: Clearable(z.string().regex(/^\d{9}$/, 'ssn must be 9 digits')),
  address: Clearable(z.string().min(1).max(500)),
  phone: Clearable(z.string().min(1).max(40)),
  occupation: Clearable(z.string().min(1).max(120)),
  maritalStatus: Clearable(
    z.enum(['single', 'married', 'domestic_partnership', 'divorced', 'widowed']),
  ),
  stateOfResidence: Clearable(
    z.string().regex(/^[A-Z]{2}$/, 'stateOfResidence must be a 2-letter code'),
  ),
});
export type ProfileUpsertInput = z.infer<typeof ProfileUpsertSchema>;

export const FamilyMemberSchema = z.object({
  relation: z.enum(['spouse', 'child', 'parent', 'sibling', 'other']),
  name: z.string().min(1).max(200),
  dob: z.string().min(1).max(40).optional(),
  isMinor: z.boolean().optional(),
  notes: OptionalText(2000),
});
export type FamilyMemberInput = z.infer<typeof FamilyMemberSchema>;

export const ContactSchema = z.object({
  name: z.string().min(1).max(200),
  email: z.string().email().max(320).optional(),
  phone: OptionalText(40),
  address: OptionalText(500),
  relationship: OptionalText(120),
  professionalKind: z.enum(['attorney', 'cpa', 'financial_advisor', 'doctor', 'other']).optional(),
  notes: OptionalText(2000),
});
export type ContactInput = z.infer<typeof ContactSchema>;

export const RoleAssignmentSchema = z.object({
  contactId: z.string().uuid(),
  role: z.enum([
    'trustee',
    'successor_trustee',
    'executor',
    'beneficiary',
    'guardian',
    'agent_financial',
    'agent_medical',
    'attorney',
    'cpa',
    'financial_advisor',
    'family_member',
    'viewer',
  ]),
  scopeType: z.enum(['estate', 'trust', 'document', 'asset', 'account']),
  scopeId: z.string().uuid().optional(),
  effectiveCondition: z
    .enum(['immediate', 'on_incapacity', 'on_death_verified'])
    .default('immediate'),
  startsAt: z.string().datetime().optional(),
  endsAt: z.string().datetime().optional(),
});
export type RoleAssignmentInput = z.infer<typeof RoleAssignmentSchema>;

export const PermissionGrantSchema = z.object({
  resource: z.string().regex(/^[a-z][a-z0-9_.]{0,63}$/, 'resource must be a lowercase token'),
  action: z.enum(['read', 'download', 'manage']),
  constraintExpr: z.record(z.unknown()).optional(),
});
export type PermissionGrantInput = z.infer<typeof PermissionGrantSchema>;

/**
 * Parse a body/param against a schema, converting failure into a generic
 * BadRequestException. Field names are NOT surfaced (a value could be echoed
 * via a zod message otherwise) — the client only learns the request was
 * malformed.
 */
export function parse<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}
