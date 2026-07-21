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

export const ProfileUpsertSchema = z.object({
  legalName: z.string().min(1).max(200),
  dob: z.string().min(1).max(40).optional(),
  ssn: z
    .string()
    .regex(/^\d{9}$/, 'ssn must be 9 digits')
    .optional(),
  address: OptionalText(500),
  phone: OptionalText(40),
  occupation: OptionalText(120),
  maritalStatus: z
    .enum(['single', 'married', 'domestic_partnership', 'divorced', 'widowed'])
    .optional(),
  stateOfResidence: z
    .string()
    .regex(/^[A-Z]{2}$/, 'stateOfResidence must be a 2-letter code')
    .optional(),
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
