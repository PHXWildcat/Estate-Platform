import { z } from 'zod';
import { defineEvent } from './envelope';

/**
 * Document service vocabulary (docs/02 §4). Lives in contracts because it
 * crosses the bus inside domain events and appears in audit detail payloads.
 */
export const DOC_TYPES = [
  'will',
  'revocable_trust',
  'irrevocable_trust',
  'pour_over_will',
  'durable_poa',
  'financial_poa',
  'medical_poa',
  'mental_health_poa',
  'living_will',
  'hipaa_auth',
  'guardian_designation',
  'certification_of_trust',
  'property_assignment',
  'funding_letter',
  'beneficiary_letter',
] as const;
export const DocTypeSchema = z.enum(DOC_TYPES);
export type DocType = z.infer<typeof DocTypeSchema>;

/**
 * The 50-state template matrix plus DC (docs/01 §2.4). Estate instruments are
 * state law; a code outside this list has no template and never will.
 */
export const US_STATES = [
  'AL',
  'AK',
  'AZ',
  'AR',
  'CA',
  'CO',
  'CT',
  'DE',
  'DC',
  'FL',
  'GA',
  'HI',
  'ID',
  'IL',
  'IN',
  'IA',
  'KS',
  'KY',
  'LA',
  'ME',
  'MD',
  'MA',
  'MI',
  'MN',
  'MS',
  'MO',
  'MT',
  'NE',
  'NV',
  'NH',
  'NJ',
  'NM',
  'NY',
  'NC',
  'ND',
  'OH',
  'OK',
  'OR',
  'PA',
  'RI',
  'SC',
  'SD',
  'TN',
  'TX',
  'UT',
  'VT',
  'VA',
  'WA',
  'WV',
  'WI',
  'WY',
] as const;
export const UsStateSchema = z.enum(US_STATES);
export type UsState = z.infer<typeof UsStateSchema>;

/** Execution lifecycle per docs/02 §4 `documents.execution_status`. */
export const EXECUTION_STATUSES = [
  'draft',
  'generated',
  'signed',
  'witnessed',
  'notarized',
  'executed',
  'revoked',
  'superseded',
] as const;
export const ExecutionStatusSchema = z.enum(EXECUTION_STATUSES);
export type ExecutionStatus = z.infer<typeof ExecutionStatusSchema>;

export const DOCUMENT_SOURCES = ['generated', 'uploaded'] as const;
export const DocumentSourceSchema = z.enum(DOCUMENT_SOURCES);
export type DocumentSource = z.infer<typeof DocumentSourceSchema>;

/**
 * Domain events for the Document service. IDs, enums, and counts only — no
 * titles, no content, no variable values. Carrying values would require the
 * docs/01 §4 Zone B Kafka payload crypto, which is not built yet; consumers
 * needing detail must read it from the owning service.
 */
export const DocumentVersionCreatedEvent = defineEvent(
  'document.version.created',
  1,
  z.object({
    documentId: z.string().uuid(),
    version: z.number().int().positive(),
    docType: DocTypeSchema,
    source: DocumentSourceSchema,
  }),
);
export type DocumentVersionCreated = z.infer<typeof DocumentVersionCreatedEvent>;

export const DocumentStatusChangedEvent = defineEvent(
  'document.status.changed',
  1,
  z.object({
    documentId: z.string().uuid(),
    from: ExecutionStatusSchema,
    to: ExecutionStatusSchema,
  }),
);
export type DocumentStatusChanged = z.infer<typeof DocumentStatusChangedEvent>;
