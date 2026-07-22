import { AssetCategorySchema } from '@estate/contracts';
import { z } from 'zod';

/**
 * Ledger event payload schemas — the write model's vocabulary. Each carries a
 * `v: 1` literal so payloads can evolve (new version = new literal + union
 * member; the reducer handles all versions forever — events are immutable).
 *
 * Payloads are serialized to JSON and stored ONLY as AEAD ciphertext
 * (`asset_events.payload_ct`, AAD-bound to user_id + event_id). They never
 * cross the Kafka bus — the domain topic carries IDs/enums only (see
 * @estate/contracts AssetLedgerAppendedEvent) — which is why these schemas
 * live in-service rather than in contracts.
 */

/** Decimal money string, up to 2 fraction digits (e.g. "1500000.00"). */
export const MoneySchema = z.string().regex(/^(0|[1-9]\d{0,12})(\.\d{1,2})?$/, {
  message: 'money must be a decimal string with up to 2 fraction digits',
});

/** Percentage with NUMERIC(6,3) scale: 0–100, at most 3 fraction digits. */
export const PctSchema = z
  .number()
  .gt(0)
  .max(100)
  .refine((n) => Math.abs(n * 1000 - Math.round(n * 1000)) < 1e-6, {
    message: 'percentage supports at most 3 decimal places',
  });

/** ISO calendar date (valuation_as_of is a DATE column). */
export const IsoDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((s) => !Number.isNaN(new Date(`${s}T00:00:00Z`).getTime()), { message: 'invalid date' });

export const ValuationSourceSchema = z.enum([
  'owner_estimate',
  'appraisal',
  'purchase_price',
  'market',
]);
export const FundingStatusSchema = z.enum(['unfunded', 'in_progress', 'funded', 'na']);
export const DesignationSchema = z.enum(['primary', 'contingent']);
export const RetireReasonSchema = z.enum(['sold', 'gifted', 'lost', 'error', 'other']);

const TitleSchema = z.string().min(1).max(200);
const LocationSchema = z.string().min(1).max(500);
const NotesSchema = z.string().min(1).max(2000);

export const AssetCreatedV1 = z.object({
  v: z.literal(1),
  type: z.literal('AssetCreated'),
  category: AssetCategorySchema,
  title: TitleSchema,
  ownershipPct: PctSchema.default(100),
  inTrust: z.boolean().default(false),
  fundingStatus: FundingStatusSchema.optional(),
  estValue: MoneySchema.optional(),
  valuationAsOf: IsoDateSchema.optional(),
  valuationSource: ValuationSourceSchema.optional(),
  costBasis: MoneySchema.optional(),
  location: LocationSchema.optional(),
  notes: NotesSchema.optional(),
});

/**
 * `null` clears a field; absent leaves it unchanged. Category is immutable in
 * M3. "At least one field" is enforced at the DTO layer (schemas.ts) — a
 * refine here would break the discriminated union.
 */
export const AssetDetailsUpdatedV1 = z.object({
  v: z.literal(1),
  type: z.literal('AssetDetailsUpdated'),
  title: TitleSchema.optional(),
  location: LocationSchema.nullable().optional(),
  notes: NotesSchema.nullable().optional(),
  inTrust: z.boolean().optional(),
  fundingStatus: FundingStatusSchema.nullable().optional(),
});

export const ValuationRecordedV1 = z.object({
  v: z.literal(1),
  type: z.literal('ValuationRecorded'),
  estValue: MoneySchema,
  valuationAsOf: IsoDateSchema,
  valuationSource: ValuationSourceSchema,
});

export const OwnershipChangedV1 = z.object({
  v: z.literal(1),
  type: z.literal('OwnershipChanged'),
  ownershipPct: PctSchema,
  costBasis: MoneySchema.nullable().optional(),
});

export const BeneficiaryDesignatedV1 = z.object({
  v: z.literal(1),
  type: z.literal('BeneficiaryDesignated'),
  /** Core-cluster contact id — UUID shape only; no cross-cluster FK (docs/02 §8). */
  contactId: z.string().uuid(),
  designation: DesignationSchema,
  sharePct: PctSchema,
});

export const BeneficiaryRemovedV1 = z.object({
  v: z.literal(1),
  type: z.literal('BeneficiaryRemoved'),
  contactId: z.string().uuid(),
  designation: DesignationSchema,
});

export const AssetRetiredV1 = z.object({
  v: z.literal(1),
  type: z.literal('AssetRetired'),
  reason: RetireReasonSchema.optional(),
});

export const AssetEventPayloadSchema = z.discriminatedUnion('type', [
  AssetCreatedV1,
  AssetDetailsUpdatedV1,
  ValuationRecordedV1,
  OwnershipChangedV1,
  BeneficiaryDesignatedV1,
  BeneficiaryRemovedV1,
  AssetRetiredV1,
]);
export type AssetEventPayload = z.infer<typeof AssetEventPayloadSchema>;
export type AssetEventType = AssetEventPayload['type'];

/** Serialize a payload for encryption into `payload_ct`. */
export function serializePayload(payload: AssetEventPayload): string {
  return JSON.stringify(AssetEventPayloadSchema.parse(payload));
}

/**
 * Parse a decrypted `payload_ct`. Validated on the way OUT of storage too:
 * the ledger is append-only forever, and replay must fail loudly on a payload
 * this code no longer understands rather than projecting garbage.
 */
export function deserializePayload(json: string): AssetEventPayload {
  return AssetEventPayloadSchema.parse(JSON.parse(json));
}
