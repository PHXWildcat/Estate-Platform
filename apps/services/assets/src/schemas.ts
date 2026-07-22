import { BadRequestException } from '@nestjs/common';
import { AssetCategorySchema } from '@estate/contracts';
import { z } from 'zod';
import {
  DesignationSchema,
  FundingStatusSchema,
  IsoDateSchema,
  MoneySchema,
  PctSchema,
  RetireReasonSchema,
  ValuationSourceSchema,
} from './asset-events';

/**
 * Request body/param schemas. Validation is shape + length only; the values
 * themselves are sensitive financial data and are NEVER echoed back — a parse
 * failure is a single generic `invalid_request`, with field names withheld.
 *
 * Every command accepts an optional client-generated `eventId` (idempotency
 * key): a retry carrying the same eventId is a no-op returning current state.
 */

export const UuidSchema = z.string().uuid();

const OptionalText = (max: number): z.ZodOptional<z.ZodString> =>
  z.string().min(1).max(max).optional();

export const CreateAssetSchema = z
  .object({
    eventId: UuidSchema.optional(),
    category: AssetCategorySchema,
    title: z.string().min(1).max(200),
    ownershipPct: PctSchema.optional(),
    inTrust: z.boolean().optional(),
    fundingStatus: FundingStatusSchema.optional(),
    estValue: MoneySchema.optional(),
    valuationAsOf: IsoDateSchema.optional(),
    valuationSource: ValuationSourceSchema.optional(),
    costBasis: MoneySchema.optional(),
    location: OptionalText(500),
    notes: OptionalText(2000),
  })
  .refine(
    (b) =>
      (b.estValue === undefined &&
        b.valuationAsOf === undefined &&
        b.valuationSource === undefined) ||
      (b.estValue !== undefined &&
        b.valuationAsOf !== undefined &&
        b.valuationSource !== undefined),
    { message: 'estValue, valuationAsOf and valuationSource must be provided together' },
  );
export type CreateAssetInput = z.infer<typeof CreateAssetSchema>;

export const UpdateDetailsSchema = z
  .object({
    eventId: UuidSchema.optional(),
    title: z.string().min(1).max(200).optional(),
    location: z.string().min(1).max(500).nullable().optional(),
    notes: z.string().min(1).max(2000).nullable().optional(),
    inTrust: z.boolean().optional(),
    fundingStatus: FundingStatusSchema.nullable().optional(),
  })
  .refine(
    (b) =>
      b.title !== undefined ||
      b.location !== undefined ||
      b.notes !== undefined ||
      b.inTrust !== undefined ||
      b.fundingStatus !== undefined,
    { message: 'at least one field must change' },
  );
export type UpdateDetailsInput = z.infer<typeof UpdateDetailsSchema>;

export const RecordValuationSchema = z.object({
  eventId: UuidSchema.optional(),
  estValue: MoneySchema,
  valuationAsOf: IsoDateSchema,
  valuationSource: ValuationSourceSchema,
});
export type RecordValuationInput = z.infer<typeof RecordValuationSchema>;

export const ChangeOwnershipSchema = z.object({
  eventId: UuidSchema.optional(),
  ownershipPct: PctSchema,
  costBasis: MoneySchema.nullable().optional(),
});
export type ChangeOwnershipInput = z.infer<typeof ChangeOwnershipSchema>;

export const DesignateBeneficiarySchema = z.object({
  eventId: UuidSchema.optional(),
  contactId: UuidSchema,
  designation: DesignationSchema,
  sharePct: PctSchema,
});
export type DesignateBeneficiaryInput = z.infer<typeof DesignateBeneficiarySchema>;

export const RemoveBeneficiarySchema = z.object({
  eventId: UuidSchema.optional(),
  designation: DesignationSchema,
});
export type RemoveBeneficiaryInput = z.infer<typeof RemoveBeneficiarySchema>;

export const RetireAssetSchema = z.object({
  eventId: UuidSchema.optional(),
  reason: RetireReasonSchema.optional(),
});
export type RetireAssetInput = z.infer<typeof RetireAssetSchema>;

/** ?asOf=YYYY-MM-DD on list/net-worth queries (temporal replay). */
export const AsOfQuerySchema = IsoDateSchema.optional();

/** Optional If-Match version token (the asset's latest ledger seq). */
export const IfMatchSchema = z.coerce.bigint().positive().optional();

export function parse<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}
