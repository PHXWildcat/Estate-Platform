import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

/** Transport-level body ceiling; settlement payloads are ids and enums only. */
export const BODY_LIMIT = '64kb';

/** Parse-or-400. Field names only — never echo submitted values. */
export function parse<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}

export const UuidSchema = z.string().uuid();

/** Provider match ids are third-party tokens — clamp to the audit-safe grammar. */
export const ProviderMatchIdSchema = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/);

/** A death-certificate (or later court-document) reference: ids only, never content. */
export const DocumentEvidenceSchema = z
  .object({
    type: z.literal('document'),
    documentId: z.string().uuid(),
    version: z.number().int().min(1),
  })
  .strict();

export const ProviderEvidenceSchema = z
  .object({
    type: z.literal('provider_match'),
    matchId: ProviderMatchIdSchema,
  })
  .strict();

export const EvidenceInputSchema = z.discriminatedUnion('type', [
  DocumentEvidenceSchema,
  ProviderEvidenceSchema,
]);
export type EvidenceInput = z.infer<typeof EvidenceInputSchema>;

/**
 * Reporter intake (docs/03 §5.1). `data_provider` is deliberately absent from
 * the reporter-facing source enum: provider signals arrive via the
 * operator-filed route, never as a self-serve claim.
 *
 * EVIDENCE IS DOCUMENTS ONLY, closing that same gap from the other side (M22
 * PR4b). The source enum stopped a reporter CALLING their report a provider
 * signal while `EvidenceInputSchema` still let them ATTACH one — a
 * `provider_match` carrying a matchId of their own choosing, which renders on
 * the review screen beside the ones operators file. This route's authority is
 * the linked-contact check, and `report` already says what that means where it
 * declines to count breadth: a reporter who is also an operator "acted as a
 * contact here". So the narrowing is STATIC and needs no caller context —
 * unlike `AddEvidenceSchema`, whose one route serves both capacities and must
 * therefore decide at the call (`SettlementService.addEvidence`).
 */
export const ReportCaseSchema = z
  .object({
    decedentUserId: z.string().uuid(),
    source: z.enum(['trusted_contact', 'death_certificate_upload']),
    evidence: z.array(DocumentEvidenceSchema).max(16).default([]),
  })
  .strict()
  .superRefine((input, ctx) => {
    if (
      input.source === 'death_certificate_upload' &&
      !input.evidence.some((e) => e.type === 'document')
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['evidence'],
        message: 'a death_certificate_upload report must reference at least one document',
      });
    }
  });
export type ReportCaseInput = z.infer<typeof ReportCaseSchema>;

/** Operator-filed provider-signal intake (docs/01 §2.7: providers are signals). */
export const ProviderReportSchema = z
  .object({
    decedentUserId: z.string().uuid(),
    providerMatchIds: z.array(ProviderMatchIdSchema).min(1).max(16),
  })
  .strict();
export type ProviderReportInput = z.infer<typeof ProviderReportSchema>;

/**
 * Evidence attached to a case that already exists — by its reporter, or by an
 * operator working it.
 *
 * THE UNION STAYS WHOLE HERE and the narrowing lives in the service, because
 * this is the one route that serves both capacities and operators legitimately
 * file provider signals through it. A schema cannot see who is calling;
 * `SettlementService.addEvidence` refuses a non-operator's non-document entry
 * at the point where operator-ness has been measured.
 */
export const AddEvidenceSchema = z.object({ evidence: EvidenceInputSchema }).strict();

export const ReviewDecisionSchema = z
  .object({
    decision: z.enum(['approve', 'reject']),
    // Enum tokens only (audit-safe); free-text rationale deliberately has no
    // field to land in.
    reason: z
      .enum(['insufficient_evidence', 'fraud_suspected', 'duplicate_report', 'other'])
      .optional(),
  })
  .strict()
  .superRefine((input, ctx) => {
    if (input.decision === 'reject' && !input.reason) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['reason'],
        message: 'a rejection must carry a reason token',
      });
    }
  });
export type ReviewDecisionInput = z.infer<typeof ReviewDecisionSchema>;

/** Floor restated from the DDL CHECK so a bad value is a 400, not a 500. */
export const SettingsSchema = z
  .object({ waitingPeriodDays: z.number().int().min(5).max(60) })
  .strict();
export type SettingsInput = z.infer<typeof SettingsSchema>;

export const EvidenceReadQuerySchema = z.object({
  documentId: z.string().uuid(),
  version: z.coerce.number().int().min(1),
});

// --------------------------------------------------------------- PR2 schemas

/** The staged-access ladder (docs/03 §5.1 control 5). Vault is LAST. */
export const AccessStageSchema = z.enum(['inventory', 'documents', 'vault']);

export const StageRequestSchema = z.object({ stage: AccessStageSchema }).strict();

export const StageDecisionSchema = z.object({ decision: z.enum(['approve', 'deny']) }).strict();

export const StageAccessQuerySchema = z.object({
  ownerUserId: z.string().uuid(),
  stage: AccessStageSchema,
});

export const VaultReleaseQuerySchema = z.object({ ownerUserId: z.string().uuid() });

export const CompleteTaskSchema = z
  .object({
    completed: z.boolean(),
    /** A document_versions id in the DOCUMENTS cluster (letters testamentary). */
    courtDocVersionId: z.string().uuid().optional(),
  })
  .strict();

/**
 * A distribution amount as a decimal string. Kept as a STRING end to end: it
 * is encrypted before storage, never parsed into a float (money and binary
 * floating point do not mix), and never appears in an audit payload.
 */
export const AmountSchema = z
  .string()
  .regex(/^\d{1,15}(\.\d{1,2})?$/, 'amount must be a decimal with at most 2 places');

export const RecordDistributionSchema = z
  .object({
    beneficiaryContactId: z.string().uuid(),
    assetId: z.string().uuid().optional(),
    amount: AmountSchema.optional(),
  })
  .strict();

export const DistributionStatusSchema = z
  .object({ status: z.enum(['in_progress', 'completed', 'disputed']) })
  .strict();
