import { randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import {
  EvidenceReadQuerySchema,
  parse,
  ProviderReportSchema,
  ReportCaseSchema,
  ReviewDecisionSchema,
  SettingsSchema,
} from '../src/schemas';

describe('ReportCaseSchema (reporter intake)', () => {
  const base = { decedentUserId: randomUUID(), source: 'trusted_contact', evidence: [] };

  it('accepts a trusted-contact report with no evidence', () => {
    expect(parse(ReportCaseSchema, base).source).toBe('trusted_contact');
  });

  it('data_provider is NOT a reporter-facing source (operator route only)', () => {
    expect(() => parse(ReportCaseSchema, { ...base, source: 'data_provider' })).toThrow(
      BadRequestException,
    );
  });

  it('a death-certificate report must reference at least one document', () => {
    // The boundary this refine decides is EMPTY vs. non-empty. It used to be
    // tested with a provider-match entry as the counter-example too; since
    // PR4b that entry is refused by the array itself, one layer earlier, so it
    // would have proven the refine while never reaching it.
    expect(() => parse(ReportCaseSchema, { ...base, source: 'death_certificate_upload' })).toThrow(
      BadRequestException,
    );
    const ok = parse(ReportCaseSchema, {
      ...base,
      source: 'death_certificate_upload',
      evidence: [{ type: 'document', documentId: randomUUID(), version: 1 }],
    });
    expect(ok.evidence).toHaveLength(1);
  });

  /**
   * A REPORTER CANNOT ATTACH A PROVIDER MATCH (M22 PR4b) — the static half of
   * the rule whose dynamic half lives in `SettlementService.addEvidence`
   * (proven in `settlement.service.spec.ts`, which is where a caller exists).
   *
   * This route's authority is the linked-contact check, so its caller is a
   * contact by construction — including a caller who happens to be on the
   * operator allowlist, as `report()` says where it declines to count breadth.
   * That is why documents-only can be a property of the SCHEMA here and cannot
   * be one on the attach route.
   */
  it('a reporter may attach documents, never a provider match', () => {
    expect(() =>
      parse(ReportCaseSchema, {
        ...base,
        evidence: [{ type: 'provider_match', matchId: 'x:1' }],
      }),
    ).toThrow(BadRequestException);

    // Both controls. A document still parses — so the assertion above is about
    // the TYPE and not about the evidence array having been sealed shut — and
    // `ProviderReportSchema` still takes match ids, so the operator door this
    // evidence arrives through is open.
    expect(
      parse(ReportCaseSchema, {
        ...base,
        evidence: [{ type: 'document', documentId: randomUUID(), version: 1 }],
      }).evidence,
    ).toHaveLength(1);
    expect(
      parse(ProviderReportSchema, {
        decedentUserId: randomUUID(),
        providerMatchIds: ['x:1'],
      }).providerMatchIds,
    ).toEqual(['x:1']);
  });

  it('is strict: unknown keys are rejected', () => {
    expect(() => parse(ReportCaseSchema, { ...base, extra: true })).toThrow(BadRequestException);
  });

  it('provider match ids are clamped to the audit-safe token grammar', () => {
    expect(() =>
      parse(ProviderReportSchema, {
        decedentUserId: randomUUID(),
        providerMatchIds: ['has spaces and @'],
      }),
    ).toThrow(BadRequestException);
  });
});

describe('ReviewDecisionSchema', () => {
  it('approve needs no reason; reject requires a reason token', () => {
    expect(parse(ReviewDecisionSchema, { decision: 'approve' }).decision).toBe('approve');
    expect(() => parse(ReviewDecisionSchema, { decision: 'reject' })).toThrow(BadRequestException);
    expect(
      parse(ReviewDecisionSchema, { decision: 'reject', reason: 'fraud_suspected' }).reason,
    ).toBe('fraud_suspected');
  });

  it('free-text reasons have no field to land in', () => {
    expect(() =>
      parse(ReviewDecisionSchema, { decision: 'reject', reason: 'looked shady to me' }),
    ).toThrow(BadRequestException);
  });
});

describe('SettingsSchema (floor restated from the DDL)', () => {
  it('enforces 5..60 days', () => {
    expect(parse(SettingsSchema, { waitingPeriodDays: 5 }).waitingPeriodDays).toBe(5);
    expect(() => parse(SettingsSchema, { waitingPeriodDays: 4 })).toThrow(BadRequestException);
    expect(() => parse(SettingsSchema, { waitingPeriodDays: 61 })).toThrow(BadRequestException);
    expect(() => parse(SettingsSchema, { waitingPeriodDays: 5.5 })).toThrow(BadRequestException);
  });
});

describe('EvidenceReadQuerySchema', () => {
  it('coerces the version and validates the document id', () => {
    const parsed = parse(EvidenceReadQuerySchema, {
      documentId: randomUUID(),
      version: '3',
    });
    expect(parsed.version).toBe(3);
    expect(() =>
      parse(EvidenceReadQuerySchema, { documentId: 'not-a-uuid', version: '1' }),
    ).toThrow(BadRequestException);
  });
});
