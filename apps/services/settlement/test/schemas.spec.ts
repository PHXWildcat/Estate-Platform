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
    expect(() => parse(ReportCaseSchema, { ...base, source: 'death_certificate_upload' })).toThrow(
      BadRequestException,
    );
    expect(() =>
      parse(ReportCaseSchema, {
        ...base,
        source: 'death_certificate_upload',
        evidence: [{ type: 'provider_match', matchId: 'x:1' }],
      }),
    ).toThrow(BadRequestException);
    const ok = parse(ReportCaseSchema, {
      ...base,
      source: 'death_certificate_upload',
      evidence: [{ type: 'document', documentId: randomUUID(), version: 1 }],
    });
    expect(ok.evidence).toHaveLength(1);
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
