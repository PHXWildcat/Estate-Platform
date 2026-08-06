import type { DocumentInfo } from '../graphql/client';
import {
  documentKindLabel,
  documentSourceLabel,
  executionRequirementsSummary,
  executionStatusLabel,
  executionStatusMeaning,
  executionStatusTone,
  formatBytes,
  formatDateTime,
  sortDocuments,
} from './documents';

/**
 * The copy table, held to the same two rules as `lib/findings.ts`: every
 * sentence is a fact about the user's own account rather than a legal claim,
 * and an unknown token from a peer deployed ahead of this app must degrade
 * rather than blank the page.
 */

describe('status wording', () => {
  it('distinguishes a document that exists from one that is in force', () => {
    // The distinction the whole surface exists to make. `instrument_missing`
    // and `instrument_not_executed` are separate findings on the readiness
    // page for exactly this reason.
    expect(executionStatusMeaning('generated')).toMatch(/does not direct anything yet/i);
    expect(executionStatusMeaning('executed')).toBe('In force.');
    expect(executionStatusTone('generated')).toContain('warn');
    expect(executionStatusTone('executed')).toContain('success');
  });

  it('does not dress a revoked or superseded document as a warning to act on', () => {
    expect(executionStatusTone('revoked')).toBe('chip');
    expect(executionStatusTone('superseded')).toBe('chip');
    expect(executionStatusMeaning('revoked')).toMatch(/no longer has effect/i);
  });

  it('makes an unknown status readable rather than blank', () => {
    // A service deployed ahead of this app must not empty a row.
    expect(executionStatusLabel('partially_witnessed')).toBe('Partially witnessed');
    expect(executionStatusMeaning('partially_witnessed')).toBe('');
    expect(executionStatusTone('partially_witnessed')).toContain('warn');
  });
});

describe('kind and source labels', () => {
  it('names the instruments a person would recognise', () => {
    expect(documentKindLabel('hipaa_auth')).toBe('HIPAA authorization');
    expect(documentKindLabel('mental_health_poa')).toBe('Mental-health power of attorney');
    expect(documentKindLabel('death_certificate')).toBe('Death certificate');
  });

  it('degrades an unknown kind instead of dropping it', () => {
    expect(documentKindLabel('digital_asset_memo')).toBe('Digital asset memo');
    expect(documentKindLabel('')).toBe('Document');
  });

  it('says where a document came from, and nothing for an unknown source', () => {
    expect(documentSourceLabel('generated')).toBe('Generated here');
    expect(documentSourceLabel('uploaded')).toBe('Uploaded');
    expect(documentSourceLabel('imported')).toBe('');
  });
});

describe('execution requirements are a readback, never a claim of law', () => {
  it.each([
    [
      { witnesses: 2, notarization: false, selfProvingAffidavit: false },
      'This template records that signing needs 2 witnesses.',
    ],
    [
      { witnesses: 1, notarization: true, selfProvingAffidavit: false },
      'This template records that signing needs 1 witness and notarization.',
    ],
    [
      { witnesses: 2, notarization: true, selfProvingAffidavit: true },
      'This template records that signing needs 2 witnesses, notarization and a self-proving affidavit.',
    ],
    [
      { witnesses: 0, notarization: false, selfProvingAffidavit: false },
      'This template records no additional signing formalities.',
    ],
  ])('summarises %j', (requirements, expected) => {
    const summary = executionRequirementsSummary(requirements);
    expect(summary).toBe(expected);
    // Every sentence attributes the requirement to the reviewed TEMPLATE, not
    // to the platform's reading of a statute.
    expect(summary).toMatch(/^This template records/);
  });
});

describe('list ordering and formatting', () => {
  const base: DocumentInfo = {
    documentId: 'd1',
    docType: 'will',
    source: 'generated',
    title: 'A',
    currentVersion: 1,
    executionStatus: 'generated',
    executedAt: null,
    legalHold: false,
    sealed: false,
    templateId: null,
    createdAt: '2026-08-01T10:00:00.000Z',
    updatedAt: '2026-08-01T10:00:00.000Z',
  };

  it('puts the most recently changed document first', () => {
    const sorted = sortDocuments([
      { ...base, documentId: 'old', updatedAt: '2026-07-01T00:00:00.000Z' },
      { ...base, documentId: 'new', updatedAt: '2026-08-04T00:00:00.000Z' },
    ]);
    expect(sorted.map((doc) => doc.documentId)).toEqual(['new', 'old']);
  });

  it('does not mutate the array it was given', () => {
    const input = [
      { ...base, documentId: 'old', updatedAt: '2026-07-01T00:00:00.000Z' },
      { ...base, documentId: 'new', updatedAt: '2026-08-04T00:00:00.000Z' },
    ];
    sortDocuments(input);
    expect(input.map((doc) => doc.documentId)).toEqual(['old', 'new']);
  });

  it('renders sizes without parsing anything', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB');
    expect(formatBytes(Number.NaN)).toBe('');
    expect(formatBytes(-1)).toBe('');
  });

  it('renders an unparseable timestamp as empty rather than "Invalid Date"', () => {
    expect(formatDateTime('not a date')).toBe('');
    expect(formatDateTime('2026-08-04T10:00:00.000Z')).not.toBe('');
  });
});
