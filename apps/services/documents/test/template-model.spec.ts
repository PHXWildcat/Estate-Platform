import {
  intakeSchemaFor,
  parseTemplateSource,
  TemplateValidationError,
} from '../src/template-model';
import { sampleSource } from './support';

describe('parseTemplateSource', () => {
  it('parses a valid source', () => {
    const source = parseTemplateSource(sampleSource());
    expect(source.docType).toBe('will');
    expect(source.body).toHaveLength(4);
  });

  it('requires legal sign-off structurally', () => {
    const bad = { ...sampleSource(), legalReview: undefined };
    expect(() => parseTemplateSource(bad)).toThrow(TemplateValidationError);
  });

  it('rejects undeclared placeholders', () => {
    const source = sampleSource({
      body: [{ text: 'Hello {{nobody}}.' }],
    });
    expect(() => parseTemplateSource(source)).toThrow(/undeclared placeholder 'nobody'/);
  });

  it('rejects substituting boolean variables', () => {
    const source = sampleSource({
      body: [{ text: 'Minor children: {{hasMinorChildren}}.' }],
    });
    expect(() => parseTemplateSource(source)).toThrow(/cannot be substituted/);
  });

  it('rejects `when` referencing non-boolean or undeclared variables', () => {
    expect(() =>
      parseTemplateSource(sampleSource({ body: [{ text: 'x', when: 'testatorName' }] })),
    ).toThrow(/is not boolean/);
    expect(() =>
      parseTemplateSource(sampleSource({ body: [{ text: 'x', when: { not: 'ghost' } }] })),
    ).toThrow(/undeclared variable 'ghost'/);
  });

  it('rejects malformed braces and templated titles', () => {
    expect(() =>
      parseTemplateSource(sampleSource({ body: [{ text: 'broken {{ brace' }] })),
    ).toThrow(/malformed braces/);
    expect(() => parseTemplateSource(sampleSource({ title: 'Will of {{testatorName}}' }))).toThrow(
      /title/,
    );
  });

  it('rejects duplicate variable names and unknown states', () => {
    const dupe = sampleSource();
    dupe.variables = [...dupe.variables, { name: 'testatorName', kind: 'boolean', required: true }];
    expect(() => parseTemplateSource(dupe)).toThrow(TemplateValidationError);
    expect(() => parseTemplateSource({ ...sampleSource(), state: 'ZZ' })).toThrow(
      TemplateValidationError,
    );
  });
});

describe('intakeSchemaFor', () => {
  const schema = intakeSchemaFor(parseTemplateSource(sampleSource()));

  const valid = {
    testatorName: 'A. Person',
    executorName: 'B. Person',
    hasMinorChildren: true,
    guardianName: 'C. Person',
    signedOn: '2026-07-23',
    maritalStatus: 'single',
  };

  it('accepts a fully valid payload and optional omissions', () => {
    expect(schema.safeParse(valid).success).toBe(true);
    const { guardianName: _omitted, ...withoutOptional } = valid;
    expect(schema.safeParse(withoutOptional).success).toBe(true);
  });

  it('is strict: undeclared keys never pass', () => {
    expect(schema.safeParse({ ...valid, smuggled: 'data' }).success).toBe(false);
  });

  it('enforces kinds: enum membership, calendar dates, booleans, lengths', () => {
    expect(schema.safeParse({ ...valid, maritalStatus: 'other' }).success).toBe(false);
    expect(schema.safeParse({ ...valid, signedOn: '2026-02-30' }).success).toBe(false);
    expect(schema.safeParse({ ...valid, hasMinorChildren: 'yes' }).success).toBe(false);
    expect(schema.safeParse({ ...valid, testatorName: 'x'.repeat(201) }).success).toBe(false);
    expect(schema.safeParse({ ...valid, testatorName: '' }).success).toBe(false);
  });

  it('rejects missing required variables', () => {
    const { testatorName: _missing, ...rest } = valid;
    expect(schema.safeParse(rest).success).toBe(false);
  });
});
