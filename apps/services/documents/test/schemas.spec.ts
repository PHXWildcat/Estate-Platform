import { BadRequestException } from '@nestjs/common';
import {
  GenerateDocumentSchema,
  IfMatchSchema,
  NewVersionSchema,
  parse,
  SearchQuerySchema,
  StatusTransitionSchema,
  UPLOAD_MAX_BYTES,
  UploadDocumentSchema,
  UuidSchema,
  VersionParamSchema,
} from '../src/schemas';

describe('request schemas', () => {
  it('GenerateDocumentSchema: valid shape, defaults, strictness', () => {
    const input = parse(GenerateDocumentSchema, {
      docType: 'will',
      state: 'CA',
      variables: { a: 'x', b: true },
    });
    expect(input.variables).toEqual({ a: 'x', b: true });
    expect(parse(GenerateDocumentSchema, { docType: 'will', state: 'CA' }).variables).toEqual({});
    expect(() => parse(GenerateDocumentSchema, { docType: 'will', state: 'CA', extra: 1 })).toThrow(
      BadRequestException,
    );
    expect(() => parse(GenerateDocumentSchema, { docType: 'codicil', state: 'CA' })).toThrow(
      BadRequestException,
    );
    expect(() => parse(GenerateDocumentSchema, { docType: 'will', state: 'XX' })).toThrow(
      BadRequestException,
    );
  });

  it('rejects non-string/boolean intake values at the shape layer', () => {
    for (const value of [42, null, { nested: true }, ['a']]) {
      expect(() =>
        parse(GenerateDocumentSchema, { docType: 'will', state: 'CA', variables: { v: value } }),
      ).toThrow(BadRequestException);
    }
  });

  it('StatusTransitionSchema validates status enum and date shape', () => {
    expect(parse(StatusTransitionSchema, { status: 'signed' }).status).toBe('signed');
    expect(
      parse(StatusTransitionSchema, { status: 'executed', executedAt: '2026-07-23' }).executedAt,
    ).toBe('2026-07-23');
    expect(() => parse(StatusTransitionSchema, { status: 'notarised' })).toThrow(
      BadRequestException,
    );
    expect(() =>
      parse(StatusTransitionSchema, { status: 'executed', executedAt: '2026-02-30' }),
    ).toThrow(BadRequestException);
  });

  it('NewVersionSchema is strict and defaults variables', () => {
    expect(parse(NewVersionSchema, {}).variables).toEqual({});
    expect(() => parse(NewVersionSchema, { docType: 'will' })).toThrow(BadRequestException);
  });

  it('params: UUIDs, version numbers, If-Match coercion', () => {
    expect(() => parse(UuidSchema, 'not-a-uuid')).toThrow(BadRequestException);
    expect(parse(VersionParamSchema, '3')).toBe(3);
    expect(() => parse(VersionParamSchema, '0')).toThrow(BadRequestException);
    expect(() => parse(VersionParamSchema, '1.5')).toThrow(BadRequestException);
    expect(parse(IfMatchSchema, undefined)).toBeUndefined();
    expect(parse(IfMatchSchema, '2')).toBe(2);
    expect(() => parse(IfMatchSchema, 'abc')).toThrow(BadRequestException);
  });

  it('UploadDocumentSchema: strict base64, kinds, size ceiling', () => {
    const valid = {
      kind: 'property',
      title: 'Deed',
      mime: 'application/pdf',
      contentBase64: Buffer.from('%PDF-1.4 test').toString('base64'),
    };
    expect(parse(UploadDocumentSchema, valid).kind).toBe('property');
    expect(parse(UploadDocumentSchema, { ...valid, kind: 'will' }).kind).toBe('will');
    expect(() => parse(UploadDocumentSchema, { ...valid, kind: 'memes' })).toThrow(
      BadRequestException,
    );
    // Whitespace-tolerant base64 would make decoded size unpredictable.
    expect(() => parse(UploadDocumentSchema, { ...valid, contentBase64: 'AAAA\nBBBB' })).toThrow(
      BadRequestException,
    );
    expect(() => parse(UploadDocumentSchema, { ...valid, contentBase64: 'not base64!!' })).toThrow(
      BadRequestException,
    );
    const oversized = 'A'.repeat(Math.ceil(UPLOAD_MAX_BYTES / 3) * 4 + 8);
    expect(() => parse(UploadDocumentSchema, { ...valid, contentBase64: oversized })).toThrow(
      BadRequestException,
    );
    expect(() => parse(UploadDocumentSchema, { ...valid, extra: 1 })).toThrow(BadRequestException);
  });

  it('SearchQuerySchema bounds query length', () => {
    expect(parse(SearchQuerySchema, 'marlow deed')).toBe('marlow deed');
    expect(() => parse(SearchQuerySchema, 'ab')).toThrow(BadRequestException);
    expect(() => parse(SearchQuerySchema, 'x'.repeat(201))).toThrow(BadRequestException);
  });

  it('parse errors are the generic token, never field details', () => {
    try {
      parse(GenerateDocumentSchema, { docType: 'will' });
      throw new Error('expected BadRequestException');
    } catch (err) {
      expect((err as BadRequestException).getResponse()).toEqual({ error: 'invalid_request' });
    }
  });
});
