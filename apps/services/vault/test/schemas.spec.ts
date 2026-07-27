import { BadRequestException } from '@nestjs/common';
import {
  BLOB_MAX_BYTES,
  CreateItemSchema,
  CreateKeysetSchema,
  IfMatchSchema,
  ListItemsQuerySchema,
  parse,
  ReplaceKeysetSchema,
  SrpVerifySchema,
  UpdateItemSchema,
  UuidSchema,
} from '../src/schemas';

const UUID = '2c1f0a3b-4d5e-4f60-8172-93a4b5c6d7e8';

function b64(bytes: number, fill = 1): string {
  return Buffer.alloc(bytes, fill).toString('base64');
}

const KEYSET = {
  srpSalt: b64(16),
  srpVerifier: b64(512),
  wrappedMasterKey: b64(61),
  kdfParams: {
    v: 1,
    alg: 'pbkdf2-sha256',
    iterations: 650_000,
    aukSalt: b64(16, 2),
    srpGroup: 'rfc5054-4096',
    cipher: 'aes-256-gcm',
  },
};

describe('parse', () => {
  it('rejects with a single token that names no field', () => {
    try {
      parse(UuidSchema, 'not-a-uuid');
      throw new Error('expected a rejection');
    } catch (err) {
      expect(err).toBeInstanceOf(BadRequestException);
      expect((err as BadRequestException).getResponse()).toEqual({ error: 'invalid_request' });
    }
  });
});

describe('keyset schemas', () => {
  it('accepts a well-formed keyset', () => {
    expect(parse(CreateKeysetSchema, KEYSET)).toMatchObject({ srpSalt: KEYSET.srpSalt });
  });

  it.each([
    ['a short salt', { srpSalt: b64(8) }],
    ['a short verifier', { srpVerifier: b64(256) }],
    ['a long verifier', { srpVerifier: b64(513) }],
    ['a non-base64 verifier', { srpVerifier: 'not base64!' }],
  ])('rejects %s', (_label, override) => {
    expect(() => parse(CreateKeysetSchema, { ...KEYSET, ...override })).toThrow(
      BadRequestException,
    );
  });

  it.each([
    ['a lowered iteration count', { iterations: 1000 }],
    ['a substituted group', { srpGroup: 'rfc5054-1024' }],
    ['a substituted cipher', { cipher: 'aes-128-gcm' }],
    ['a substituted kdf', { alg: 'pbkdf2-sha1' }],
    ['an unknown version', { v: 2 }],
  ])('refuses to store a keyset with %s', (_label, override) => {
    // The server cannot use these parameters, but storing a profile it does
    // not recognise would mint a vault nobody can open.
    const kdfParams = { ...KEYSET.kdfParams, ...override };
    expect(() => parse(CreateKeysetSchema, { ...KEYSET, kdfParams })).toThrow(BadRequestException);
  });

  it('rejects unknown keys', () => {
    expect(() => parse(CreateKeysetSchema, { ...KEYSET, extra: 1 })).toThrow(BadRequestException);
  });

  it('requires a proof on replacement', () => {
    expect(() => parse(ReplaceKeysetSchema, KEYSET)).toThrow(BadRequestException);
    expect(parse(ReplaceKeysetSchema, { ...KEYSET, proof: b64(32) })).toMatchObject({
      proof: b64(32),
    });
  });

  it('requires the proof to be exactly 32 bytes', () => {
    expect(() => parse(ReplaceKeysetSchema, { ...KEYSET, proof: b64(31) })).toThrow(
      BadRequestException,
    );
  });
});

describe('srp verify schema', () => {
  const body = { handshakeId: UUID, clientPublic: b64(512), clientProof: b64(32) };

  it('accepts a well-formed proof submission', () => {
    expect(parse(SrpVerifySchema, body)).toMatchObject({ handshakeId: UUID });
  });

  it.each([
    ['a short client public value', { clientPublic: b64(64) }],
    ['a short proof', { clientProof: b64(16) }],
    ['a non-uuid handshake', { handshakeId: 'abc' }],
  ])('rejects %s', (_label, override) => {
    expect(() => parse(SrpVerifySchema, { ...body, ...override })).toThrow(BadRequestException);
  });
});

describe('item schemas', () => {
  const item = { id: UUID, itemType: 'password', blob: b64(128) };

  it('accepts a well-formed item', () => {
    expect(parse(CreateItemSchema, item)).toMatchObject({ id: UUID, itemType: 'password' });
  });

  it('requires a client-supplied uuid', () => {
    const { id: _id, ...withoutId } = item;
    expect(() => parse(CreateItemSchema, withoutId)).toThrow(BadRequestException);
  });

  it('rejects an unknown item type', () => {
    expect(() => parse(CreateItemSchema, { ...item, itemType: 'crypto_wallet' })).toThrow(
      BadRequestException,
    );
  });

  it('accepts a blob at the cap', () => {
    expect(() =>
      parse(UpdateItemSchema, { itemType: 'password', blob: b64(BLOB_MAX_BYTES) }),
    ).not.toThrow();
  });

  it('rejects a blob over the cap', () => {
    expect(() =>
      parse(UpdateItemSchema, { itemType: 'password', blob: b64(BLOB_MAX_BYTES + 1) }),
    ).toThrow(BadRequestException);
  });

  it('rejects an empty blob', () => {
    expect(() => parse(UpdateItemSchema, { itemType: 'password', blob: '' })).toThrow(
      BadRequestException,
    );
  });

  it('rejects a non-base64 blob', () => {
    expect(() => parse(UpdateItemSchema, { itemType: 'password', blob: 'not base64!' })).toThrow(
      BadRequestException,
    );
  });
});

describe('list query', () => {
  it('defaults the page size', () => {
    expect(parse(ListItemsQuerySchema, {})).toEqual({ limit: 100 });
  });

  it('caps the page size', () => {
    expect(() => parse(ListItemsQuerySchema, { limit: '501' })).toThrow(BadRequestException);
    expect(parse(ListItemsQuerySchema, { limit: '500' })).toEqual({ limit: 500 });
  });

  it('carries a cursor through', () => {
    expect(parse(ListItemsQuerySchema, { cursor: 'abc' })).toEqual({ limit: 100, cursor: 'abc' });
  });
});

describe('If-Match', () => {
  it('coerces a version header', () => {
    expect(parse(IfMatchSchema, '3')).toBe(3);
  });

  it.each([['0'], ['-1'], ['abc'], [undefined]])('rejects %p', (value) => {
    expect(() => parse(IfMatchSchema, value)).toThrow(BadRequestException);
  });
});
