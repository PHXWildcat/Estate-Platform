import { BadRequestException } from '@nestjs/common';
import { deserializePayload, serializePayload } from '../src/asset-events';
import { centsToMoney, moneyToCents, ownedShareCents, pctToSql, sqlToPct } from '../src/money';
import {
  ChangeOwnershipSchema,
  CreateAssetSchema,
  DesignateBeneficiarySchema,
  IfMatchSchema,
  parse,
  UpdateDetailsSchema,
} from '../src/schemas';

describe('command schemas', () => {
  it('accepts a minimal create and applies no hidden defaults', () => {
    const input = parse(CreateAssetSchema, { category: 'jewelry', title: 'Grandmother’s ring' });
    expect(input.category).toBe('jewelry');
    expect(input.ownershipPct).toBeUndefined();
  });

  it('requires valuation fields together', () => {
    expect(() =>
      parse(CreateAssetSchema, { category: 'cash', title: 'x', estValue: '10.00' }),
    ).toThrow(BadRequestException);
    expect(
      parse(CreateAssetSchema, {
        category: 'cash',
        title: 'x',
        estValue: '10.00',
        valuationAsOf: '2026-07-01',
        valuationSource: 'owner_estimate',
      }).estValue,
    ).toBe('10.00');
  });

  it('rejects malformed money, percents, dates, and categories', () => {
    const bad = [
      { category: 'yacht_money', title: 'x' },
      { category: 'cash', title: '' },
      { category: 'cash', title: 'x', costBasis: '10.123' },
      { category: 'cash', title: 'x', costBasis: '1e9' },
      { category: 'cash', title: 'x', ownershipPct: 0 },
      { category: 'cash', title: 'x', ownershipPct: 100.0001 },
      { category: 'cash', title: 'x', ownershipPct: 12.3456 },
    ];
    for (const body of bad) {
      expect(() => parse(CreateAssetSchema, body)).toThrow(BadRequestException);
    }
    expect(() =>
      parse(ChangeOwnershipSchema, { ownershipPct: 50, costBasis: '99999999999999999.00' }),
    ).toThrow(BadRequestException);
    expect(() =>
      parse(DesignateBeneficiarySchema, {
        contactId: 'not-a-uuid',
        designation: 'primary',
        sharePct: 50,
      }),
    ).toThrow(BadRequestException);
  });

  it('update requires at least one change; null clears', () => {
    expect(() => parse(UpdateDetailsSchema, {})).toThrow(BadRequestException);
    const input = parse(UpdateDetailsSchema, { location: null });
    expect(input.location).toBeNull();
  });

  it('validation failures never echo field names or values', () => {
    try {
      parse(CreateAssetSchema, { category: 'cash', title: 'Secret Vault Location' });
      // title alone is valid; force a failure carrying a value
      parse(CreateAssetSchema, { category: 'cash', title: 'x', notes: '' });
      fail('expected BadRequestException');
    } catch (err) {
      const body = JSON.stringify((err as BadRequestException).getResponse());
      expect(body).toBe('{"error":"invalid_request"}');
    }
  });

  it('parses If-Match version tokens strictly', () => {
    expect(parse(IfMatchSchema, undefined)).toBeUndefined();
    expect(parse(IfMatchSchema, '42')).toBe(42n);
    expect(() => parse(IfMatchSchema, 'abc')).toThrow(BadRequestException);
    expect(() => parse(IfMatchSchema, '-3')).toThrow(BadRequestException);
  });
});

describe('event payload round-trip', () => {
  it('serializes and re-validates payloads', () => {
    const payload = {
      v: 1 as const,
      type: 'ValuationRecorded' as const,
      estValue: '123.45',
      valuationAsOf: '2026-07-21',
      valuationSource: 'appraisal' as const,
    };
    expect(deserializePayload(serializePayload(payload))).toEqual(payload);
  });

  it('rejects unknown event types on the way out of storage', () => {
    expect(() => deserializePayload(JSON.stringify({ v: 1, type: 'AssetTeleported' }))).toThrow();
  });
});

describe('money math', () => {
  it('round-trips decimal strings through cents', () => {
    expect(moneyToCents('0')).toBe(0n);
    expect(moneyToCents('1234.5')).toBe(123450n);
    expect(centsToMoney(123450n)).toBe('1234.50');
  });

  it('computes owned shares exactly', () => {
    expect(ownedShareCents(moneyToCents('100.00'), 50)).toBe(5000n);
    expect(ownedShareCents(moneyToCents('0.01'), 33.333)).toBe(0n); // rounds to nearest cent
    expect(ownedShareCents(moneyToCents('1000000000000.00'), 33.333)).toBe(33333000000000n);
  });

  it('normalizes percents for NUMERIC(6,3) and back', () => {
    expect(pctToSql(100)).toBe('100.000');
    expect(pctToSql(33.333)).toBe('33.333');
    expect(sqlToPct('33.333')).toBe(33.333);
  });
});
