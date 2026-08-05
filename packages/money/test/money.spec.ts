import {
  centsToMoney,
  moneyToCents,
  ownedShareCents,
  pctToMilli,
  pctToSql,
  sqlToPct,
} from '../src';

/**
 * The properties asserted here are the ones a floating-point implementation
 * would fail — which is the only reason this package exists. The estate-sized
 * values are deliberate: `1e12` dollars is beyond the precision where a double
 * still counts cents, and an estate that large is exactly the one whose owner
 * notices.
 */

describe('moneyToCents', () => {
  it('accepts whole, one-decimal and two-decimal strings', () => {
    expect(moneyToCents('0')).toBe(0n);
    expect(moneyToCents('1234.5')).toBe(123450n);
    expect(moneyToCents('1234.56')).toBe(123456n);
  });

  it('keeps every cent of a value a double would round', () => {
    // 2^53 cents is where Number stops being able to count them one at a time.
    expect(moneyToCents('90071992547409.91')).toBe(9007199254740991n);
    expect(moneyToCents('90071992547409.93')).toBe(9007199254740993n);
  });

  it('signs the whole value, not just its whole part', () => {
    // The extracted original split on '.' and added the fraction unsigned, so
    // this returned -1166n. Unreachable through MoneySchema, which forbids the
    // sign — but centsToMoney emits one, so the pair must round-trip.
    expect(moneyToCents('-12.34')).toBe(-1234n);
    expect(moneyToCents('-0.05')).toBe(-5n);
  });

  it('throws rather than guessing at anything that is not money', () => {
    for (const bad of ['', '1.234', '1.', '.5', 'abc', '1e3', ' 1.00', '1,000.00', '--1']) {
      expect(() => moneyToCents(bad)).toThrow(RangeError);
    }
  });
});

describe('centsToMoney', () => {
  it('always renders exactly two decimal places', () => {
    expect(centsToMoney(0n)).toBe('0.00');
    expect(centsToMoney(5n)).toBe('0.05');
    expect(centsToMoney(123450n)).toBe('1234.50');
  });

  it('renders negatives with one leading minus, not a negative cents field', () => {
    expect(centsToMoney(-1234n)).toBe('-12.34');
    expect(centsToMoney(-5n)).toBe('-0.05');
  });

  it('round-trips against moneyToCents at estate scale', () => {
    for (const value of ['0.00', '0.01', '99.99', '1000000000000.00', '-4500.25']) {
      expect(centsToMoney(moneyToCents(value))).toBe(value);
    }
  });
});

describe('pctToMilli', () => {
  it('scales to milli-percent and rounds half away from zero', () => {
    expect(pctToMilli(100)).toBe(100_000n);
    expect(pctToMilli(33.333)).toBe(33_333n);
    // 0.0005 is below the NUMERIC(6,3) column's precision; rounding it here is
    // what keeps the value the database will store and the value we computed
    // with the same number.
    expect(pctToMilli(0.0005)).toBe(1n);
  });
});

describe('ownedShareCents', () => {
  it('computes an exact share', () => {
    expect(ownedShareCents(moneyToCents('100.00'), 50)).toBe(5000n);
    expect(ownedShareCents(moneyToCents('100.00'), 100)).toBe(10000n);
    expect(ownedShareCents(moneyToCents('100.00'), 0)).toBe(0n);
  });

  it('rounds half-up to the nearest cent', () => {
    expect(ownedShareCents(moneyToCents('0.01'), 33.333)).toBe(0n);
    expect(ownedShareCents(moneyToCents('0.01'), 50)).toBe(1n); // 0.5c rounds up
  });

  it('stays exact on an estate too large for a double', () => {
    expect(ownedShareCents(moneyToCents('1000000000000.00'), 33.333)).toBe(33333000000000n);
  });
});

describe('pctToSql / sqlToPct', () => {
  it('normalizes to three decimal places', () => {
    expect(pctToSql(100)).toBe('100.000');
    expect(pctToSql(33.333)).toBe('33.333');
    expect(pctToSql(0)).toBe('0.000');
    expect(pctToSql(0.5)).toBe('0.500');
  });

  it('round-trips a column value', () => {
    expect(sqlToPct(pctToSql(33.333))).toBe(33.333);
    expect(sqlToPct('100.000')).toBe(100);
  });
});
