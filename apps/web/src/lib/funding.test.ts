import { trustFundingPct } from './funding';

/**
 * The client-side funding percentage must be FAITHFUL to the service's own
 * computation (assets.service.ts `inTrustPct`): BigInt cents, half-up at one
 * decimal place, null on a zero total. If a later milestone un-strips the
 * service's field, the two surfaces must already agree — these cases mirror
 * the service formula's behaviour, boundary included.
 */
describe('trustFundingPct', () => {
  it('computes the plain case', () => {
    expect(trustFundingPct('150000.00', '200000.00')).toBe(75);
  });

  it('a fully funded estate is exactly 100', () => {
    expect(trustFundingPct('200000.00', '200000.00')).toBe(100);
  });

  it('rounds HALF-UP at one decimal place, the service’s own boundary', () => {
    // Exact value 0.75%: half-up gives 0.8, truncation would give 0.7.
    expect(trustFundingPct('0.03', '4.00')).toBe(0.8);
    // Exact value 16.666…%: rounds up to 16.7.
    expect(trustFundingPct('0.50', '3.00')).toBe(16.7);
  });

  it('a zero-value estate has NO percentage — null, never 0', () => {
    // The service answers null here too: a percentage of nothing is not 0%.
    expect(trustFundingPct('0.00', '0.00')).toBe(null);
  });

  it('is digit-perfect beyond Number.MAX_SAFE_INTEGER (no float ever touches the money)', () => {
    expect(trustFundingPct('9007199254740993.00', '18014398509481986.00')).toBe(50);
  });

  it('accepts the ledger’s decimal-string forms', () => {
    // centsToMoney always emits two decimals, but the parser tolerates fewer.
    expect(trustFundingPct('1', '4')).toBe(25);
    expect(trustFundingPct('1.5', '3.0')).toBe(50);
  });

  it('REFUSES what it cannot be sure of — null, never a confident guess', () => {
    expect(trustFundingPct('abc', '100.00')).toBe(null);
    expect(trustFundingPct('100.00', 'NaN')).toBe(null);
    // The ledger's totals are non-negative; a negative string is not ours to
    // interpret.
    expect(trustFundingPct('-5.00', '100.00')).toBe(null);
    expect(trustFundingPct('1.234', '100.00')).toBe(null);
    expect(trustFundingPct('', '100.00')).toBe(null);
  });
});
