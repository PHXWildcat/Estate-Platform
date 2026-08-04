import { formatMoney } from './money';

describe('formatMoney', () => {
  it('groups thousands and keeps the ledger’s cent precision verbatim', () => {
    expect(formatMoney('739700.00')).toBe('$739,700.00');
    expect(formatMoney('12500.50')).toBe('$12,500.50');
    expect(formatMoney('0.00')).toBe('$0.00');
    expect(formatMoney('999')).toBe('$999');
    expect(formatMoney('1000')).toBe('$1,000');
  });

  it('renders an absent valuation as an em dash, not zero', () => {
    expect(formatMoney(null)).toBe('—');
  });

  it('never round-trips through a float: values beyond MAX_SAFE_INTEGER stay digit-perfect', () => {
    // 9007199254740993 is not representable as a double (it collapses to …992).
    expect(formatMoney('9007199254740993.31')).toBe('$9,007,199,254,740,993.31');
    expect(formatMoney('123456789012345678901234567890.10')).toBe(
      '$123,456,789,012,345,678,901,234,567,890.10',
    );
  });

  it('handles negatives and refuses to reinterpret non-decimal input', () => {
    expect(formatMoney('-1234.56')).toBe('-$1,234.56');
    // Not a plain decimal string — rendered verbatim, never “fixed”.
    expect(formatMoney('1e9')).toBe('$1e9');
  });
});
