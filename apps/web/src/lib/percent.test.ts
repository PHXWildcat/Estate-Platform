import { formatPct } from './percent';

describe('formatPct', () => {
  it('keeps every digit the wire can carry and drops the ones it cannot', () => {
    // PctSchema admits at most 3 decimal places, so 3dp is the value's full
    // precision — nothing a server may legitimately send is rounded away.
    expect(formatPct(33.333)).toBe('33.333');
    expect(formatPct(0.001)).toBe('0.001');
    expect(formatPct(100)).toBe('100');
    expect(formatPct(40)).toBe('40');
    expect(formatPct(12.5)).toBe('12.5');
    expect(formatPct(0)).toBe('0');
  });

  it('renders computed shares without float noise (the reason this exists)', () => {
    // The M19 PR3 review's finding, measured: across the legal 3-decimal
    // domain, 32,448 of ~100,000 shares made `100 - x` print noise. These are
    // three of them; the raw subtraction gives 97.94200000000001 &c.
    expect(formatPct(100 - 2.058)).toBe('97.942');
    expect(formatPct(100 - 2.067)).toBe('97.933');
    expect(formatPct(100 - 2.183)).toBe('97.817');
  });

  it('renders no legal share as noise, over the whole 3-decimal domain', () => {
    // The property, not three examples: for every share the service would
    // accept, the unassigned remainder prints as a plain ≤3dp number.
    const shape = /^\d{1,3}(\.\d{1,3})?$/;
    for (let thousandths = 1; thousandths <= 100_000; thousandths += 1) {
      const share = thousandths / 1000;
      expect(formatPct(100 - share)).toMatch(shape);
    }
  });

  it('renders a non-finite value as an em dash rather than "NaN%"', () => {
    expect(formatPct(Number.NaN)).toBe('—');
    expect(formatPct(Number.POSITIVE_INFINITY)).toBe('—');
  });
});
