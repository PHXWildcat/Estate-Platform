/**
 * The trust-funding percentage — the one number on the dashboard the wire does
 * not carry.
 *
 * The assets service computes exactly this figure (`inTrustPct`,
 * assets.service.ts) but the BFF's NetWorth schema strips it, so the tile
 * re-derives it from the two decimal strings the SDL does carry. The formula
 * here is the SERVICE'S OWN, kept faithful on purpose: BigInt cents, half-up
 * at one decimal place, and null when the total is zero — so if a later
 * milestone un-strips the field, the two surfaces cannot disagree.
 *
 * No floats touch money: parsing and division are BigInt end to end, and the
 * one `Number()` converts tenths-of-a-percent (an integer 0..1000), which is
 * exact. The result is a COMPUTED number, so callers render it through
 * `formatPct` (.claude/rules/frontend.md).
 */

const MONEY_STRING = /^(\d+)(?:\.(\d{1,2}))?$/;

/**
 * "739700.00" → 73970000n. Null for anything else — the ledger's totals are
 * non-negative two-decimal strings, and a value this cannot be sure of is
 * refused rather than guessed at (the @estate/money rule, applied at render):
 * the caller shows "—", never a confident wrong percentage.
 */
function moneyStringToCents(value: string): bigint | null {
  const match = MONEY_STRING.exec(value);
  if (match === null) return null;
  const whole = match[1] as string;
  const fraction = (match[2] ?? '').padEnd(2, '0');
  return BigInt(whole) * 100n + BigInt(fraction);
}

/**
 * Percent of the valued estate held in trust, at 1dp — or null when there is
 * no valued estate to measure (the service answers null there too: a
 * percentage of nothing is not 0%, it is no answer).
 */
export function trustFundingPct(inTrustValue: string, totalValue: string): number | null {
  const inTrust = moneyStringToCents(inTrustValue);
  const total = moneyStringToCents(totalValue);
  if (inTrust === null || total === null || total === 0n) return null;
  // The service's exact rounding: tenths of a percent, half-up.
  return Number((inTrust * 1000n + total / 2n) / total) / 10;
}
