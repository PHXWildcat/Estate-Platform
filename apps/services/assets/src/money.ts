/**
 * Exact decimal arithmetic for money (≤2dp strings) and NUMERIC(6,3)
 * percentages, on BigInt — the ledger must never accumulate float error.
 */

/** "1234.5" → 123450n (cents). Input must match MoneySchema. */
export function moneyToCents(value: string): bigint {
  const [whole = '0', frac = ''] = value.split('.');
  return BigInt(whole) * 100n + BigInt(frac.padEnd(2, '0') || '0');
}

/** 123450n → "1234.50". */
export function centsToMoney(cents: bigint): string {
  const negative = cents < 0n;
  const abs = negative ? -cents : cents;
  const whole = abs / 100n;
  const frac = (abs % 100n).toString().padStart(2, '0');
  return `${negative ? '-' : ''}${whole.toString()}.${frac}`;
}

/** 12.345 (≤3dp, validated by PctSchema) → 12345n (milli-percent). */
export function pctToMilli(pct: number): bigint {
  return BigInt(Math.round(pct * 1000));
}

/** Owner's share of a value: cents × pct/100, rounded half-up to a cent. */
export function ownedShareCents(cents: bigint, pct: number): bigint {
  return (cents * pctToMilli(pct) + 50_000n) / 100_000n;
}

/** Normalize a percentage for a NUMERIC(6,3) column ("12.345"). */
export function pctToSql(pct: number): string {
  const milli = pctToMilli(pct);
  const whole = milli / 1000n;
  const frac = (milli % 1000n).toString().padStart(3, '0');
  return `${whole.toString()}.${frac}`;
}

/** Parse a NUMERIC(6,3) column value back to a number. */
export function sqlToPct(value: string): number {
  return Number(value);
}
