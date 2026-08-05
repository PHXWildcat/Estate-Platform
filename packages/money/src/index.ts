/**
 * Exact decimal arithmetic for money (≤2dp strings) and NUMERIC(6,3)
 * percentages, on BigInt — a ledger must never accumulate float error.
 *
 * MONEY IS A DECIMAL STRING AT EVERY BOUNDARY IN THIS REPO: in the database, on
 * the wire, in GraphQL, in the UI. Cents exist only inside a calculation, which
 * is what these functions bracket. Nothing here parses money to `number`, and
 * nothing that consumes this package should either — `Number("0.1") + Number("0.2")`
 * is the whole reason this file exists.
 *
 * Extracted from `apps/services/assets/src/money.ts` in M10 PR3, unchanged, when
 * the assistant's analysers became the second consumer. The alternative was a
 * second copy, which is the shape of the bug M8 PR2 found in seven byte-identical
 * audit producers: copies do not stay identical, and the one that drifts is the
 * one nobody is looking at.
 */

/**
 * What this package will convert: an optional sign, digits, and at most two
 * fraction digits. Deliberately looser than the assets service's `MoneySchema`
 * (which additionally bounds the magnitude and forbids a sign) — the CALLER's
 * schema decides what is a legal amount in its domain; this decides only what
 * can be converted without losing a cent.
 */
const MONEY = /^-?\d+(\.\d{1,2})?$/;

/**
 * "1234.5" → 123450n (cents).
 *
 * THROWS on anything that is not a money string, rather than returning a number
 * that looks plausible. The extracted original assumed a schema-validated input
 * and split on '.', which silently mis-signed the fraction of a negative value
 * ("-12.34" → -1166n, quietly 68 cents wrong). No caller could reach it —
 * `MoneySchema` forbids the sign — but the assistant's analysers subtract, and a
 * function that answers confidently for input it cannot handle is the wrong
 * thing to hand a new consumer.
 */
export function moneyToCents(value: string): bigint {
  if (!MONEY.test(value)) {
    throw new RangeError('not a money string');
  }
  const negative = value.startsWith('-');
  const unsigned = negative ? value.slice(1) : value;
  // Split on the FIRST '.' by index rather than destructuring `split('.')` with
  // defaults. The defaults read as caution and were dead code: the regex above
  // already guarantees a whole part, so `= '0'` and `|| '0'` were branches no
  // input could take — which a 100% branch floor is exactly the right thing to
  // have noticed.
  const dot = unsigned.indexOf('.');
  const whole = dot === -1 ? unsigned : unsigned.slice(0, dot);
  const frac = dot === -1 ? '' : unsigned.slice(dot + 1);
  const cents = BigInt(whole) * 100n + BigInt(frac.padEnd(2, '0'));
  return negative ? -cents : cents;
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
