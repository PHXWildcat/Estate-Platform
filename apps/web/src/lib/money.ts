/**
 * Display formatting for ledger decimal strings. Money is NEVER parsed into a
 * float anywhere in this app — grouping is pure string manipulation, so a
 * value wider than Number.MAX_SAFE_INTEGER renders digit-perfect.
 */

const DECIMAL_STRING = /^-?\d+(\.\d+)?$/;

/**
 * "739700.00" → "$739,700.00"; null → "—" (an unvalued asset is a fact, not a
 * zero). Anything that is not a plain decimal string is rendered verbatim
 * behind the dollar sign rather than guessed at.
 */
export function formatMoney(value: string | null): string {
  if (value === null) return '—';
  if (!DECIMAL_STRING.test(value)) return `$${value}`;
  const negative = value.startsWith('-');
  const unsigned = negative ? value.slice(1) : value;
  const dot = unsigned.indexOf('.');
  const whole = dot === -1 ? unsigned : unsigned.slice(0, dot);
  const fraction = dot === -1 ? null : unsigned.slice(dot + 1);
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const sign = negative ? '-' : '';
  return fraction === null ? `${sign}$${grouped}` : `${sign}$${grouped}.${fraction}`;
}
