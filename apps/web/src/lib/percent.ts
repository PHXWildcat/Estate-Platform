/**
 * Percentages, rendered at the precision the wire actually carries.
 *
 * Shares cross the API as JSON numbers, and the service's own `PctSchema`
 * admits at most THREE decimal places — so 3dp is not a display preference,
 * it is the full precision of the value being shown, and rounding there can
 * never hide a digit the server sent.
 *
 * The reason this exists is ARITHMETIC, not display. A server-supplied share
 * renders fine on its own; `100 - total.sharePct` does not, because IEEE-754
 * subtraction turns 2.058 into `97.94200000000001% unassigned` — measured
 * across the legal 3-decimal domain, 32,448 of ~100,000 valid shares render
 * float noise that way (M19 PR3 review). This is the `formatMoney` rule
 * arriving for the other numeric type in the product: a number a person reads
 * goes through a formatter, and the moment one is computed rather than echoed
 * that stops being style and becomes correctness.
 *
 * Applied to echoed values too, deliberately — one function for every
 * percentage on the surface means the next computed one cannot skip it by
 * looking like all the others.
 */
export function formatPct(value: number): string {
  if (!Number.isFinite(value)) {
    return '—';
  }
  // toFixed(3) then trim: '66.667' stays, '40.000' becomes '40', and the
  // rounding is a no-op for anything the server could legitimately send.
  const fixed = value.toFixed(3);
  return fixed.includes('.') ? fixed.replace(/\.?0+$/, '') : fixed;
}
