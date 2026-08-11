/**
 * One timestamp formatter for the whole app.
 *
 * It lived in `lib/documents.ts` until the paired-devices list (M16) became its
 * second consumer, and a second consumer of a formatter is where a second COPY
 * of it normally appears — the M8 PR2 shape, where seven byte-identical audit
 * producers all carried the same bug. `documents.ts` re-exports it so its own
 * consumers and tests are untouched.
 *
 * A malformed value renders as an empty string rather than "Invalid Date": both
 * are a failure to display a time, and only one of them looks like a fault in
 * the user's account.
 */
export function formatDateTime(iso: string): string {
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime())
    ? ''
    : parsed.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
