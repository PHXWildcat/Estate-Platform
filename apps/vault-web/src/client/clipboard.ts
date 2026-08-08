/**
 * Copy a secret, then clear it (docs/03 §4 TB6 asks for clipboard auto-clear).
 *
 * WHAT THIS DOES NOT DO, said here rather than discovered later, because the
 * UI's wording depends on it being honest:
 *
 *   · It cannot READ the clipboard to check whether our value is still there —
 *     that needs a permission this app will not ask for. So the clear is
 *     unconditional, and if the user copied something else in the meantime this
 *     overwrites THEIR value. Twenty seconds is chosen against that: long
 *     enough to paste, short enough that an intervening copy is unlikely.
 *   · It cannot reach a clipboard MANAGER, a synced clipboard, or another
 *     device. Those keep history by design and nothing in a web page touches
 *     them.
 *   · A page that is closed before the timer fires never clears at all.
 *
 * Best effort, and the UI says "clears in 20 seconds" rather than implying the
 * secret is gone from everywhere.
 */

export const CLIPBOARD_CLEAR_MS = 20_000;

export type CopyOutcome = 'copied' | 'unavailable';

let pending: ReturnType<typeof setTimeout> | null = null;

/**
 * Copy `value`, scheduling a clear. A second copy CANCELS the first timer
 * rather than adding another — otherwise copying twice in quick succession
 * would have the first timer wipe the second value early.
 */
export async function copyWithAutoClear(value: string): Promise<CopyOutcome> {
  if (!navigator.clipboard?.writeText) {
    // Insecure context or a browser without the API. Reported so the UI can
    // tell the user to select the field instead of silently doing nothing.
    return 'unavailable';
  }
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    return 'unavailable';
  }
  if (pending !== null) {
    clearTimeout(pending);
  }
  pending = setTimeout(() => {
    pending = null;
    // Writing an empty string is the only clear a page can perform. Failure is
    // ignored: the tab may have lost focus, which browsers treat as grounds to
    // refuse a clipboard write, and there is nothing useful to say about it.
    void navigator.clipboard.writeText('').catch(() => undefined);
  }, CLIPBOARD_CLEAR_MS);
  return 'copied';
}

/** Cancel a pending clear — used when the vault locks and clears immediately. */
export function clearNow(): void {
  if (pending !== null) {
    clearTimeout(pending);
    pending = null;
  }
  void navigator.clipboard?.writeText('').catch(() => undefined);
}
