/**
 * THE ONLY MODULE THAT MAY RUN CODE IN A PAGE (M16 PR3b).
 *
 * `api.ts` is the extension's one network call site and `test/fences.spec.ts`
 * enforces it, because "can anything derived from the vault password leave the
 * device" is then a one-file question. `chrome.scripting.executeScript` is the
 * SECOND way something leaves — a credential crosses into another process,
 * outside any fetch — so it gets the same treatment: one call site, named by the
 * same fence, for the same reason.
 *
 * THE POPUP ISSUES IT, not the service worker and not the offscreen document.
 * The offscreen document cannot: `chrome.runtime` is the only API available
 * there. The service worker could, and deliberately does not — `background.ts`
 * says it "holds NOTHING" and routes no vault message, and putting a decrypted
 * credential through it to save one hop would make that sentence false. So the
 * credential's whole life is: worker → offscreen → popup → `args` → the page.
 *
 * MEASURED, and it is why this can be fire-and-forget: an injection issued from
 * the popup is delivered and executed even when the popup closes in the same
 * turn. What dies with the popup is its own promise continuation — so the caller
 * may issue a fill and close, and may NOT rely on observing the outcome.
 */
import { fillIntoPage, type FillPayload } from './fill-into-page.js';

export interface FillOutcome {
  readonly ok: boolean;
  readonly filledUsername: boolean;
  readonly filledSecret: boolean;
}

/**
 * Inject the fill into the TOP FRAME of one tab.
 *
 * NO `frameIds` AND NO `allFrames`, and both absences are decisions:
 *
 *   · The top frame is the only frame this extension can name. Enumerating
 *     frames needs `webNavigation` or `tabs`, which it does not hold, so a login
 *     form inside even a same-origin subframe is not filled — stated in docs/03
 *     §6j rather than half-solved.
 *   · `allFrames` was MEASURED to return partial results silently (two of four
 *     frames, `ok: true`, no error), so a caller cannot tell "no such frame"
 *     from "not permitted". It is not in the type declaration at all.
 *
 * The credential travels as `args` because `func` is serialized for injection
 * and closes over nothing. That is the mechanism, not a preference.
 */
export async function injectFill(tabId: number, payload: FillPayload): Promise<FillOutcome> {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: fillIntoPage,
      args: [payload],
    });
    const report = results[0]?.result;
    return {
      ok: report !== undefined,
      filledUsername: report?.filledUsername ?? false,
      filledSecret: report?.filledSecret ?? false,
    };
  } catch {
    // The page navigated, the tab closed, or the activeTab grant lapsed. None of
    // those is worth a reason on screen: the user can see the field is empty,
    // and a message naming the platform error would say nothing they can act on.
    return { ok: false, filledUsername: false, filledSecret: false };
  }
}
