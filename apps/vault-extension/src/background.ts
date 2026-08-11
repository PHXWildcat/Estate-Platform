import { ensureOffscreenDocument } from './offscreen-lifecycle.js';

/**
 * The service worker entry, which holds NOTHING.
 *
 * An MV3 service worker is terminated after seconds of inactivity, so it cannot
 * hold a key — and the offscreen document, which has no lifetime limit, can.
 * That inversion is the whole reason the offscreen document exists (docs/04 M16
 * decision 1), and this file is the four lines that keep one alive.
 *
 * It routes no vault message and receives no secret. Stated plainly because it
 * is a design rule rather than an isolation claim: `chrome.runtime.sendMessage`
 * broadcasts, so this context RECEIVES the same messages the offscreen document
 * does and simply does not act on them. All extension contexts are one signed
 * artifact.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const target = (message as { target?: unknown } | null)?.target;
  if (target !== 'background') return undefined;
  void ensureOffscreenDocument().then(() => {
    sendResponse({ ok: true });
  });
  return true;
});
