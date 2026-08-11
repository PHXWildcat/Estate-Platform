import { mountPopup } from './popup.js';

/**
 * The popup's entry point. Three lines around code the suite drives directly —
 * the same shape as `vault-web`'s two `main.ts` files, and 0% covered for the
 * same stated reason: a test that imports one only proves it can be imported.
 */
const root = document.getElementById('root');
if (root) {
  void mountPopup({ root });
}
