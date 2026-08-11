/**
 * THE VAULT ORIGIN, SUBSTITUTED AT PACKAGE TIME.
 *
 * WHY THIS EXISTS AT ALL, because it replaces something better. `config.ts`
 * used to read the origin back out of `chrome.runtime.getManifest()`, so there
 * was exactly one copy of the value and nothing for it to drift against. That
 * is the right shape and it does not work: MEASURED in Chrome 151, an OFFSCREEN
 * DOCUMENT gets only `chrome.runtime`'s messaging surface — no `getManifest`,
 * no `chrome.storage` — while the popup gets the full extension API. The
 * offscreen document is where the key holder lives and therefore where every
 * vault request is made, so `vaultOrigin()` threw there on every call, `api.ts`
 * caught it as `NETWORK`, and the extension told the user to check their
 * connection. It could never have unlocked a vault.
 *
 * Nothing in jsdom could catch that: the chrome double supplies `getManifest`
 * unconditionally, so the double was more generous than the platform — the
 * fixture lesson this repo keeps relearning, one layer beneath the fixtures.
 *
 * SO THE VALUE IS WRITTEN HERE BY THE BUILD, from the same `VAULT_ORIGIN` the
 * manifest gets, in the same script, after the same validation. It is a second
 * PLACE the value appears, which is exactly what the old design avoided — so it
 * is a second place that is CHECKED: `test/manifest.spec.ts` builds a real
 * package and asserts this constant equals the manifest's `host_permissions`
 * entry. Neither can move without the other.
 *
 * The constant can never widen what the extension may reach. `host_permissions`
 * is what the BROWSER enforces, so a wrong value here produces refused requests,
 * never requests to somewhere unreviewed.
 *
 * The default is the dev stack's origin rather than a placeholder, and that is
 * deliberate: a placeholder would make every test exercise a value the product
 * never has, and `PLAID_MODE`'s lesson applies to builds too — the common case
 * is a developer loading this unpacked against the local stack.
 */
export const PACKAGED_VAULT_ORIGIN = 'http://vault.localhost:3010';
