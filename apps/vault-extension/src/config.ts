/**
 * WHERE THIS EXTENSION IS ALLOWED TO TALK.
 *
 * The value comes from `origin.ts`, which the build writes from the same
 * `VAULT_ORIGIN` it puts in the manifest — see that file for why it is no
 * longer read back out of `chrome.runtime.getManifest()` (an offscreen document
 * cannot call it, and the key holder lives in one).
 *
 * IT IS STILL PARSED RATHER THAN TRUSTED. A wildcard host or a value that is
 * not an exact origin would mean this artifact could be pointed somewhere
 * nobody reviewed, and the build is not the only way this constant could ever
 * be edited.
 *
 * `test/manifest.spec.ts` asserts the constant and the manifest's
 * `host_permissions` agree in a REAL build, which is what keeps two places
 * holding one value honest.
 */
import { PACKAGED_VAULT_ORIGIN } from './origin.js';

export class ExtensionConfigError extends Error {}

/**
 * Exported so the refusals are testable WITHOUT mocking a module constant.
 *
 * The alternative was `jest.mock` over `origin.ts`, which would prove that a
 * mocked constant produces a thrown error and nothing about the real one. This
 * way the validation is exercised directly with the values it exists to refuse,
 * and `vaultOrigin` is the one-line application of it.
 */
export function assertExactOrigin(value: string): string {
  const declared = value.replace(/\/\*$/, '').replace(/\/$/, '');
  let parsed: URL;
  try {
    parsed = new URL(declared);
  } catch {
    throw new ExtensionConfigError('packaged vault origin is not a URL');
  }
  if (parsed.hostname.includes('*') || parsed.origin !== declared) {
    throw new ExtensionConfigError('packaged vault origin is not an exact origin');
  }
  return parsed.origin;
}

export function vaultOrigin(): string {
  return assertExactOrigin(PACKAGED_VAULT_ORIGIN);
}
