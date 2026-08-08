/**
 * Platform APIs jsdom omits that every real browser has.
 *
 * jsdom is a DOM implementation, not a browser: it ships no `TextEncoder`, no
 * `TextDecoder`, no `crypto.subtle` and no `crypto.getRandomValues`. The vault
 * client uses all four, so without this the suite would report failures that
 * say nothing about the code — and, worse, a test could "pass" by taking an
 * error path that a browser never takes (the M15 PR1 lesson, where a missing
 * `Response` global made `request` report NETWORK and looked like a real
 * result).
 *
 * These are Node's own implementations of the SAME specifications: WHATWG
 * Encoding and W3C WebCrypto. Using them means the suite exercises the real
 * PBKDF2, the real AES-GCM and the real CSPRNG rather than a stub — which is
 * what makes `no-key-material-egress.spec.ts` meaningful. What it does NOT
 * exercise is a browser's implementation of them; that is what driving the live
 * stack in a real browser is for, and neither substitutes for the other.
 *
 * `structuredClone` is the one stand-in that is NOT Node's own: the identity
 * function is enough for `fake-indexeddb` to store an ArrayBuffer, and the
 * device store's own test asserts the property that actually matters (a stored
 * COPY survives the caller wiping its buffer) by wiping and re-reading.
 */
import { webcrypto } from 'node:crypto';
import { TextDecoder, TextEncoder } from 'node:util';

if (typeof globalThis.TextEncoder === 'undefined') {
  Object.defineProperty(globalThis, 'TextEncoder', { value: TextEncoder, writable: true });
}
if (typeof globalThis.TextDecoder === 'undefined') {
  Object.defineProperty(globalThis, 'TextDecoder', { value: TextDecoder, writable: true });
}
if (globalThis.crypto?.subtle === undefined) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, writable: true });
}
if (typeof globalThis.structuredClone === 'undefined') {
  // IndexedDB stores structured clones, so the device store needs it. Node has
  // had it globally since 17; the jsdom environment does not expose it.
  Object.defineProperty(globalThis, 'structuredClone', {
    value: (value: unknown) => value,
    writable: true,
  });
}
