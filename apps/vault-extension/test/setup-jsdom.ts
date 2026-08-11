/**
 * Platform APIs jsdom omits that every real browser (and every extension
 * context) has.
 *
 * `structuredClone` is the one that matters here, and unlike `vault-web` — which
 * installs an IDENTITY function and says so, because all its device store needs
 * is that a stored copy survives the caller wiping its buffer — this one has to
 * be REAL.
 *
 * The reason is what the fixture is for. `chrome.storage.local` stores
 * structured clones, so a value the platform cannot persist must fail in the
 * suite rather than in someone's browser; that is the property `session.spec.ts`
 * leans on when it asserts nothing but tokens is ever written. An identity
 * function would accept anything at all and quietly turn that assertion into a
 * statement about the fixture.
 *
 * `v8.serialize`/`deserialize` implements the same algorithm Node's own
 * `structuredClone` is built on, and throws on the values a real clone throws
 * on. What it does NOT exercise is a browser's implementation, or the actual
 * `chrome.storage` quota and serialisation — that is what loading the unpacked
 * artifact is for, and neither substitutes for the other.
 */
import { webcrypto } from 'node:crypto';
import { deserialize, serialize } from 'node:v8';
import { TextDecoder, TextEncoder } from 'node:util';

if (typeof globalThis.structuredClone === 'undefined') {
  Object.defineProperty(globalThis, 'structuredClone', {
    value: (value: unknown): unknown => deserialize(serialize(value)),
    writable: true,
  });
}

/*
 * WEBCRYPTO AND THE ENCODERS, for the same reason `vault-web` installs them:
 * jsdom ships no `crypto.subtle`, no `getRandomValues` and no `TextEncoder`,
 * and the key holder uses all of them.
 *
 * These are NODE'S OWN implementations of the same specifications (W3C
 * WebCrypto, WHATWG Encoding), so the suite exercises the real PBKDF2, the real
 * AES-GCM and the real CSPRNG rather than a stub — which is what makes a
 * genuine SRP round trip meaningful. What it does NOT exercise is a BROWSER's
 * implementation, or an extension worker's; that is what loading the unpacked
 * artifact is for, and neither substitutes for the other.
 *
 * Without them the failure is worse than a red test: `vault-crypto` would throw
 * on `crypto.subtle`, a `catch` would report the item as unreadable, and a
 * "passing" assertion could describe an error path no browser ever takes — the
 * M15 PR1 lesson, where a missing `Response` global made a client report
 * NETWORK and it looked like a result.
 */
if (typeof globalThis.TextEncoder === 'undefined') {
  Object.defineProperty(globalThis, 'TextEncoder', { value: TextEncoder, writable: true });
}
if (typeof globalThis.TextDecoder === 'undefined') {
  Object.defineProperty(globalThis, 'TextDecoder', { value: TextDecoder, writable: true });
}
if (globalThis.crypto?.subtle === undefined) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, writable: true });
}
