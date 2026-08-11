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
import { deserialize, serialize } from 'node:v8';

if (typeof globalThis.structuredClone === 'undefined') {
  Object.defineProperty(globalThis, 'structuredClone', {
    value: (value: unknown): unknown => deserialize(serialize(value)),
    writable: true,
  });
}
