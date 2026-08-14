import '@testing-library/jest-dom';
import { randomUUID } from 'node:crypto';

// jsdom ships no crypto.randomUUID; the app uses it for client-minted
// idempotency keys (command-id.ts). Polyfill from node so the MODULE stays a
// plain browser API call rather than carrying a test-only fallback branch.
if (typeof globalThis.crypto === 'undefined') {
  (globalThis as { crypto?: unknown }).crypto = {};
}
if (typeof globalThis.crypto.randomUUID !== 'function') {
  (globalThis.crypto as { randomUUID?: () => string }).randomUUID = () => randomUUID();
}
