import type { AuditEvent } from '@estate/contracts';

/**
 * Deterministic canonical encoding of an audit event — the byte string that
 * gets hashed into the tamper-evidence chain.
 *
 * ## Contract (chain format v1) — NEVER change without a chain-format
 * version bump
 *
 * This canonicalization is part of the tamper-evidence contract: every stored
 * `event_hash` was computed over these exact bytes, so any change to the
 * rules below (key ordering, escaping, whitespace, number formatting) makes
 * every previously written chain unverifiable. If the format must evolve,
 * introduce an explicit chain-format version (persisted alongside the chain)
 * and keep this function byte-for-byte stable for v1.
 *
 * Rules:
 *  - JSON text, UTF-8 encoded, no whitespace between tokens.
 *  - Object keys sorted lexicographically by UTF-16 code units
 *    (`Array.prototype.sort` default), recursively at every depth.
 *  - Strings/numbers encoded exactly as `JSON.stringify` encodes them
 *    (non-ASCII characters are NOT `\u`-escaped; they are emitted raw and
 *    UTF-8 encoded).
 *  - Keys whose value is `undefined` are omitted (mirrors `JSON.stringify`);
 *    `null` is encoded as `null`.
 *  - Non-finite numbers and non-JSON values (functions, symbols, bigints)
 *    are an error, never silently coerced.
 *
 * Callers hash the event in its NORMALIZED, storage-equivalent form (see
 * AuditIngestor: `occurredAt` normalized to millisecond-precision ISO-8601
 * UTC) so the verifier can rebuild identical bytes from database rows.
 */
export function canonicalize(event: AuditEvent): Buffer {
  return Buffer.from(canonicalJson(event), 'utf8');
}

function canonicalJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('canonicalize: non-finite number is not representable');
      }
      return JSON.stringify(value);
    case 'object':
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
      }
      return canonicalObject(value as Record<string, unknown>);
    default:
      throw new Error(`canonicalize: unsupported value type '${typeof value}'`);
  }
}

function canonicalObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj)
    .filter((key) => obj[key] !== undefined)
    .sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(obj[key])}`);
  return `{${parts.join(',')}}`;
}
