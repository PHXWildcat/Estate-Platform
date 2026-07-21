import { createHash } from 'node:crypto';
import type { AuditEvent } from '@estate/contracts';
import { canonicalize } from './canonical';

/**
 * The chain starts from 32 zero bytes (matches the seed row written to
 * `audit_chain_head` by migration 001). Part of the chain-format v1 contract.
 */
export const GENESIS_HASH: Buffer = Buffer.alloc(32, 0);

/** SHA-256 output length in bytes; every link in the chain is this size. */
export const HASH_LENGTH = 32;

/**
 * Chain-format v1 hash recipe:
 *
 *   event_hash = SHA-256(prev_hash || canonicalize(event))
 *
 * where `||` is byte concatenation and `canonicalize` is the deterministic
 * encoding in ./canonical.ts. See that file's doc comment — neither this
 * recipe nor the canonicalization may change without a chain-format version
 * bump.
 */
export function computeEventHash(prevHash: Buffer, event: AuditEvent): Buffer {
  if (prevHash.length !== HASH_LENGTH) {
    throw new Error(`computeEventHash: prevHash must be ${HASH_LENGTH} bytes`);
  }
  return createHash('sha256').update(prevHash).update(canonicalize(event)).digest();
}
