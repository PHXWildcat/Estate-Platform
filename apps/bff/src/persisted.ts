import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { ConfigError } from './config';

/**
 * Persisted-operations manifest: a JSON object mapping the lowercase hex
 * sha256 of a GraphQL document to that document's source text. Produced at
 * client build time; the client sends only
 * `extensions.persistedQuery.sha256Hash`.
 *
 * In production ONLY manifest hashes execute (allowArbitraryOperations is
 * false); in dev/test arbitrary operations are also allowed.
 */
export type PersistedOperationsManifest = ReadonlyMap<string, string>;

const SHA256_HEX = /^[0-9a-f]{64}$/;

const ManifestSchema = z.record(z.string().regex(SHA256_HEX), z.string().min(1));

/** Loads and validates the manifest. Empty manifest when path is null. */
export function loadPersistedManifest(path: string | null): PersistedOperationsManifest {
  if (path === null) {
    return new Map();
  }
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    throw new ConfigError(['PERSISTED_MANIFEST_PATH: manifest file is not readable']);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ConfigError(['PERSISTED_MANIFEST_PATH: manifest is not valid JSON']);
  }
  const manifest = ManifestSchema.safeParse(parsed);
  if (!manifest.success) {
    // Shape errors only — never manifest contents.
    throw new ConfigError([
      'PERSISTED_MANIFEST_PATH: manifest must map lowercase hex sha256 keys to GraphQL documents',
    ]);
  }
  // Map keeps lookups own-property-only (no prototype-chain surprises).
  return new Map(Object.entries(manifest.data));
}
