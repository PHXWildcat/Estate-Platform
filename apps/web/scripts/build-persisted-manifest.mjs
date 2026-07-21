/**
 * Builds apps/web/persisted-manifest.json from src/graphql/operations.ts.
 *
 * The manifest maps lowercase-hex sha256(document) -> document and is checked
 * in; the BFF allowlists these hashes (persisted queries). Workflow: edit
 * operations.ts, run `node scripts/build-persisted-manifest.mjs`, commit both.
 * A jest test (src/graphql/persisted-manifest.test.ts) re-derives the hashes
 * from the TypeScript module and fails CI if the manifest drifts.
 *
 * operations.ts documents are extracted with a line-anchored pattern; the file
 * documents the format contract (no interpolation, no nested backticks). Any
 * extraction mistake is caught by the sync test, which imports the real module.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const webRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const operationsPath = join(webRoot, 'src', 'graphql', 'operations.ts');
const manifestPath = join(webRoot, 'persisted-manifest.json');

const source = readFileSync(operationsPath, 'utf8');
const documentPattern = /^export const (\w+_(?:MUTATION|QUERY)) = `([^`]+)`;$/gm;

const documents = [];
for (const match of source.matchAll(documentPattern)) {
  documents.push({ name: match[1], document: match[2] });
}

if (documents.length === 0) {
  process.stderr.write('No operation documents found in operations.ts — format drift?\n');
  process.exit(1);
}

const entries = documents
  .map(({ document }) => [createHash('sha256').update(document, 'utf8').digest('hex'), document])
  .sort(([a], [b]) => (a < b ? -1 : 1));

const manifest = Object.fromEntries(entries);
if (Object.keys(manifest).length !== documents.length) {
  process.stderr.write('Duplicate operation documents detected — hashes collide.\n');
  process.exit(1);
}

writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
process.stdout.write(`Wrote ${documents.length} persisted operations to persisted-manifest.json\n`);
