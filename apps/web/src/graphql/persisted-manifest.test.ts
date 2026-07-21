import { createHash } from 'node:crypto';
import manifestJson from '../../persisted-manifest.json';
import { operations } from './operations';

const manifest = manifestJson as Record<string, string>;

function sha256Hex(document: string): string {
  return createHash('sha256').update(document, 'utf8').digest('hex');
}

describe('persisted-manifest.json', () => {
  it('contains exactly the documents defined in operations.ts', () => {
    const manifestDocuments = Object.values(manifest).sort();
    const operationDocuments = Object.values(operations).slice().sort();
    expect(manifestDocuments).toEqual(operationDocuments);
  });

  it('keys every document by its lowercase hex sha256 (regenerate with `node scripts/build-persisted-manifest.mjs` if this fails)', () => {
    for (const document of Object.values(operations)) {
      const hash = sha256Hex(document);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      expect(manifest[hash]).toBe(document);
    }
  });

  it('has no stray entries', () => {
    expect(Object.keys(manifest)).toHaveLength(Object.keys(operations).length);
  });
});
