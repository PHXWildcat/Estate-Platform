import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertValidKey,
  LocalFsObjectStore,
  ObjectConflictError,
  ObjectNotFoundError,
} from '../src/object-store';

describe('assertValidKey', () => {
  it('accepts slash-separated identifier segments', () => {
    expect(() => assertValidKey('templates/CA/will/v1.json')).not.toThrow();
    expect(() => assertValidKey('documents/abc-123/v1-deadbeef')).not.toThrow();
  });

  it.each([
    '',
    '/leading',
    'trailing/',
    'a//b',
    '../escape',
    'a/../b',
    'a/./b',
    'a\\b',
    'a b',
    'a/{b}',
    '.hidden-first-char-dot/x',
    'x'.repeat(513),
  ])('rejects %j', (key) => {
    expect(() => assertValidKey(key)).toThrow('invalid object key');
  });
});

describe('LocalFsObjectStore', () => {
  let dir: string;
  let store: LocalFsObjectStore;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'estate-objstore-'));
    store = new LocalFsObjectStore(dir);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('round-trips bytes and reports existence', async () => {
    const body = Buffer.from('opaque ciphertext bytes');
    await store.put('documents/d1/v1-abc', body);
    expect(await store.exists('documents/d1/v1-abc')).toBe(true);
    expect((await store.get('documents/d1/v1-abc')).equals(body)).toBe(true);
    expect(await store.exists('documents/d1/v2-abc')).toBe(false);
  });

  it('throws ObjectNotFoundError for missing keys', async () => {
    await expect(store.get('missing/key')).rejects.toThrow(ObjectNotFoundError);
  });

  it('is immutable: identical re-put is a no-op, different bytes conflict', async () => {
    const body = Buffer.from('v1 bytes');
    await store.put('k/x', body);
    await expect(store.put('k/x', Buffer.from('v1 bytes'))).resolves.toBeUndefined();
    await expect(store.put('k/x', Buffer.from('tampered'))).rejects.toThrow(ObjectConflictError);
    expect((await store.get('k/x')).equals(body)).toBe(true);
  });

  it('refuses traversal keys before touching the filesystem', async () => {
    await expect(store.put('../outside', Buffer.from('x'))).rejects.toThrow('invalid object key');
    await expect(store.get('..')).rejects.toThrow('invalid object key');
  });
});
