import { createHash, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';

/**
 * The object-store port: where encrypted content blobs live (docs/01 §2.6
 * "S3 with per-object DEKs"). Two implementations — LocalFsObjectStore for
 * dev/test and S3ObjectStore (s3-object-store.ts) for production — behind one
 * interface, mirroring the Plaid gateway pattern. Extract to a package only
 * when a second service needs object storage.
 *
 * Contract invariants, enforced by both implementations:
 *  - Keys are validated identifiers (no traversal, no absolute paths).
 *  - Objects are IMMUTABLE: a put to an existing key succeeds only if the
 *    bytes are identical (idempotent republish), otherwise it throws
 *    ObjectConflictError. Version history lives in document_versions rows;
 *    silently overwriting a blob would be a tamper path, not a feature.
 *  - The store holds OPAQUE BYTES. Content encryption happens in the service
 *    before put(); nothing here sees plaintext document content.
 */
export interface ObjectStore {
  put(key: string, body: Buffer): Promise<void>;
  /** Throws ObjectNotFoundError if the key does not exist. */
  get(key: string): Promise<Buffer>;
  exists(key: string): Promise<boolean>;
}

export class ObjectNotFoundError extends Error {
  constructor() {
    super('object not found');
    this.name = 'ObjectNotFoundError';
  }
}

export class ObjectConflictError extends Error {
  constructor() {
    super('object exists with different content');
    this.name = 'ObjectConflictError';
  }
}

/**
 * Key grammar: slash-separated segments of [A-Za-z0-9_.-], no empty segments,
 * no '.'/'..' segments, bounded length. Rejecting everything else makes path
 * traversal structurally impossible in the fs store and keeps S3 keys within
 * safe-character territory.
 */
const KEY_SEGMENT = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;

export function assertValidKey(key: string): void {
  if (key.length === 0 || key.length > 512) {
    throw new Error('invalid object key');
  }
  const segments = key.split('/');
  for (const segment of segments) {
    if (!KEY_SEGMENT.test(segment) || segment === '.' || segment === '..') {
      throw new Error('invalid object key');
    }
  }
}

/** Constant-time byte comparison (avoid content-probing via timing on put). */
function sameBytes(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

function isErrnoCode(err: unknown, code: string): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: unknown }).code === code
  );
}

/**
 * Dev/test object store on the local filesystem. NEVER runs in production
 * (config.ts refuses fs mode there). Writes are atomic: a unique temp file in
 * the same directory, then rename.
 */
export class LocalFsObjectStore implements ObjectStore {
  private readonly root: string;

  constructor(rootDir: string) {
    this.root = resolve(rootDir);
  }

  private pathFor(key: string): string {
    assertValidKey(key);
    const full = resolve(join(this.root, ...key.split('/')));
    // Defense in depth behind assertValidKey: the resolved path must stay
    // inside the root.
    if (full !== this.root && !full.startsWith(this.root + sep)) {
      throw new Error('invalid object key');
    }
    return full;
  }

  async put(key: string, body: Buffer): Promise<void> {
    const target = this.pathFor(key);
    await mkdir(dirname(target), { recursive: true });
    const existing = await this.read(target);
    if (existing !== null) {
      if (sameBytes(existing, body)) {
        return; // idempotent republish
      }
      throw new ObjectConflictError();
    }
    // Hash-suffixed temp name keeps concurrent writers of IDENTICAL content
    // from clobbering each other's temp files; rename is atomic per volume.
    const tmp = `${target}.tmp-${createHash('sha256').update(body).digest('hex').slice(0, 16)}`;
    await writeFile(tmp, body);
    await rename(tmp, target);
  }

  async get(key: string): Promise<Buffer> {
    const body = await this.read(this.pathFor(key));
    if (body === null) {
      throw new ObjectNotFoundError();
    }
    return body;
  }

  async exists(key: string): Promise<boolean> {
    try {
      await stat(this.pathFor(key));
      return true;
    } catch (err) {
      if (isErrnoCode(err, 'ENOENT')) {
        return false;
      }
      throw err;
    }
  }

  private async read(path: string): Promise<Buffer | null> {
    try {
      return await readFile(path);
    } catch (err) {
      if (isErrnoCode(err, 'ENOENT')) {
        return null;
      }
      throw err;
    }
  }
}
