import { createHash, timingSafeEqual } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { OBJECT_STORE } from './di-tokens';
import type { ObjectStore } from './object-store';
import { parseTemplateSource, type TemplateSource } from './template-model';
import type { TemplateRow } from './templates.repo';

export class TemplateIntegrityError extends Error {
  constructor() {
    super('template body failed integrity verification');
    this.name = 'TemplateIntegrityError';
  }
}

/**
 * Loads a template row's body from the object store and verifies it against
 * the row's body_sha256 pin BEFORE parsing — a replaced or bit-rotted
 * template object fails closed instead of rendering someone an altered legal
 * instrument (docs/03 TB4 tamper adversary).
 *
 * Parsed sources are cached by (template id, sha) — both immutable once
 * published — so steady-state generation costs no object-store round trip.
 */
@Injectable()
export class TemplateEngine {
  private readonly cache = new Map<string, TemplateSource>();

  constructor(@Inject(OBJECT_STORE) private readonly store: ObjectStore) {}

  async load(row: TemplateRow): Promise<TemplateSource> {
    const shaHex = row.body_sha256.toString('hex');
    const cacheKey = `${row.id}:${shaHex}`;
    const cached = this.cache.get(cacheKey);
    if (cached) {
      return cached;
    }
    const body = await this.store.get(row.body_ref);
    const digest = createHash('sha256').update(body).digest();
    if (digest.length !== row.body_sha256.length || !timingSafeEqual(digest, row.body_sha256)) {
      throw new TemplateIntegrityError();
    }
    const source = parseTemplateSource(JSON.parse(body.toString('utf8')));
    // The row is the authority on identity; a body that disagrees with its
    // own row on (docType, state, version) is a publishing defect.
    if (
      source.docType !== row.doc_type ||
      source.state !== row.state ||
      source.version !== row.version
    ) {
      throw new TemplateIntegrityError();
    }
    this.cache.set(cacheKey, source);
    return source;
  }
}

/** Deterministic object key for a template source. */
export function templateObjectKey(docType: string, state: string, version: number): string {
  return `templates/${state}/${docType}/v${version}.json`;
}
