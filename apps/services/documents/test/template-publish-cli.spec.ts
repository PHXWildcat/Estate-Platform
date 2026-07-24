import { AuditEmitter } from '@estate/audit-emitter';
import { InMemoryAuditProducer } from '../src/audit-producer';
import type { Queryable } from '../src/db';
import { EXEMPLAR_REVIEW_MARKER, publishTemplates } from '../src/template-publish-cli';
import { MemoryObjectStore, sampleSource } from './support';

/** A DB that must never be reached — the guard rejects before any query. */
const rejectingDb: Queryable = {
  query: () => Promise.reject(new Error('db must not be touched')),
};

function emitter(): AuditEmitter {
  return new AuditEmitter(new InMemoryAuditProducer(), () => new Date());
}

function fileFor(source: object): { path: string; bytes: Buffer } {
  return { path: 'x.json', bytes: Buffer.from(JSON.stringify(source), 'utf8') };
}

describe('template publish CLI — production sign-off guard', () => {
  const original = process.env['NODE_ENV'];
  afterEach(() => {
    if (original === undefined) {
      delete process.env['NODE_ENV'];
    } else {
      process.env['NODE_ENV'] = original;
    }
  });

  it('refuses an attorney-unreviewed exemplar template in production', async () => {
    process.env['NODE_ENV'] = 'production';
    const source = sampleSource({
      legalReview: {
        by: `${EXEMPLAR_REVIEW_MARKER} - pending attorney review`,
        at: '2026-07-01T00:00:00.000Z',
      },
    });
    const store = new MemoryObjectStore();
    await expect(
      publishTemplates(rejectingDb, store, emitter(), [fileFor(source)]),
    ).rejects.toThrow(/attorney-unreviewed exemplar/);
    // Refusal happens before any store/DB write.
    expect(store.objects.size).toBe(0);
  });

  it('allows a genuinely-reviewed template in production (guard passes to the DB boundary)', async () => {
    process.env['NODE_ENV'] = 'production';
    const source = sampleSource({
      legalReview: { by: 'Jane Attorney, Esq. (CA Bar 123456)', at: '2026-07-01T00:00:00.000Z' },
    });
    // The guard passes, so publish proceeds to the DB — which we reject to stop
    // here. The error being the DB sentinel (not the refusal) proves the guard
    // did NOT block a genuinely-reviewed template.
    await expect(
      publishTemplates(rejectingDb, new MemoryObjectStore(), emitter(), [fileFor(source)]),
    ).rejects.toThrow('db must not be touched');
  });
});
