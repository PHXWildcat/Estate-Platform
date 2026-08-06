import { createHash } from 'node:crypto';
import {
  TEMPLATE_CACHE_MAX_ENTRIES,
  TEMPLATE_CACHE_TTL_MS,
  TemplateEngine,
  TemplateIntegrityError,
  templateObjectKey,
} from '../src/template-engine';
import { FakeTemplates, MemoryObjectStore, publishSourceToFakes, sampleSource } from './support';

describe('TemplateEngine', () => {
  it('loads, verifies, parses, and caches a published template', async () => {
    const store = new MemoryObjectStore();
    const templates = new FakeTemplates();
    const row = await publishSourceToFakes(sampleSource(), store, templates);
    const engine = new TemplateEngine(store);
    const source = await engine.load(row);
    expect(source.docType).toBe('will');
    // Cached: removing the object does not break subsequent loads.
    store.objects.delete(row.body_ref);
    await expect(engine.load(row)).resolves.toEqual(source);
  });

  it('fails closed on a tampered body (hash mismatch)', async () => {
    const store = new MemoryObjectStore();
    const templates = new FakeTemplates();
    const row = await publishSourceToFakes(sampleSource(), store, templates);
    const tampered = sampleSource();
    tampered.body[0]!.text = 'I leave everything to the attacker.';
    store.objects.set(row.body_ref, Buffer.from(JSON.stringify(tampered), 'utf8'));
    await expect(new TemplateEngine(store).load(row)).rejects.toThrow(TemplateIntegrityError);
  });

  it('fails closed when body identity disagrees with the row', async () => {
    const store = new MemoryObjectStore();
    const templates = new FakeTemplates();
    // Publish a TX body, then point a CA row at it with a "correct" hash.
    const foreign = sampleSource({ state: 'TX' });
    const bytes = Buffer.from(JSON.stringify(foreign), 'utf8');
    const row = await publishSourceToFakes(sampleSource(), store, templates);
    store.objects.set(row.body_ref, bytes);
    row.body_sha256 = createHash('sha256').update(bytes).digest();
    await expect(new TemplateEngine(store).load(row)).rejects.toThrow(TemplateIntegrityError);
  });

  it('derives deterministic object keys', () => {
    expect(templateObjectKey('will', 'CA', 3)).toBe('templates/CA/will/v3.json');
  });
});

/**
 * Cache expiry (M12 follow-up). The cache key `(row id, sha)` commits to the
 * content — an entry can only ever be a parse whose bytes hashed to the sha in
 * its own key, and a published version is immutable — so a warm cache has never
 * been able to SERVE a tampered parse. What it cost was DETECTION: the process
 * stopped looking at the object, so a swapped body went unremarked for the
 * process's lifetime, and M12 had just wired an audit event to that check.
 */
describe('cache expiry keeps the pin a detector, not just a gate', () => {
  /** Store that records every read, so cache hits are observable. */
  class CountingStore extends MemoryObjectStore {
    reads = 0;
    override get(key: string): Promise<Buffer> {
      this.reads += 1;
      return super.get(key);
    }
  }

  async function fixture(): Promise<{
    store: CountingStore;
    row: Awaited<ReturnType<typeof publishSourceToFakes>>;
    clock: { now: number };
    engine: TemplateEngine;
  }> {
    const store = new CountingStore();
    const templates = new FakeTemplates();
    const row = await publishSourceToFakes(sampleSource(), store, templates);
    const clock = { now: 1_000_000 };
    const engine = new TemplateEngine(store, () => clock.now);
    return { store, row, clock, engine };
  }

  it('serves from cache inside the window, and re-verifies after it', async () => {
    const { store, row, clock, engine } = await fixture();
    await engine.load(row);
    expect(store.reads).toBe(1);

    clock.now += TEMPLATE_CACHE_TTL_MS - 1;
    await engine.load(row);
    expect(store.reads).toBe(1);

    clock.now += 1;
    await engine.load(row);
    expect(store.reads).toBe(2);
  });

  it('NOTICES a body swapped under an unchanged pin, which is the whole point', async () => {
    // Before expiry existed this returned the legitimate cached parse forever:
    // never wrong, and never reported. The row is untouched — only the object
    // store is — so the cache key does not change and nothing else would miss.
    const { store, row, clock, engine } = await fixture();
    await engine.load(row);

    const tampered = sampleSource();
    tampered.body[0]!.text = 'I leave everything to the attacker.';
    store.objects.set(row.body_ref, Buffer.from(JSON.stringify(tampered), 'utf8'));

    // Inside the window it is still the good parse — not the attacker's text.
    await expect(engine.load(row)).resolves.toEqual(
      expect.objectContaining({ docType: 'will', state: 'CA' }),
    );

    clock.now += TEMPLATE_CACHE_TTL_MS;
    await expect(engine.load(row)).rejects.toThrow(TemplateIntegrityError);
  });

  it('DROPS the stale entry when it detects, rather than serving it out the window', async () => {
    const { store, row, clock, engine } = await fixture();
    await engine.load(row);
    store.objects.set(row.body_ref, Buffer.from('{"docType":"will"}', 'utf8'));

    clock.now += TEMPLATE_CACHE_TTL_MS;
    await expect(engine.load(row)).rejects.toThrow(TemplateIntegrityError);
    // The next call must not fall back on the entry the last one disproved,
    // even though the clock has barely moved.
    await expect(engine.load(row)).rejects.toThrow(TemplateIntegrityError);
  });

  it('bounds the cache, so a long-lived process cannot grow without limit', async () => {
    // The key space grows with every republication (a new version is a NEW
    // ROW), so an unevicted map is unbounded in principle.
    const { store, row, engine } = await fixture();
    const rows = Array.from({ length: TEMPLATE_CACHE_MAX_ENTRIES + 8 }, (_, i) => ({
      ...row,
      id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
    }));
    for (const r of rows) {
      await engine.load(r);
    }
    const readsAfterFill = store.reads;
    // The most recently verified entries are still warm…
    await engine.load(rows[rows.length - 1]!);
    expect(store.reads).toBe(readsAfterFill);
    // …and the oldest was evicted, so it costs a read (and a re-verify).
    await engine.load(rows[0]!);
    expect(store.reads).toBe(readsAfterFill + 1);
  });

  it('never serves one row’s parse under another row’s sha', async () => {
    // The key commits to the content, which is why expiry is about detection
    // rather than correctness. A different sha is a different key, full stop.
    const { row, engine, store } = await fixture();
    await engine.load(row);
    const readsAfterWarm = store.reads;
    const impostor = { ...row, body_sha256: Buffer.alloc(32, 0xab) };
    await expect(engine.load(impostor)).rejects.toThrow(TemplateIntegrityError);
    expect(store.reads).toBe(readsAfterWarm + 1);
  });
});
