import { createHash } from 'node:crypto';
import { TemplateEngine, TemplateIntegrityError, templateObjectKey } from '../src/template-engine';
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
