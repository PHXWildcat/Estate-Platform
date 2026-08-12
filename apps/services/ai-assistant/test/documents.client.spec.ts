/**
 * THE HTTP VERB WAS EXERCISED BY ZERO TESTS, and that is how search shipped
 * broken.
 *
 * `tools.spec.ts` fakes this client, and the int spec never reaches search, so
 * nothing in the suite ever observed the request `DocumentsClient` actually
 * builds. Meanwhile documents has been `@Post('documents/search')` with no
 * `@Get` since M12 — the term is a word out of the caller's own estate, and a
 * query string is the part of a request intermediaries log by default. The
 * client kept building `?q=…` and handing it to a GET-only transport, so every
 * call fell through to `@Get('documents/:documentId')`, failed `UuidSchema` and
 * 400'd: search reported unavailable EVERY time, while putting the term in the
 * one place M12 had just removed it from.
 *
 * These cases pin the request itself — verb, URL, body — because that is the
 * layer the defect lived in. The M13 rule: a test must say WHICH layer it
 * proves, and a fake of this client proves nothing about it.
 */
import { DocumentsClient } from '../src/clients/documents.client';
import type { FetchLike } from '../src/clients/http';

type Recorded = {
  url: string;
  init: { method: string; headers: Record<string, string>; body?: string };
};

const BEARER = 'caller-access-token';
const BASE = 'http://documents.internal:3004';
const TERM = 'lakehouse';

function recording(response: { ok: boolean; body: unknown }): {
  fetchImpl: FetchLike;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const fetchImpl: FetchLike = (url, init) => {
    calls.push({ url, init });
    return Promise.resolve({ ok: response.ok, json: () => Promise.resolve(response.body) });
  };
  return { fetchImpl, calls };
}

const client = (fetchImpl: FetchLike): DocumentsClient => new DocumentsClient(BASE, fetchImpl);

describe('DocumentsClient.search speaks the route documents actually exposes', () => {
  it('POSTs, because the route is POST-only and a GET 400s on the id route', async () => {
    const { fetchImpl, calls } = recording({ ok: true, body: [] });
    await client(fetchImpl).search(BEARER, TERM);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init.method).toBe('POST');
  });

  it('THE TERM NEVER APPEARS IN THE URL — the whole point of M12 moving it', async () => {
    const { fetchImpl, calls } = recording({ ok: true, body: [] });
    await client(fetchImpl).search(BEARER, TERM);
    const url = calls[0]?.url ?? '';
    expect(url).toBe(`${BASE}/v1/documents/search`);
    expect(url).not.toContain('?');
    expect(url).not.toContain(TERM);
  });

  it('sends the term as `query`, the key documents’ strict schema accepts', async () => {
    // `SearchRequestSchema` is `.strict()`, so `{q}` is rejected outright — the
    // key is part of the contract, not a naming preference.
    const { fetchImpl, calls } = recording({ ok: true, body: [] });
    await client(fetchImpl).search(BEARER, TERM);
    expect(JSON.parse(calls[0]?.init.body ?? '{}')).toEqual({ query: TERM });
    expect(calls[0]?.init.headers['content-type']).toBe('application/json');
  });

  it('forwards the CALLER’S OWN bearer and holds no credential of its own', async () => {
    const { fetchImpl, calls } = recording({ ok: true, body: [] });
    await client(fetchImpl).search(BEARER, TERM);
    expect(calls[0]?.init.headers['authorization']).toBe(`Bearer ${BEARER}`);
  });

  it('refuses without a round trip when there is no bearer', async () => {
    const { fetchImpl, calls } = recording({ ok: true, body: [] });
    expect(await client(fetchImpl).search('', TERM)).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it('keeps the flat taxonomy: a non-ok answer is null, never a partial read', async () => {
    const { fetchImpl } = recording({ ok: false, body: { error: 'not_found' } });
    // Even the peer's own not-found token collapses here — search has no
    // ABSENT case, so "no data" is the only thing it can say.
    expect(await client(fetchImpl).search(BEARER, TERM)).toBeNull();
  });

  it('returns the parsed list on success', async () => {
    const row = {
      documentId: '11111111-2222-4333-8444-555555555555',
      docType: 'will',
      title: 'Lake house deed',
      currentVersion: 2,
      executionStatus: 'executed',
      executedAt: '2026-08-12T00:00:00.000Z',
      sealed: false,
      updatedAt: '2026-08-12T00:00:00.000Z',
    };
    const { fetchImpl } = recording({ ok: true, body: [row] });
    const result = await client(fetchImpl).search(BEARER, TERM);
    expect(result).toHaveLength(1);
    expect(result?.[0]?.title).toBe('Lake house deed');
  });
});
