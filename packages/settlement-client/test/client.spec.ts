import { randomUUID } from 'node:crypto';
import { HttpSettlementAuthority, type FetchLike } from '../src/client';

const CASE_ID = randomUUID();
const OWNER_ID = randomUUID();
const DOC_ID = randomUUID();

function clientWith(fetchImpl: FetchLike): HttpSettlementAuthority {
  return new HttpSettlementAuthority({ settlementUrl: 'http://settlement.internal/', fetchImpl });
}

function okResponse(body: unknown): ReturnType<FetchLike> {
  return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
}

describe('HttpSettlementAuthority.checkEvidenceRead (fail closed)', () => {
  it('allows on a well-formed allow with case and owner ids, forwarding the bearer', async () => {
    const seen: { url: string | null; auth: string | null } = { url: null, auth: null };
    const client = clientWith((url, init) => {
      seen.url = url;
      seen.auth = init.headers['authorization'] ?? null;
      return okResponse({ allowed: true, caseId: CASE_ID, ownerUserId: OWNER_ID });
    });
    const result = await client.checkEvidenceRead({
      bearerToken: 'operator-token',
      documentId: DOC_ID,
      version: 3,
    });
    expect(result).toEqual({ allowed: true, caseId: CASE_ID, ownerUserId: OWNER_ID });
    expect(seen.auth).toBe('Bearer operator-token');
    // Trailing slash stripped; question encoded in the query string.
    expect(seen.url).toBe(
      `http://settlement.internal/v1/settlement/authority/evidence-read?documentId=${DOC_ID}&version=3`,
    );
  });

  it.each<[string, FetchLike]>([
    ['network error', () => Promise.reject(new Error('ECONNREFUSED'))],
    ['non-2xx', () => Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) })],
    [
      'body that fails to parse',
      () => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new Error('x')) }),
    ],
    ['contract drift', () => okResponse({ nope: true })],
    ['explicit refusal', () => okResponse({ allowed: false, caseId: null, ownerUserId: null })],
    [
      'allow missing the case id (malformed authority)',
      () => okResponse({ allowed: true, caseId: null, ownerUserId: OWNER_ID }),
    ],
    [
      'allow missing the owner id (malformed authority)',
      () => okResponse({ allowed: true, caseId: CASE_ID, ownerUserId: null }),
    ],
  ])('refuses on %s', async (_label, fetchImpl) => {
    const client = clientWith(fetchImpl);
    const result = await client.checkEvidenceRead({
      bearerToken: 'operator-token',
      documentId: DOC_ID,
      version: 1,
    });
    expect(result).toEqual({ allowed: false });
  });

  it('refuses an empty bearer token without touching the network', async () => {
    let called = false;
    const client = clientWith(() => {
      called = true;
      return okResponse({ allowed: true, caseId: CASE_ID, ownerUserId: OWNER_ID });
    });
    const result = await client.checkEvidenceRead({
      bearerToken: '',
      documentId: DOC_ID,
      version: 1,
    });
    expect(result).toEqual({ allowed: false });
    expect(called).toBe(false);
  });
});
