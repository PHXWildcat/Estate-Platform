import { randomUUID } from 'node:crypto';
import { HttpSettlementAuthority, SERVICE_CREDENTIAL_HEADER, type FetchLike } from '../src/client';

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

describe('HttpSettlementAuthority.checkStageAccess (executor staged access)', () => {
  it('allows on a well-formed allow, forwarding the caller bearer and the stage', async () => {
    const seen: { url: string | null; auth: string | null } = { url: null, auth: null };
    const client = clientWith((url, init) => {
      seen.url = url;
      seen.auth = init.headers['authorization'] ?? null;
      return okResponse({ allowed: true, caseId: CASE_ID });
    });
    await expect(
      client.checkStageAccess({
        bearerToken: 'exec-token',
        ownerUserId: OWNER_ID,
        stage: 'inventory',
      }),
    ).resolves.toEqual({ allowed: true, caseId: CASE_ID });
    expect(seen.auth).toBe('Bearer exec-token');
    expect(seen.url).toContain('/v1/settlement/authority/stage-access');
    expect(seen.url).toContain('stage=inventory');
  });

  it.each<[string, FetchLike]>([
    ['network error', () => Promise.reject(new Error('ECONNREFUSED'))],
    ['non-2xx', () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) })],
    ['contract drift', () => okResponse({ nope: true })],
    ['explicit refusal', () => okResponse({ allowed: false, caseId: null })],
    ['allow without a case id', () => okResponse({ allowed: true, caseId: null })],
  ])('refuses on %s', async (_label, fetchImpl) => {
    await expect(
      clientWith(fetchImpl).checkStageAccess({
        bearerToken: 'exec-token',
        ownerUserId: OWNER_ID,
        stage: 'vault',
      }),
    ).resolves.toEqual({ allowed: false });
  });

  it('refuses an empty bearer without touching the network', async () => {
    let called = false;
    const client = clientWith(() => {
      called = true;
      return okResponse({ allowed: true, caseId: CASE_ID });
    });
    await expect(
      client.checkStageAccess({ bearerToken: '', ownerUserId: OWNER_ID, stage: 'inventory' }),
    ).resolves.toEqual({ allowed: false });
    expect(called).toBe(false);
  });
});

describe('HttpSettlementAuthority.checkVaultRelease (the Zone A gate)', () => {
  function gateClient(
    fetchImpl: FetchLike,
    credential = 'svc-credential',
  ): HttpSettlementAuthority {
    return new HttpSettlementAuthority({
      settlementUrl: 'http://settlement.internal',
      serviceCredential: credential,
      fetchImpl,
    });
  }

  it('permits when settlement says so, authenticating with the SERVICE credential', async () => {
    const seen: { auth: string | null; cred: string | null } = { auth: null, cred: null };
    const client = gateClient((_url, init) => {
      seen.auth = init.headers['authorization'] ?? null;
      seen.cred = init.headers[SERVICE_CREDENTIAL_HEADER] ?? null;
      return okResponse({ permitted: true, caseId: null });
    });
    await expect(client.checkVaultRelease({ ownerUserId: OWNER_ID })).resolves.toEqual({
      permitted: true,
      caseId: null,
    });
    // Never a user bearer: a grantee's token must not mint this answer.
    expect(seen.auth).toBeNull();
    expect(seen.cred).toBe('svc-credential');
  });

  it('reports a block with the case id so the vault can audit it', async () => {
    const client = gateClient(() => okResponse({ permitted: false, caseId: CASE_ID }));
    await expect(client.checkVaultRelease({ ownerUserId: OWNER_ID })).resolves.toEqual({
      permitted: false,
      caseId: CASE_ID,
    });
  });

  it.each<[string, FetchLike]>([
    ['network error', () => Promise.reject(new Error('ECONNREFUSED'))],
    ['non-2xx', () => Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) })],
    [
      'unparseable body',
      () => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new Error('x')) }),
    ],
    ['contract drift', () => okResponse({ nope: true })],
  ])('BLOCKS on %s — an unreachable settlement never opens Zone A', async (_label, fetchImpl) => {
    await expect(
      gateClient(fetchImpl).checkVaultRelease({ ownerUserId: OWNER_ID }),
    ).resolves.toEqual({ permitted: false, caseId: null });
  });

  it('blocks locally when the service credential is unwired, saving the round trip', async () => {
    let called = false;
    const client = gateClient(() => {
      called = true;
      return okResponse({ permitted: true, caseId: null });
    }, '');
    await expect(client.checkVaultRelease({ ownerUserId: OWNER_ID })).resolves.toEqual({
      permitted: false,
      caseId: null,
    });
    expect(called).toBe(false);
  });
});
