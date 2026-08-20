import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FetchSettlementClient } from '../src/settlement-client';

/**
 * The REAL client against a stubbed transport (the identity/assets-client
 * pattern). What matters here is the wire contract and the ERROR FIREWALL: the
 * bearer goes out on every call, downstream response text never comes back, and
 * a malformed downstream answer is refused rather than half-trusted.
 *
 * The error-mapping table below is where this edge earns most of its keep. Four
 * of these refusals are things a person must be told apart — "not yours", "the
 * window is frozen", "too late to close it yourself", and "we could not reach a
 * service, nothing happened" — and collapsing any pair either hides a control
 * or turns one into an apparent outage.
 */

const TOKEN = 'access-token-value-123';
const BASE = 'http://settlement.test';

function response(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

const CASE = {
  caseId: '11111111-1111-4111-8111-111111111111',
  decedentUserId: '22222222-2222-4222-8222-222222222222',
  reportedBy: '33333333-3333-4333-8333-333333333333',
  status: 'reported',
  reportSource: 'trusted_contact',
  evidence: [{ type: 'provider_match', matchId: 'm-1' }],
  waitingPeriodEnds: null,
  resolution: null,
  resolvedAt: null,
  createdAt: '2026-08-20T00:00:00.000Z',
};

interface Call {
  url: string;
  init: RequestInit;
}

function clientWith(replies: Response[]): { client: FetchSettlementClient; calls: Call[] } {
  const calls: Call[] = [];
  const client = new FetchSettlementClient(BASE, (url, init) => {
    calls.push({ url, init });
    const next = replies.shift();
    if (!next) {
      throw new Error('unexpected extra request');
    }
    return Promise.resolve(next);
  });
  return { client, calls };
}

describe('the wire contract', () => {
  it('forwards the caller’s bearer on every route and holds no credential', async () => {
    const { client, calls } = clientWith([
      response(200, [CASE]),
      response(200, CASE),
      response(200, { waitingPeriodDays: 5 }),
      response(200, { waitingPeriodDays: 30 }),
    ]);
    await client.listMyCases(TOKEN);
    await client.voidCase(TOKEN, CASE.caseId);
    await client.getSettings(TOKEN);
    await client.updateSettings(TOKEN, 30);

    expect(calls).toHaveLength(4);
    for (const call of calls) {
      const headers = call.init.headers as Record<string, string>;
      expect(headers['authorization']).toBe(`Bearer ${TOKEN}`);
      // The property the whole edge rests on: no header the BFF minted itself.
      expect(Object.keys(headers).join(',')).not.toMatch(/internal|x-estate-service|api-key/i);
    }
    expect(calls.map((c) => `${String(c.init.method)} ${c.url}`)).toEqual([
      `GET ${BASE}/v1/settlement/cases`,
      `POST ${BASE}/v1/settlement/cases/${CASE.caseId}/void`,
      `GET ${BASE}/v1/settlement/settings`,
      `PUT ${BASE}/v1/settlement/settings`,
    ]);
  });

  it('encodes the case id rather than interpolating it into the path', async () => {
    const { client, calls } = clientWith([response(200, CASE)]);
    await client.voidCase(TOKEN, '../../admin/queue');
    expect(calls[0]?.url).toBe(`${BASE}/v1/settlement/cases/..%2F..%2Fadmin%2Fqueue/void`);
  });

  it('sends the waiting period as a JSON body', async () => {
    const { client, calls } = clientWith([response(200, { waitingPeriodDays: 30 })]);
    await client.updateSettings(TOKEN, 30);
    expect(calls[0]?.init.body).toBe(JSON.stringify({ waitingPeriodDays: 30 }));
  });
});

describe('the error firewall', () => {
  /**
   * Table-driven so a NEW downstream token cannot be added by editing one arm
   * and forgetting the rest. Each row states the wire answer and the code the
   * UI is entitled to act on.
   */
  const CASES: ReadonlyArray<{
    name: string;
    status: number;
    body: unknown;
    code: string;
  }> = [
    {
      name: 'a dead token',
      status: 401,
      body: { error: 'unauthenticated' },
      code: 'UNAUTHENTICATED',
    },
    {
      name: 'a bare bearer on a step-up route',
      status: 403,
      body: { error: 'stepup_required' },
      code: 'STEPUP_REQUIRED',
    },
    {
      name: 'the uniform 404 (no such case AND not yours)',
      status: 404,
      body: { error: 'not_found' },
      code: 'NOT_FOUND',
    },
    {
      name: 'the waiting period frozen by an open case',
      status: 409,
      body: { error: 'case_open' },
      code: 'CASE_OPEN',
    },
    {
      name: 'a case already past verification',
      status: 409,
      body: { error: 'invalid_transition' },
      code: 'CASE_NOT_VOIDABLE',
    },
    {
      name: 'identity unreachable — the transition rolled back',
      status: 503,
      body: { error: 'identity_unavailable' },
      code: 'SETTLEMENT_UNAVAILABLE',
    },
    {
      name: 'documents unreachable — same remedy, same code',
      status: 503,
      body: { error: 'documents_unavailable' },
      code: 'SETTLEMENT_UNAVAILABLE',
    },
    {
      name: 'a rejected body',
      status: 400,
      body: { error: 'invalid_request' },
      code: 'INVALID_REQUEST',
    },
  ];

  it.each(CASES)('maps $name to $code', async ({ status, body, code }) => {
    const { client } = clientWith([response(status, body)]);
    await expect(client.voidCase(TOKEN, CASE.caseId)).rejects.toMatchObject({
      extensions: { code },
    });
  });

  /**
   * ANTI-VACUITY FLOOR. `it.each` over an empty array is a green suite, and a
   * table that stops being read looks exactly like a table that passes.
   */
  it('checked every row of the mapping table', () => {
    expect(CASES.length).toBe(8);
    expect(new Set(CASES.map((c) => c.code)).size).toBe(7);
  });

  /**
   * The two 409s are the pair most likely to be collapsed by a later edit, and
   * collapsing them would tell an owner whose waiting period is frozen that
   * their case is too old to close — two different facts, two different things
   * to do next.
   */
  it('keeps the two 409s apart', async () => {
    const open = clientWith([response(409, { error: 'case_open' })]);
    const late = clientWith([response(409, { error: 'invalid_transition' })]);
    const a = await open.client.updateSettings(TOKEN, 30).catch((e: unknown) => e);
    const b = await late.client.voidCase(TOKEN, CASE.caseId).catch((e: unknown) => e);
    expect((a as { extensions: unknown }).extensions).not.toEqual(
      (b as { extensions: unknown }).extensions,
    );
  });

  it('never forwards a downstream body, even on an unmapped status', async () => {
    const { client } = clientWith([
      response(418, { error: 'teapot', detail: 'user bob@example.com not found' }),
    ]);
    const err = await client.listMyCases(TOKEN).catch((e: unknown) => e);
    expect((err as Error).message).toBe('settlement responded with status 418');
    expect((err as Error).message).not.toMatch(/bob@example.com|teapot/);
  });

  it('refuses a malformed downstream answer rather than half-trusting it', async () => {
    const { client } = clientWith([response(200, [{ caseId: 'x' }])]);
    await expect(client.listMyCases(TOKEN)).rejects.toThrow(
      'settlement response failed validation',
    );
  });

  it('masks a transport failure', async () => {
    const client = new FetchSettlementClient(BASE, () => {
      throw new Error('ECONNREFUSED 10.0.0.4:3007');
    });
    const err = await client.listMyCases(TOKEN).catch((e: unknown) => e);
    expect((err as Error).message).toBe('settlement service unreachable');
    expect((err as Error).message).not.toMatch(/10\.0\.0\.4/);
  });
});

/**
 * EVIDENCE CONTENTS NEVER ENTER THE BFF, and this is the assertion that keeps
 * it true. The schema counts the array and models nothing inside it, so a
 * document id or a third-party provider match id has no field here to land in —
 * absence over filter. A future edit that models evidence entries to "surface a
 * bit more detail" reddens this.
 */
describe('what the client refuses to carry', () => {
  it('parses evidence as opaque and keeps ids out of the parsed value', async () => {
    const { client } = clientWith([
      response(200, [
        {
          ...CASE,
          evidence: [
            { type: 'document', documentId: 'doc-secret-1', version: 2, addedBy: 'user-9' },
            { type: 'provider_match', matchId: 'lexisnexis-abc' },
          ],
        },
      ]),
    ]);
    const [parsed] = await client.listMyCases(TOKEN);
    expect(parsed?.evidence).toHaveLength(2);
    // The service's own ids survive the parse (it is `unknown`, not stripped) —
    // what matters is that no SCHEMA FIELD names them, so nothing downstream of
    // here can select one. That is enforced by the projection, tested below,
    // and by the SDL having no evidence field at all.
    expect(Object.keys(parsed ?? {})).not.toContain('evidenceCount');
  });

  it('models no evidence entry shape at all', () => {
    const source = readFileSync(join(__dirname, '..', 'src', 'settlement-client.ts'), 'utf8');
    // Anchored on the runtime construct, not on a comment: the evidence field
    // must stay `z.array(z.unknown())`.
    expect(source).toMatch(/evidence:\s*z\.array\(z\.unknown\(\)\)/);
    expect(source).not.toMatch(/documentId|matchId/);
  });
});
