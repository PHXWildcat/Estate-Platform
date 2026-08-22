import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { FetchIdentityClient, bffError } from '../src/identity-client';

const COOKIE = 'estate_access=the-access-token';
const BASE = 'http://identity.test';

const EMAIL_QUERY = 'query AccountEmail { accountEmail }';

function response(status: number, body: unknown): Response {
  const json = (): Promise<unknown> => Promise.resolve(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    json,
    clone: () => ({ json }) as unknown as Response,
  } as unknown as Response;
}

interface Recorded {
  url: string;
  init: RequestInit;
}

function clientWith(answer: (recorded: Recorded) => Response): {
  client: FetchIdentityClient;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const fetchFn = (input: unknown, init: RequestInit): Promise<Response> => {
    const recorded = { url: String(input), init };
    calls.push(recorded);
    return Promise.resolve(answer(recorded));
  };
  return { client: new FetchIdentityClient(BASE, fetchFn), calls };
}

/**
 * THE ADDRESS ON FILE AT THE EDGE (M24 PR2) — docs/03 §6v residual 2's
 * closure, tested in the two halves every peer client here gets: the wire
 * half pins what reaches identity (a bare GET on the caller's own bearer,
 * naming no subject) and how identity's one new refusal comes back; the
 * graph half pins what only the edge can get wrong — the auth gate, the
 * forwarded bearer, and CONTENT_ERASED surviving to the browser as itself.
 *
 * WHY THE 410 MAPPING IS LOAD-BEARING. Identity answers 410 `content_erased`
 * when the decrypt races a legal erasure. Before this PR the shared mapper had
 * no 410 arm, so the erasure control firing would have masked into a generic
 * outage — inviting retries against a key that was destroyed on purpose, and
 * violating "a control firing must not read as an outage".
 */
describe('account email — the wire to identity', () => {
  it('is a bare GET on the caller’s bearer, naming no subject', async () => {
    const { client, calls } = clientWith(() => response(200, { email: 'owner@example.com' }));
    await expect(client.accountEmail('access-token-value-123')).resolves.toBe('owner@example.com');

    expect(calls.map((c) => `${String(c.init.method)} ${c.url}`)).toEqual([
      `GET ${BASE}/v1/auth/email`,
    ]);
    const headers = calls[0]?.init.headers as Record<string, string>;
    expect(headers['authorization']).toBe('Bearer access-token-value-123');
    // No body: the subject is the caller's session at identity, and a field
    // here naming an account is a field this edge would have to prove nobody
    // may set.
    expect(calls[0]?.init.body).toBeUndefined();
  });

  it('maps identity’s 410 to CONTENT_ERASED — erasure must not read as an outage', async () => {
    const { client } = clientWith(() => response(410, { error: 'content_erased' }));
    await expect(client.accountEmail('t')).rejects.toEqual(bffError('CONTENT_ERASED'));
  });

  it('refuses a response that is not the declared shape, naming no values', async () => {
    const { client } = clientWith(() => response(200, { unexpected: true }));
    await expect(client.accountEmail('t')).rejects.toThrow('identity response failed validation');
  });
});

describe('account email at the edge', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('answers the address on the caller’s own bearer, untouched', async () => {
    identity.accountEmailResult = 'Owner.Name+tag@example.com';
    const res = await gql(app, { query: EMAIL_QUERY }, { cookie: COOKIE });
    // Forwarded EXACTLY: the address is identity's answer, and any reshaping
    // here (casefolding included) would be a second copy of a rule the
    // service owns.
    expect(gqlBody(res)).toEqual({ data: { accountEmail: 'Owner.Name+tag@example.com' } });
    expect(identity.accountEmailCalls).toEqual(['the-access-token']);
  });

  it('requires a session — it is a disclosure about the caller', async () => {
    const res = await gql(app, { query: EMAIL_QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    // Refused BEFORE identity was asked: no audited decrypt is spent on a
    // request that carries nobody.
    expect(identity.accountEmailCalls).toHaveLength(0);
  });

  it('carries CONTENT_ERASED through as itself, never a masked outage', async () => {
    identity.accountEmailError = bffError('CONTENT_ERASED');
    const res = await gql(app, { query: EMAIL_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('CONTENT_ERASED');
  });
});
