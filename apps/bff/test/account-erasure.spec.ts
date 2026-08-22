import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { FetchIdentityClient, bffError } from '../src/identity-client';

const COOKIE = 'estate_access=the-access-token';
const BASE = 'http://identity.test';

const GET_QUERY = 'query AccountErasure { accountErasure { status requestedAt } }';
const REQUEST_MUTATION =
  'mutation RequestAccountErasure { requestAccountErasure { status requestedAt } }';
const CANCEL_MUTATION =
  'mutation CancelAccountErasure { cancelAccountErasure { status requestedAt } }';

const PENDING = { status: 'pending', requestedAt: '2026-08-21T12:00:00.000Z' };
const EXECUTING = { status: 'executing', requestedAt: '2026-08-21T12:00:00.000Z' };

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
 * ACCOUNT ERASURE AT THE EDGE (M25 PR4).
 *
 * Two halves, for the reason every peer client here is tested twice: the wire
 * half pins what reaches identity and how its refusals come back, and the graph
 * half pins what only the edge can get wrong — that each verb travels on the
 * caller's own bearer, that no argument names a subject, and that refusals with
 * different remedies stay different codes all the way to the browser.
 *
 * WHY THE REFUSAL SPLIT IS TESTED HERE AND NOT ONLY AT IDENTITY. Identity went
 * to the trouble of answering `open_death_report` and `erasure_not_permitted`
 * separately; an edge that mapped both to one code would undo that work at the
 * last hop, and every test on both sides would still pass. That is the failure
 * the BFF↔web error-code parity fence exists for, one layer earlier.
 */
describe('account erasure — the wire to identity', () => {
  it('carries the caller’s bearer on all three verbs and names no subject', async () => {
    const { client, calls } = clientWith(() => response(200, { erasure: PENDING }));
    await client.getAccountErasure('access-token-value-123');
    await client.requestAccountErasure('access-token-value-123');
    await client.cancelAccountErasure('access-token-value-123');

    expect(calls.map((c) => `${String(c.init.method)} ${c.url}`)).toEqual([
      `GET ${BASE}/v1/account/erasure`,
      `POST ${BASE}/v1/account/erasure`,
      `DELETE ${BASE}/v1/account/erasure`,
    ]);
    for (const call of calls) {
      const headers = call.init.headers as Record<string, string>;
      expect(headers['authorization']).toBe('Bearer access-token-value-123');
      // NO BODY ON ANY VERB. The subject is the caller's session at identity,
      // and a field here naming an account is a field this edge would then
      // have to prove nobody may set.
      expect(call.init.body).toBeUndefined();
    }
  });

  it('answers null for "nothing outstanding" rather than inventing a state', async () => {
    const { client } = clientWith(() => response(200, { erasure: null }));
    await expect(client.getAccountErasure('t')).resolves.toBeNull();
    await expect(client.cancelAccountErasure('t')).resolves.toBeNull();
  });

  it('passes an EXECUTING cancel result through — it is not a success', async () => {
    // The cancel did not take: the driver already claimed the request. An edge
    // that collapsed this to null would tell an owner "withdrawn" about an
    // erasure that is destroying keys.
    const { client } = clientWith(() => response(200, { erasure: EXECUTING }));
    await expect(client.cancelAccountErasure('t')).resolves.toEqual(EXECUTING);
  });

  it('KEEPS THE TWO REFUSALS APART, both of which arrive as 409', async () => {
    // Status-keyed mapping cannot tell these apart, which is why the mapper is
    // token-first. One is a control firing with a remedy the owner can take.
    const dead = clientWith(() => response(409, { error: 'open_death_report' }));
    await expect(dead.client.requestAccountErasure('t')).rejects.toEqual(
      bffError('OPEN_DEATH_REPORT'),
    );

    const refused = clientWith(() => response(409, { error: 'erasure_not_permitted' }));
    await expect(refused.client.requestAccountErasure('t')).rejects.toEqual(
      bffError('ERASURE_NOT_PERMITTED'),
    );
  });

  it('does NOT guess at a 409 token it has not learned', async () => {
    // The failure direction that matters: a future refusal must surface as an
    // unmapped failure, never wearing the wrong remedy. If this ever starts
    // answering OPEN_DEATH_REPORT, the mapper has become status-keyed.
    const { client } = clientWith(() => response(409, { error: 'some_future_reason' }));
    const err = await client.requestAccountErasure('t').catch((e: Error) => e);
    expect(err).not.toEqual(bffError('OPEN_DEATH_REPORT'));
    expect(err).not.toEqual(bffError('ERASURE_NOT_PERMITTED'));
  });

  it('still maps the shared refusals — step-up and a dead session', async () => {
    const stepup = clientWith(() => response(403, { error: 'stepup_required' }));
    await expect(stepup.client.requestAccountErasure('t')).rejects.toEqual(
      bffError('STEPUP_REQUIRED'),
    );
    const dead = clientWith(() => response(401, {}));
    await expect(dead.client.getAccountErasure('t')).rejects.toEqual(bffError('UNAUTHENTICATED'));
  });

  it('refuses a malformed answer rather than half-trusting it', async () => {
    // `status` missing entirely. The surface decides whether to offer a cancel
    // from this field, so a partly-parsed object is worse than an error.
    const { client } = clientWith(() => response(200, { erasure: { requestedAt: 'x' } }));
    await expect(client.getAccountErasure('t')).rejects.toThrow();
  });
});

describe('account erasure at the edge', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('reads, arms and withdraws on the caller’s own session', async () => {
    identity.erasureResult = PENDING;
    identity.erasureRequestResult = PENDING;

    expect(gqlBody(await gql(app, { query: GET_QUERY }, { cookie: COOKIE }))).toEqual({
      data: { accountErasure: PENDING },
    });
    expect(gqlBody(await gql(app, { query: REQUEST_MUTATION }, { cookie: COOKIE }))).toEqual({
      data: { requestAccountErasure: PENDING },
    });
    expect(gqlBody(await gql(app, { query: CANCEL_MUTATION }, { cookie: COOKIE }))).toEqual({
      data: { cancelAccountErasure: null },
    });

    // The BFF holds no credential of its own: whatever authority these calls
    // had is the session the browser presented.
    expect(identity.erasureCalls).toEqual([
      { verb: 'get', accessToken: 'the-access-token' },
      { verb: 'request', accessToken: 'the-access-token' },
      { verb: 'cancel', accessToken: 'the-access-token' },
    ]);
  });

  it('a cancel that came too late surfaces as a REQUEST, not as ok', async () => {
    identity.erasureCancelResult = EXECUTING;
    expect(gqlBody(await gql(app, { query: CANCEL_MUTATION }, { cookie: COOKIE }))).toEqual({
      data: { cancelAccountErasure: EXECUTING },
    });
  });

  it('carries both refusal codes to the browser without merging them', async () => {
    identity.erasureRequestError = bffError('OPEN_DEATH_REPORT');
    const dead = gqlBody(await gql(app, { query: REQUEST_MUTATION }, { cookie: COOKIE }));
    expect(dead.errors?.[0]?.extensions?.['code']).toBe('OPEN_DEATH_REPORT');

    identity.erasureRequestError = bffError('ERASURE_NOT_PERMITTED');
    const refused = gqlBody(await gql(app, { query: REQUEST_MUTATION }, { cookie: COOKIE }));
    expect(refused.errors?.[0]?.extensions?.['code']).toBe('ERASURE_NOT_PERMITTED');
  });

  it('an anonymous caller is UNAUTHENTICATED, never "nothing outstanding"', async () => {
    // Null would make "not signed in" indistinguishable from "no request" on
    // the one surface where that difference decides what the page renders.
    const res = gqlBody(await gql(app, { query: GET_QUERY }));
    expect(res.data?.['accountErasure'] ?? null).toBeNull();
    expect(res.errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    expect(identity.erasureCalls).toEqual([]);
  });
});
