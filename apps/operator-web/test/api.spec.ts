/**
 * @jest-environment jsdom
 */

/**
 * The client's one network module (M21 PR3a).
 *
 * `ApiFailure` is a CLOSED SET and it is what every sentence on this origin is
 * chosen from, so the mapping from a wire status to a member of it decides what
 * a person reads. Two properties are worth pinning rather than reading.
 *
 * A CONTROL FIRING MUST NOT READ AS AN OUTAGE (the M9 rule): identity's step-up
 * cap answers 429, whose remedy is to WAIT, and every other refusal in this
 * union is fixed by doing something differently now. Folding it into UNKNOWN
 * would render "try again in a moment" at somebody who will be refused again.
 *
 * And SERVER TEXT IS NEVER SURFACED: a status and a token narrow to a member,
 * and the body goes no further.
 */
import { request, type ApiFailure } from '../src/client/api';

function reply(status: number, body?: unknown): void {
  (globalThis as { fetch?: unknown }).fetch = () =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      text: () => Promise.resolve(body === undefined ? '' : JSON.stringify(body)),
    });
}

async function codeFor(status: number, body?: unknown): Promise<ApiFailure | 'ok'> {
  reply(status, body);
  const result = await request<unknown>('/api/auth/session');
  return result.ok ? 'ok' : result.code;
}

describe('what the client makes of a wire answer', () => {
  it.each<[number, unknown, ApiFailure | 'ok']>([
    [200, { audience: 'operator' }, 'ok'],
    [204, undefined, 'ok'],
    [401, { error: 'unauthorized' }, 'UNAUTHENTICATED'],
    [403, { error: 'stepup_required' }, 'STEPUP_REQUIRED'],
    [403, { error: 'forbidden' }, 'FORBIDDEN'],
    [404, { error: 'not_found' }, 'NOT_FOUND'],
    [400, { error: 'invalid_request' }, 'INVALID_REQUEST'],
    // The cap. Its remedy is the only one in the union that is "wait".
    [429, { error: 'too_many_attempts' }, 'TOO_MANY_ATTEMPTS'],
    // Crypto-shredded, and PERMANENT: kept off UNKNOWN so the console does not
    // invite a retry for a key that was destroyed on purpose.
    [410, { error: 'content_erased' }, 'CONTENT_ERASED'],
    [502, { error: 'upstream_unavailable' }, 'UNAVAILABLE'],
    [503, { error: 'unavailable' }, 'UNAVAILABLE'],
    [418, { error: 'teapot' }, 'UNKNOWN'],
  ])('maps %i to %s', async (status, body, expected) => {
    await expect(codeFor(status, body)).resolves.toBe(expected);
  });

  it('narrows on the STATUS when the body says nothing usable', async () => {
    // A refusal whose body is missing, unparseable or not an object must still
    // land on a member of the set rather than throwing — an upstream that
    // returned HTML is exactly the case where a screen must still say
    // something.
    for (const body of [undefined, 'not json', ['array'], { error: 42 }]) {
      reply(403, body);

      const result = await request<unknown>('/api/auth/session');
      expect(result).toEqual({ ok: false, code: 'FORBIDDEN' });
    }
  });

  it('reports a dead connection as NETWORK and not as a refusal', async () => {
    // An outage must not wear the face of a revocation (M16 PR2a).
    (globalThis as { fetch?: unknown }).fetch = () => Promise.reject(new Error('ECONNREFUSED'));
    await expect(request<unknown>('/api/auth/session')).resolves.toEqual({
      ok: false,
      code: 'NETWORK',
    });
  });

  it('sends the CSRF header always, and a content-type only with a body', async () => {
    const seen: Array<Record<string, unknown>> = [];
    (globalThis as { fetch?: unknown }).fetch = (_p: string, init: RequestInit) => {
      seen.push(init as unknown as Record<string, unknown>);
      return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve('{}') });
    };

    await request('/api/auth/session');
    await request('/api/auth/stepup', { method: 'POST', body: { code: '123456' } });

    const headers = seen.map((i) => i.headers as Record<string, string>);
    expect(headers[0]?.['x-estate-operator-csrf']).toBe('1');
    expect(headers[0]?.['content-type']).toBeUndefined();
    expect(headers[1]?.['content-type']).toBe('application/json');
    // 'same-origin', never 'include': a future absolute URL must fail closed
    // rather than send this origin's cookie somewhere else.
    expect(seen.every((i) => i.credentials === 'same-origin')).toBe(true);
    expect(seen[1]?.body).toBe(JSON.stringify({ code: '123456' }));
  });
});
