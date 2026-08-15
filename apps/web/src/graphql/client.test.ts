import { createHash } from 'node:crypto';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';
import { errorCopy } from '../lib/copy';
import { gqlRequest } from './client';
import { EXPORT_DEMO_MUTATION, LOGIN_MUTATION } from './operations';

describe('gqlRequest', () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn();
    Object.defineProperty(globalThis, 'fetch', {
      value: fetchMock,
      writable: true,
      configurable: true,
    });
  });

  const loginVariables = { email: 'person@example.com', password: 'correct-horse-battery' };

  it('sends the CSRF header, JSON content type, and cookie credentials', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { login: { ok: true } } }));
    await gqlRequest('Login', loginVariables);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/graphql');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include');
    expect(init.headers).toEqual({
      'content-type': 'application/json',
      'x-estate-csrf': '1',
    });
  });

  it('sends the persisted sha256 hash plus the document itself outside production', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { login: { ok: true } } }));
    const result = await gqlRequest('Login', loginVariables);

    expect(result).toEqual({ ok: true, data: { login: { ok: true } } });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as {
      query?: string;
      variables: unknown;
      extensions: { persistedQuery: { sha256Hash: string } };
    };
    const expectedHash = createHash('sha256').update(LOGIN_MUTATION, 'utf8').digest('hex');
    expect(body.extensions.persistedQuery.sha256Hash).toBe(expectedHash);
    // NODE_ENV is not "production" under jest, so the dev query rides along.
    expect(body.query).toBe(LOGIN_MUTATION);
    expect(body.variables).toEqual(loginVariables);
  });

  it('sends persistedQuery.version = 1, which the BFF requires to find the operation at all', () => {
    // A REGRESSION PIN, not a formality. Without `version` the BFF's APQ
    // extractor finds no operation id and answers "Operation not allowed" —
    // and because non-production builds also send `query`, the failure is
    // invisible everywhere EXCEPT production. That is exactly how it shipped
    // unnoticed until the real web image was driven against the local stack.
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { login: { ok: true } } }));
    void gqlRequest('Login', loginVariables);
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as {
      extensions: { persistedQuery: { version: number } };
    };
    expect(body.extensions.persistedQuery.version).toBe(1);
  });

  it('narrows a known error code and never surfaces server message text', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          errors: [
            { message: 'internal secret detail', extensions: { code: 'INVALID_CREDENTIALS' } },
          ],
        },
        false,
      ),
    );
    const result = await gqlRequest('Login', loginVariables);
    expect(result).toEqual({ ok: false, code: 'INVALID_CREDENTIALS' });
    expect(JSON.stringify(result)).not.toContain('internal secret detail');
  });

  it('narrows STEPUP_REQUIRED', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ errors: [{ extensions: { code: 'STEPUP_REQUIRED' } }] }, false),
    );
    const hash = createHash('sha256').update(EXPORT_DEMO_MUTATION, 'utf8').digest('hex');
    const result = await gqlRequest('ExportDemo', {});
    expect(result).toEqual({ ok: false, code: 'STEPUP_REQUIRED' });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as {
      extensions: { persistedQuery: { sha256Hash: string } };
    };
    expect(body.extensions.persistedQuery.sha256Hash).toBe(hash);
  });

  it('maps unrecognized error codes to UNKNOWN', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ errors: [{ extensions: { code: 'SOMETHING_NEW' } }] }, false),
    );
    const result = await gqlRequest('Login', loginVariables);
    expect(result).toEqual({ ok: false, code: 'UNKNOWN' });
  });

  it('maps malformed error entries to UNKNOWN instead of throwing', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ errors: ['not-an-object'] }, false));
    const result = await gqlRequest('Login', loginVariables);
    expect(result).toEqual({ ok: false, code: 'UNKNOWN' });
  });

  it('maps a rejected fetch to NETWORK', async () => {
    fetchMock.mockRejectedValueOnce(new Error('connection refused'));
    const result = await gqlRequest('Login', loginVariables);
    expect(result).toEqual({ ok: false, code: 'NETWORK' });
  });

  it('maps an unparseable response body to NETWORK', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      json: () => Promise.reject(new Error('not json')),
    });
    const result = await gqlRequest('Login', loginVariables);
    expect(result).toEqual({ ok: false, code: 'NETWORK' });
  });

  it('maps a 2xx response with no data and no errors to UNKNOWN', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    const result = await gqlRequest('Login', loginVariables);
    expect(result).toEqual({ ok: false, code: 'UNKNOWN' });
  });
});

/**
 * SESSION CONTINUITY (M20 PR4). The properties here are the design: one
 * silent refresh-and-retry per UNAUTHENTICATED, single-flight because
 * identity's rotation-reuse detection treats a concurrent second refresh as
 * THEFT and revokes the session, and a refused refresh returning the original
 * failure so "session ended" is only ever rendered when it is true.
 */
describe('gqlRequest session continuity', () => {
  function operationNames(requests: Array<{ body: { query?: string } }>): string[] {
    return requests.map((r) => r.body.query?.split(/[\s({]+/)[1] ?? '<unknown>');
  }

  it('silently refreshes once and retries once after UNAUTHENTICATED', async () => {
    let sessionCalls = 0;
    const { requests } = installGraphqlFetchMock({
      Session: () =>
        sessionCalls++ === 0
          ? graphqlError('UNAUTHENTICATED')
          : jsonResponse({ data: { session: null } }),
      Refresh: () => jsonResponse({ data: { refresh: { ok: true } } }),
    });

    const result = await gqlRequest('Session', {});

    expect(result).toEqual({ ok: true, data: { session: null } });
    expect(operationNames(requests)).toEqual(['Session', 'Refresh', 'Session']);
  });

  it('returns the ORIGINAL UNAUTHENTICATED when the refresh is refused, with no retry', async () => {
    // This is what makes "Your session has ended" TRUE when a surface renders
    // it: the code now only reaches a caller after the refresh itself failed.
    const { requests } = installGraphqlFetchMock({
      Session: () => graphqlError('UNAUTHENTICATED'),
      Refresh: () => graphqlError('UNAUTHENTICATED'),
    });

    const result = await gqlRequest('Session', {});

    expect(result).toEqual({ ok: false, code: 'UNAUTHENTICATED' });
    expect(operationNames(requests)).toEqual(['Session', 'Refresh']);
  });

  it('coalesces CONCURRENT failures into ONE refresh — reuse detection makes this correctness', async () => {
    // Identity treats an already-rotated refresh token as theft and revokes
    // the whole session (M16), so two refreshes in flight with one cookie jar
    // is self-revocation. The in-tab latch must make it unrepresentable.
    const release: Array<() => void> = [];
    const held = (response: Response): Promise<Response> =>
      new Promise((resolve) => release.push(() => resolve(response)));
    let refreshCalls = 0;
    let sessionCalls = 0;
    let sessionsCalls = 0;
    const { requests } = installGraphqlFetchMock({
      Session: () =>
        sessionCalls++ === 0
          ? held(graphqlError('UNAUTHENTICATED'))
          : jsonResponse({ data: { session: null } }),
      Sessions: () =>
        sessionsCalls++ === 0
          ? held(graphqlError('UNAUTHENTICATED'))
          : jsonResponse({ data: { sessions: [] } }),
      Refresh: () => {
        refreshCalls += 1;
        return jsonResponse({ data: { refresh: { ok: true } } });
      },
    });

    const first = gqlRequest('Session', {});
    const second = gqlRequest('Sessions', {});
    // Both first sends are dispatched and held; release them together so both
    // discover UNAUTHENTICATED while the other's refresh could be in flight.
    expect(release).toHaveLength(2);
    for (const r of release) r();
    const [a, b] = await Promise.all([first, second]);

    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    expect(refreshCalls).toBe(1);
    expect(operationNames(requests).filter((n) => n === 'Refresh')).toHaveLength(1);
  });

  it('returns a second UNAUTHENTICATED from the retry as-is — never loops', async () => {
    // The session died between the refresh and the retry (a revocation racing
    // us). Looping would hammer a dead credential.
    const { requests } = installGraphqlFetchMock({
      Session: () => graphqlError('UNAUTHENTICATED'),
      Refresh: () => jsonResponse({ data: { refresh: { ok: true } } }),
    });

    const result = await gqlRequest('Session', {});

    expect(result).toEqual({ ok: false, code: 'UNAUTHENTICATED' });
    expect(operationNames(requests)).toEqual(['Session', 'Refresh', 'Session']);
  });

  it('does NOT retry a mutation — it reports SESSION_RENEWED instead', async () => {
    // The load-bearing case. Eleven BFF resolvers write and then read back
    // (addContact → contacts, addFamilyMember → family, …). If the write
    // lands and the read-back is refused, re-running the resolver re-runs the
    // write — and createContact/createFamilyMember carry no idempotency key,
    // so one click would produce two rows. The transport cannot tell which
    // mutations are safe, so it retries none of them.
    const { requests } = installGraphqlFetchMock({
      AddContact: () => graphqlError('UNAUTHENTICATED'),
      Refresh: () => jsonResponse({ data: { refresh: { ok: true } } }),
    });

    const result = await gqlRequest('AddContact', {
      input: { name: 'Jane Doe', relationship: null, email: null, phone: null, notes: null },
    } as never);

    expect(result).toEqual({ ok: false, code: 'SESSION_RENEWED' });
    // The refresh DID happen — the next attempt will work — but the mutation
    // was sent exactly once.
    expect(operationNames(requests)).toEqual(['AddContact', 'Refresh']);
  });

  it('SESSION_RENEWED says nothing was changed, and is not the session-ended sentence', () => {
    // Reporting the original UNAUTHENTICATED here would render "Your session
    // has ended" over a session that was just successfully renewed — the
    // false sentence this PR exists to delete, one case over.
    expect(errorCopy.SESSION_RENEWED).toContain('Nothing was changed');
    expect(errorCopy.SESSION_RENEWED).not.toEqual(errorCopy.UNAUTHENTICATED);
  });

  it('never refreshes for a non-UNAUTHENTICATED failure', async () => {
    const { requests } = installGraphqlFetchMock({
      Session: () => graphqlError('STEPUP_REQUIRED'),
    });

    const result = await gqlRequest('Session', {});

    expect(result).toEqual({ ok: false, code: 'STEPUP_REQUIRED' });
    expect(operationNames(requests)).toEqual(['Session']);
  });

  it('a Refresh refused with UNAUTHENTICATED does not recurse into itself', async () => {
    // refreshSession calls gqlRequest('Refresh'); the operation guard is the
    // recursion control. Without it, a refused refresh would refresh in order
    // to refresh.
    const { requests } = installGraphqlFetchMock({
      Refresh: () => graphqlError('UNAUTHENTICATED'),
    });

    const result = await gqlRequest('Refresh', {});

    expect(result).toEqual({ ok: false, code: 'UNAUTHENTICATED' });
    expect(operationNames(requests)).toEqual(['Refresh']);
  });

  it('reads a version-skewed Refresh answering {data:{}} as NOT refreshed', async () => {
    // A missing field is NO DATA, never data (M11): a BFF predating the
    // mutation must not be read as a successful refresh.
    const { requests } = installGraphqlFetchMock({
      Session: () => graphqlError('UNAUTHENTICATED'),
      Refresh: () => jsonResponse({ data: {} }),
    });

    const result = await gqlRequest('Session', {});

    expect(result).toEqual({ ok: false, code: 'UNAUTHENTICATED' });
    expect(operationNames(requests)).toEqual(['Session', 'Refresh']);
  });

  it('runs the refresh under the cross-tab Web Lock when the browser has one', async () => {
    // Every tab of this origin shares one cookie jar, so the in-tab latch is
    // not enough: two TABS refreshing concurrently is the same reuse-detection
    // self-revocation. jsdom has no LockManager, so a fake asserts the wiring.
    const lockNames: string[] = [];
    Object.defineProperty(globalThis.navigator, 'locks', {
      configurable: true,
      value: {
        request: (name: string, fn: () => Promise<unknown>): Promise<unknown> => {
          lockNames.push(name);
          return fn();
        },
      },
    });
    try {
      let sessionCalls = 0;
      installGraphqlFetchMock({
        Session: () =>
          sessionCalls++ === 0
            ? graphqlError('UNAUTHENTICATED')
            : jsonResponse({ data: { session: null } }),
        Refresh: () => jsonResponse({ data: { refresh: { ok: true } } }),
      });

      const result = await gqlRequest('Session', {});

      expect(result.ok).toBe(true);
      expect(lockNames).toEqual(['estate.session.refresh']);
    } finally {
      delete (globalThis.navigator as { locks?: unknown }).locks;
    }
  });

  it('survives a misbehaving LockManager: gqlRequest resolves, it does not throw', async () => {
    Object.defineProperty(globalThis.navigator, 'locks', {
      configurable: true,
      value: {
        request: (): Promise<unknown> => Promise.reject(new Error('lock API broke')),
      },
    });
    try {
      installGraphqlFetchMock({
        Session: () => graphqlError('UNAUTHENTICATED'),
      });

      const result = await gqlRequest('Session', {});

      // The refresh evaporated with the lock; the original failure survives
      // and the never-throws contract holds.
      expect(result).toEqual({ ok: false, code: 'UNAUTHENTICATED' });
    } finally {
      delete (globalThis.navigator as { locks?: unknown }).locks;
    }
  });
});
