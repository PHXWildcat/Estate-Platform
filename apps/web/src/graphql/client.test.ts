import { createHash } from 'node:crypto';
import { jsonResponse } from '../test-utils/graphql-fetch-mock';
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
