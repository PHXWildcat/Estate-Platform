/**
 * Test helpers: a fake `fetch` that routes GraphQL requests by operation name.
 * Tests never touch the network; NODE_ENV=test means the client includes the
 * full `query` alongside the persisted hash, which we parse the name from.
 */

export interface RecordedRequest {
  url: string;
  init: RequestInit;
  body: {
    query?: string;
    variables?: unknown;
    extensions?: { persistedQuery?: { sha256Hash?: string } };
  };
}

export function jsonResponse(payload: unknown, ok = true): Response {
  return { ok, json: () => Promise.resolve(payload) } as unknown as Response;
}

/**
 * A handler may return a PROMISE, which is how a test holds a request open: an
 * in-flight guard only exists between dispatch and resolution, so proving one
 * needs a response the test releases itself. `Promise.resolve` below already
 * accepted either; only the type was narrower than the mock.
 */
export type OperationHandler = (variables: unknown) => Response | Promise<Response>;

/**
 * Installs a fetch mock that dispatches to per-operation handlers
 * (keyed by GraphQL operation name, e.g. "Session", "ExportDemo").
 * Returns the mock plus a log of recorded requests.
 */
export function installGraphqlFetchMock(handlers: Record<string, OperationHandler>): {
  fetchMock: jest.Mock;
  requests: RecordedRequest[];
} {
  const requests: RecordedRequest[] = [];
  const fetchMock = jest.fn((url: unknown, init?: RequestInit) => {
    const body = JSON.parse((init?.body as string | undefined) ?? '{}') as RecordedRequest['body'];
    requests.push({ url: String(url), init: init ?? {}, body });
    const operationName = body.query?.split(/[\s({]+/)[1];
    const handler = operationName !== undefined ? handlers[operationName] : undefined;
    if (handler === undefined) {
      // SESSION CONTINUITY (M20 PR4): any handler answering UNAUTHENTICATED
      // now triggers the client's silent Refresh attempt. Unless a test is
      // ABOUT refresh (then it supplies its own handler, which wins above),
      // the honest default is a refusal — "genuinely signed out" — which is
      // exactly the state every pre-PR4 UNAUTHENTICATED fixture was modeling.
      if (operationName === 'Refresh') {
        return Promise.resolve(graphqlError('UNAUTHENTICATED'));
      }
      throw new Error(`No test handler for operation "${operationName ?? '<unknown>'}"`);
    }
    return Promise.resolve(handler(body.variables));
  });
  Object.defineProperty(globalThis, 'fetch', {
    value: fetchMock,
    writable: true,
    configurable: true,
  });
  return { fetchMock, requests };
}

export function graphqlError(code: string, message = 'redacted-by-test'): Response {
  return jsonResponse({ errors: [{ message, extensions: { code } }] }, false);
}
