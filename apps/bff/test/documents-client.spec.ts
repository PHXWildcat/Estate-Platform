import { FetchDocumentsClient } from '../src/documents-client';

/**
 * The translation layer between the document service's HTTP answers and the
 * codes a browser sees. The mapping IS the contract: every assertion here is
 * about a distinction a user would act on differently, or about a value this
 * client must refuse to pass on.
 */

const TOKEN = 'callers-own-access-token';

function respond(status: number, body: unknown): typeof globalThis.fetch {
  return (() =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
    })) as unknown as typeof globalThis.fetch;
}

function client(fetchFn: typeof globalThis.fetch): FetchDocumentsClient {
  return new FetchDocumentsClient('http://documents.test', fetchFn);
}

function codeOf(err: unknown): unknown {
  return (err as { extensions?: { code?: unknown } }).extensions?.code;
}

const TEMPLATE_BODY = {
  templateId: 'd0000000-0000-4000-8000-00000000000t',
  docType: 'will',
  state: 'CA',
  version: 1,
  legalReviewAt: '2026-07-23T00:00:00.000Z',
  executionRequirements: { witnesses: 2, notarization: false, selfProvingAffidavit: false },
  variables: [
    {
      name: 'testatorName',
      kind: 'text',
      label: 'Full legal name',
      required: true,
      maxLength: 200,
    },
    { name: 'hasMinorChildren', kind: 'boolean', required: true },
  ],
};

const DOCUMENT_BODY = {
  documentId: 'd0000000-0000-4000-8000-00000000000d',
  docType: 'will',
  source: 'generated',
  title: 'Last Will and Testament',
  currentVersion: 2,
  executionStatus: 'signed',
  executedAt: null,
  legalHold: false,
  sealed: false,
  templateId: TEMPLATE_BODY.templateId,
  createdAt: '2026-08-05T10:00:00.000Z',
  updatedAt: '2026-08-05T11:00:00.000Z',
};

const CONTENT_BODY = {
  documentId: DOCUMENT_BODY.documentId,
  version: 2,
  mime: 'text/html',
  contentSha256: 'a'.repeat(64),
  encoding: 'utf8',
  content: '<!doctype html><html><body><h1>Will</h1></body></html>',
};

describe('reads', () => {
  it('forwards the caller’s bearer and nothing else', async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const spy = ((url: string, init: RequestInit) => {
      seen.push({ url, init });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).list(TOKEN);
    expect(seen[0]?.url).toBe('http://documents.test/v1/documents');
    // No service credential, no identity header — the whole trust model.
    expect(seen[0]?.init.headers).toEqual({ authorization: `Bearer ${TOKEN}` });
  });

  it('passes a template catalog through, variables and formalities intact', async () => {
    const templates = await client(respond(200, [TEMPLATE_BODY])).templates(TOKEN, 'CA');
    expect(templates).toEqual([TEMPLATE_BODY]);
  });

  it('encodes the state into the query rather than concatenating it raw', async () => {
    const seen: string[] = [];
    const spy = ((url: string) => {
      seen.push(url);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).templates(TOKEN, 'C A&x=1');
    expect(seen[0]).toBe('http://documents.test/v1/templates?state=C%20A%26x%3D1');
  });

  it('reads one version’s content on the exact path asked for', async () => {
    const seen: string[] = [];
    const spy = ((url: string) => {
      seen.push(url);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(CONTENT_BODY) });
    }) as unknown as typeof globalThis.fetch;
    const content = await client(spy).content(TOKEN, DOCUMENT_BODY.documentId, 2);
    expect(seen[0]).toBe(
      `http://documents.test/v1/documents/${DOCUMENT_BODY.documentId}/versions/2/content`,
    );
    expect(content).toEqual(CONTENT_BODY);
  });

  it('passes one document and its version history through', async () => {
    const document = await client(respond(200, DOCUMENT_BODY)).get(TOKEN, DOCUMENT_BODY.documentId);
    expect(document).toEqual(DOCUMENT_BODY);
    const versions = await client(
      respond(200, [
        {
          version: 1,
          contentSha256: 'a'.repeat(64),
          sizeBytes: 900,
          mime: 'text/html',
          createdAt: '2026-08-05T10:00:00.000Z',
        },
      ]),
    ).versions(TOKEN, DOCUMENT_BODY.documentId);
    expect(versions).toHaveLength(1);
    expect(versions[0]?.version).toBe(1);
  });

  it('refuses a body that is not JSON at all', async () => {
    const garbage = (() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.reject(new Error('unexpected token <')),
      })) as unknown as typeof globalThis.fetch;
    await expect(client(garbage).list(TOKEN)).rejects.toThrow('documents response was not JSON');
  });

  it('falls back to the status when an ERROR body is not JSON', async () => {
    // A proxy or gateway answering HTML: there is no machine token to read, so
    // the status decides — and the body still never reaches a client.
    const html = (() =>
      Promise.resolve({
        ok: false,
        status: 401,
        json: () => Promise.reject(new Error('unexpected token <')),
      })) as unknown as typeof globalThis.fetch;
    const err = await client(html)
      .list(TOKEN)
      .catch((e: unknown) => e);
    expect(codeOf(err)).toBe('UNAUTHENTICATED');
  });

  it('refuses a response whose shape it does not understand', async () => {
    // Contract drift ⇒ no data, never a guess — and never the peer's text.
    await expect(client(respond(200, [{ documentId: 1 }])).list(TOKEN)).rejects.toThrow(
      'documents response failed validation',
    );
  });

  it('refuses an unknown variable kind rather than rendering a control for it', async () => {
    // The web app builds its intake form from these declarations, so a kind it
    // has no control for must fail here rather than silently drop a variable a
    // legal instrument depends on.
    const drifted = { ...TEMPLATE_BODY, variables: [{ name: 'x', kind: 'signature' }] };
    await expect(client(respond(200, [drifted])).templates(TOKEN, 'CA')).rejects.toThrow(
      'documents response failed validation',
    );
  });

  it('never surfaces the peer’s body on an unmapped status', async () => {
    const err = await client(respond(500, { error: 'pg: relation does not exist' }))
      .list(TOKEN)
      .catch((e: unknown) => e);
    expect((err as Error).message).toBe('documents responded with status 500');
  });

  it('masks a network failure', async () => {
    const dead = (() => Promise.reject(new Error('ECONNREFUSED'))) as unknown as typeof fetch;
    await expect(client(dead).list(TOKEN)).rejects.toThrow('documents service unreachable');
  });
});

describe('error mapping', () => {
  it('maps 401 to UNAUTHENTICATED', async () => {
    const err = await client(respond(401, { error: 'unauthorized' }))
      .list(TOKEN)
      .catch((e: unknown) => e);
    expect(codeOf(err)).toBe('UNAUTHENTICATED');
  });

  it('maps the step-up refusal to STEPUP_REQUIRED so the client can retry', async () => {
    const err = await client(respond(403, { error: 'stepup_required' }))
      .generate(TOKEN, { docType: 'will', state: 'CA', variables: {} })
      .catch((e: unknown) => e);
    expect(codeOf(err)).toBe('STEPUP_REQUIRED');
  });

  it('narrows a plain 403 to NOT_FOUND at this edge', async () => {
    // The service answers 404 for a document that does not exist and 403 for
    // one that exists and is somebody else's — its own recorded 404-vs-403
    // follow-up. Browser traffic sees one answer for both.
    const err = await client(respond(403, { error: 'forbidden' }))
      .get(TOKEN, DOCUMENT_BODY.documentId)
      .catch((e: unknown) => e);
    expect(codeOf(err)).toBe('NOT_FOUND');
  });

  it('keeps a missing TEMPLATE apart from a missing document', async () => {
    const template = await client(respond(404, { error: 'template_not_found' }))
      .generate(TOKEN, { docType: 'will', state: 'WY', variables: {} })
      .catch((e: unknown) => e);
    expect(codeOf(template)).toBe('TEMPLATE_NOT_FOUND');
    const document = await client(respond(404, { error: 'not_found' }))
      .get(TOKEN, DOCUMENT_BODY.documentId)
      .catch((e: unknown) => e);
    expect(codeOf(document)).toBe('NOT_FOUND');
  });

  it('maps a crypto-shredded version to CONTENT_ERASED, not a retryable failure', async () => {
    const err = await client(respond(410, { error: 'content_erased' }))
      .content(TOKEN, DOCUMENT_BODY.documentId, 1)
      .catch((e: unknown) => e);
    expect(codeOf(err)).toBe('CONTENT_ERASED');
  });

  it('separates the two 409s, because the remedies differ', async () => {
    const stale = await client(respond(409, { error: 'version_conflict' }))
      .regenerate(TOKEN, DOCUMENT_BODY.documentId, { variables: {} })
      .catch((e: unknown) => e);
    expect(codeOf(stale)).toBe('VERSION_CONFLICT');
    const signed = await client(respond(409, { error: 'invalid_status' }))
      .regenerate(TOKEN, DOCUMENT_BODY.documentId, { variables: {} })
      .catch((e: unknown) => e);
    expect(codeOf(signed)).toBe('DOCUMENT_NOT_EDITABLE');
  });

  it('maps a rejected intake payload to INVALID_REQUEST without echoing it', async () => {
    // The service withholds WHICH variable failed how — values are PII — and
    // this client must not invent detail the service refused to give.
    const err = await client(respond(422, { error: 'invalid_variables' }))
      .generate(TOKEN, { docType: 'will', state: 'CA', variables: { testatorName: 'Ada' } })
      .catch((e: unknown) => e);
    expect(codeOf(err)).toBe('INVALID_REQUEST');
    expect((err as Error).message).toBe('Invalid request');
  });
});

describe('writes', () => {
  it('sends only the fields that were supplied', async () => {
    const seen: RequestInit[] = [];
    const spy = ((_url: string, init: RequestInit) => {
      seen.push(init);
      return Promise.resolve({
        ok: true,
        status: 201,
        json: () =>
          Promise.resolve({
            documentId: DOCUMENT_BODY.documentId,
            version: 1,
            contentSha256: 'b'.repeat(64),
            executionStatus: 'generated',
          }),
      });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).generate(TOKEN, {
      docType: 'will',
      state: 'CA',
      variables: { testatorName: 'Ada Lovelace', hasMinorChildren: false },
    });
    expect(JSON.parse((seen[0]?.body as string | undefined) ?? '{}')).toEqual({
      docType: 'will',
      state: 'CA',
      variables: { testatorName: 'Ada Lovelace', hasMinorChildren: false },
    });
  });

  it('sends a pinned template and a title override when they are given', async () => {
    const seen: RequestInit[] = [];
    const spy = ((_url: string, init: RequestInit) => {
      seen.push(init);
      return Promise.resolve({
        ok: true,
        status: 201,
        json: () =>
          Promise.resolve({
            documentId: DOCUMENT_BODY.documentId,
            version: 1,
            contentSha256: 'd'.repeat(64),
            executionStatus: 'generated',
          }),
      });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).generate(TOKEN, {
      docType: 'will',
      state: 'CA',
      templateId: TEMPLATE_BODY.templateId,
      title: 'My will',
      variables: {},
    });
    await client(spy).regenerate(TOKEN, DOCUMENT_BODY.documentId, {
      templateId: TEMPLATE_BODY.templateId,
      title: 'My will',
      variables: {},
    });
    expect(JSON.parse((seen[0]?.body as string | undefined) ?? '{}')).toEqual({
      docType: 'will',
      state: 'CA',
      templateId: TEMPLATE_BODY.templateId,
      title: 'My will',
      variables: {},
    });
    expect(JSON.parse((seen[1]?.body as string | undefined) ?? '{}')).toEqual({
      templateId: TEMPLATE_BODY.templateId,
      title: 'My will',
      variables: {},
    });
  });

  it('regenerates against the document’s own path', async () => {
    const seen: string[] = [];
    const spy = ((url: string) => {
      seen.push(url);
      return Promise.resolve({
        ok: true,
        status: 201,
        json: () =>
          Promise.resolve({
            documentId: DOCUMENT_BODY.documentId,
            version: 2,
            contentSha256: 'c'.repeat(64),
            executionStatus: 'generated',
          }),
      });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).regenerate(TOKEN, DOCUMENT_BODY.documentId, { variables: {} });
    expect(seen[0]).toBe(`http://documents.test/v1/documents/${DOCUMENT_BODY.documentId}/versions`);
  });
});
