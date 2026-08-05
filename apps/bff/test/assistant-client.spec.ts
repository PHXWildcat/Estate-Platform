import { ASSISTANT_TURN_BUDGET_MS, assistantTurnTimeoutMs } from '@estate/contracts';
import { FetchAssistantClient } from '../src/assistant-client';

/**
 * The translation layer between the assistant service's HTTP answers and the
 * statuses the readiness page renders. The mapping IS the contract: every
 * assertion here is about a distinction a user would act on differently.
 */

const TOKEN = 'callers-own-access-token';
const DISCLAIMER = 'Automated analysis for education only. Not legal or tax advice.';

function respond(status: number, body: unknown): typeof globalThis.fetch {
  return (() =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
    })) as unknown as typeof globalThis.fetch;
}

function client(fetchFn: typeof globalThis.fetch): FetchAssistantClient {
  return new FetchAssistantClient('http://assistant.test', fetchFn);
}

const OK_BODY = {
  status: 'ok',
  findings: [
    {
      code: 'no_trust_on_file',
      severity: 'info',
      subject: { kind: 'estate', ref: null, label: null },
      detail: { assetCount: 2 },
    },
  ],
  summary: { trustOnFile: false },
  disclaimer: DISCLAIMER,
};

describe('analysis', () => {
  it('passes a successful analysis through with its findings and watermark', async () => {
    const view = await client(respond(200, OK_BODY)).analysis(TOKEN, 'funding');
    expect(view).toEqual({
      status: 'OK',
      reason: null,
      findings: OK_BODY.findings,
      disclaimer: DISCLAIMER,
    });
  });

  it('forwards the caller’s bearer and nothing else', async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const spy = ((url: string, init: RequestInit) => {
      seen.push({ url, init });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(OK_BODY) });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).analysis(TOKEN, 'estate-tax');
    expect(seen[0]?.url).toBe('http://assistant.test/v1/analysis/estate-tax');
    expect(seen[0]?.init.headers).toEqual({ authorization: `Bearer ${TOKEN}` });
  });

  it('maps a 503 outage to UNAVAILABLE, with the token and no findings', async () => {
    const view = await client(respond(503, { error: 'upstream_unavailable' })).analysis(
      TOKEN,
      'funding',
    );
    expect(view).toMatchObject({
      status: 'UNAVAILABLE',
      reason: 'upstream_unavailable',
      findings: [],
    });
  });

  it('keeps the reference-data gate DISTINCT from an outage', async () => {
    // A control firing is not a transient failure: "we don't publish this here"
    // is actionable in a way "try again later" is not, and a user told the
    // wrong one retries forever.
    const view = await client(respond(503, { error: 'reference_unreviewed' })).analysis(
      TOKEN,
      'estate-tax',
    );
    expect(view).toMatchObject({ status: 'REFUSED', reason: 'reference_unreviewed' });
  });

  it('maps the assistant being switched off to DISABLED', async () => {
    // The analysis routes require the master consent switch and nothing else,
    // so a 403 has exactly one meaning — and it is the one the user can fix.
    const view = await client(respond(403, { error: 'assistant_disabled' })).analysis(
      TOKEN,
      'funding',
    );
    expect(view).toMatchObject({ status: 'DISABLED', reason: 'assistant_disabled' });
  });

  it('throws UNAUTHENTICATED for an expired session rather than degrading', async () => {
    await expect(
      client(respond(401, { error: 'unauthorized' })).analysis(TOKEN, 'funding'),
    ).rejects.toMatchObject({ extensions: { code: 'UNAUTHENTICATED' } });
  });

  it('carries a watermark even when the peer sent no parseable body', async () => {
    // docs/01 §2.8 makes the non-advice watermark a required field all the way
    // to the screen; a fallback that says less beats a card that says none.
    const view = await client(respond(502, 'not json at all')).analysis(TOKEN, 'funding');
    expect(view.status).toBe('UNAVAILABLE');
    expect(view.disclaimer).toMatch(/not legal or tax advice/i);
  });

  it('refuses to pass through a response it cannot validate', async () => {
    // Contract drift ⇒ no data, never a guess. A prose `detail` or a nested
    // object is exactly what must not reach a browser unexamined.
    await expect(
      client(
        respond(200, { status: 'ok', findings: [{ code: 42 }], disclaimer: DISCLAIMER }),
      ).analysis(TOKEN, 'funding'),
    ).rejects.toThrow(/failed validation/);
  });

  it('never leaks downstream text into the thrown error', async () => {
    const secret = 'postgres://user:pw@core-db:5432 blew up';
    await expect(
      client(respond(500, { error: secret, message: secret })).consents(TOKEN),
    ).rejects.not.toThrow(new RegExp(secret));
  });
});

describe('the conversation surface', () => {
  const CONVO = {
    conversationId: 'c1',
    createdAt: '2026-08-05T10:00:00Z',
    updatedAt: '2026-08-05T10:00:00Z',
  };

  it('maps the assistant’s uniform 404 to one code, with nothing added', async () => {
    // The service refuses "no such conversation" and "someone else's" the same
    // way so an id is not an oracle. Two distinct codes here would rebuild it.
    await expect(
      client(respond(404, { error: 'not_found' })).transcript(TOKEN, 'c1'),
    ).rejects.toMatchObject({ extensions: { code: 'NOT_FOUND' } });
    await expect(client(respond(404, {})).transcript(TOKEN, 'c2')).rejects.toMatchObject({
      extensions: { code: 'NOT_FOUND' },
    });
  });

  it('maps the master switch being off to its own actionable code', async () => {
    await expect(
      client(respond(403, { error: 'assistant_disabled' })).sendMessage(TOKEN, 'c1', 'hi'),
    ).rejects.toMatchObject({ extensions: { code: 'ASSISTANT_DISABLED' } });
  });

  it('does not let a future 403 inherit "turn the assistant on"', async () => {
    // Discriminated by TOKEN, not by status: an unrecognized forbidden case
    // stays a masked generic failure rather than telling a user to flip a
    // switch that is already on.
    await expect(
      client(respond(403, { error: 'some_other_rule' })).sendMessage(TOKEN, 'c1', 'hi'),
    ).rejects.not.toMatchObject({ extensions: { code: 'ASSISTANT_DISABLED' } });
  });

  it('sends the turn text as a JSON body on the caller’s bearer', async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const spy = ((url: string, init: RequestInit) => {
      seen.push({ url, init });
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({ conversationId: 'c1', messageId: 'm1', text: 'hi back', toolCalls: 0 }),
      });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).sendMessage(TOKEN, 'c1', 'hello');
    expect(seen[0]?.url).toBe('http://assistant.test/v1/conversations/c1/turns');
    expect(seen[0]?.init.method).toBe('POST');
    // The body is a JSON string by construction (the client stringifies it);
    // parsing it back is what asserts the shape rather than the serialization.
    const body: unknown = seen[0]?.init.body;
    expect(typeof body).toBe('string');
    expect(JSON.parse(body as string)).toEqual({ text: 'hello' });
    expect(seen[0]?.init.headers).toMatchObject({ authorization: `Bearer ${TOKEN}` });
  });

  it('waits LONGER than the assistant is allowed to spend on a turn', () => {
    // THE INVARIANT THE M11 REVIEW FOUND INVERTED. It used to be a claim in two
    // comments; it is now a fact about one shared constant, asserted here so it
    // cannot silently invert again. If the edge gives up first the turn still
    // commits — nothing cancels the server side — and the user is told an
    // exchange that happened did not.
    expect(assistantTurnTimeoutMs()).toBeGreaterThan(ASSISTANT_TURN_BUDGET_MS);
    // And the headroom is for the platform's own work, not for another
    // provider call: a gap wide enough to hide a whole extra turn would put us
    // back where we started.
    expect(assistantTurnTimeoutMs() - ASSISTANT_TURN_BUDGET_MS).toBeLessThan(
      ASSISTANT_TURN_BUDGET_MS,
    );
  });

  it('gives a turn its own deadline, and nothing else one', async () => {
    // A turn waits on a real provider round trip; a list that hangs is a broken
    // peer, not a slow one, and should not be papered over with a timeout.
    const seen: RequestInit[] = [];
    const spy = ((_url: string, init: RequestInit) => {
      seen.push(init);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(CONVO) });
    }) as unknown as typeof globalThis.fetch;
    const c = client(spy);
    await c.conversations(TOKEN).catch(() => undefined);
    await c.sendMessage(TOKEN, 'c1', 'hello').catch(() => undefined);
    expect(seen[0]?.signal).toBeUndefined();
    expect(seen[1]?.signal).toBeDefined();
  });

  it('percent-encodes the conversation id into every path', async () => {
    const seen: string[] = [];
    const spy = ((url: string) => {
      seen.push(url);
      return Promise.resolve({
        ok: true,
        status: 204,
        json: () => Promise.reject(new Error('no body')),
      });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).deleteConversation(TOKEN, '../../v1/consents/assistant.enabled');
    expect(seen[0]).toBe(
      'http://assistant.test/v1/conversations/..%2F..%2Fv1%2Fconsents%2Fassistant.enabled',
    );
  });

  it('refuses a transcript it cannot validate rather than passing it on', async () => {
    await expect(
      client(respond(200, { conversationId: 'c1', messages: [{ role: 'wizard' }] })).transcript(
        TOKEN,
        'c1',
      ),
    ).rejects.toThrow(/failed validation/);
  });
});

describe('consents', () => {
  const GRANTED = { granted: ['assistant.enabled', 'assistant.assets'] };

  it('reads, grants and revokes on the caller’s bearer', async () => {
    const seen: Array<{ url: string; method: string }> = [];
    const spy = ((url: string, init: RequestInit) => {
      seen.push({ url, method: String(init.method) });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(GRANTED) });
    }) as unknown as typeof globalThis.fetch;
    const c = client(spy);
    await expect(c.consents(TOKEN)).resolves.toEqual(GRANTED.granted);
    await c.grantConsent(TOKEN, 'assistant.assets');
    await c.revokeConsent(TOKEN, 'assistant.assets');
    expect(seen).toEqual([
      { url: 'http://assistant.test/v1/consents', method: 'GET' },
      { url: 'http://assistant.test/v1/consents/assistant.assets', method: 'PUT' },
      { url: 'http://assistant.test/v1/consents/assistant.assets', method: 'DELETE' },
    ]);
  });

  it('percent-encodes the scope into the path', async () => {
    // The scope reaches this client from a GraphQL variable, so it is caller
    // input: it must not be able to become a different route.
    const seen: string[] = [];
    const spy = ((url: string) => {
      seen.push(url);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(GRANTED) });
    }) as unknown as typeof globalThis.fetch;
    await client(spy).grantConsent(TOKEN, '../../v1/conversations');
    expect(seen[0]).toBe('http://assistant.test/v1/consents/..%2F..%2Fv1%2Fconversations');
  });

  it('maps the step-up requirement, an expired session and a bad request', async () => {
    await expect(
      client(respond(403, { error: 'stepup_required' })).grantConsent(TOKEN, 'assistant.assets'),
    ).rejects.toMatchObject({ extensions: { code: 'STEPUP_REQUIRED' } });
    await expect(client(respond(401, {})).consents(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'UNAUTHENTICATED' },
    });
    await expect(
      client(respond(400, { error: 'unknown_scope' })).grantConsent(TOKEN, 'nope'),
    ).rejects.toMatchObject({ extensions: { code: 'INVALID_REQUEST' } });
  });

  it('treats an unreachable service as a masked failure, not as no consents', async () => {
    const dead = (() =>
      Promise.reject(new Error('ECONNREFUSED'))) as unknown as typeof globalThis.fetch;
    await expect(client(dead).consents(TOKEN)).rejects.toThrow('assistant service unreachable');
  });
});
