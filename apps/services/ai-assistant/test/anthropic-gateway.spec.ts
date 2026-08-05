import Anthropic from '@anthropic-ai/sdk';
import {
  ANTHROPIC_MODEL,
  AnthropicGatewayError,
  AnthropicLlmGateway,
  MAX_OUTPUT_TOKENS,
  PROVIDER_UNAVAILABLE_MESSAGE,
  REFUSAL_FALLBACK_BETA,
  type AnthropicMessagesLike,
} from '../src/anthropic-gateway';
import type { LlmTurnInput } from '../src/llm-gateway';

/**
 * Every test here runs against a FAKE TRANSPORT. No credentials exist anywhere
 * in this project and none are needed: the class takes an already-built
 * provider surface rather than constructing one, which is the whole reason it
 * is shaped that way (the Plaid live-client precedent).
 *
 * What these tests are actually protecting is not "the adapter formats JSON
 * correctly" — it is the two properties the adapter owns. It FAILS CLOSED (no
 * abnormal provider outcome ever becomes a plausible-looking answer) and it
 * DOES NOT LEAK (no provider error text, no refusal explanation, no estate
 * content in a place it was not put deliberately).
 */

type Params = Anthropic.Beta.Messages.MessageCreateParamsNonStreaming;
type Options = { readonly timeout?: number } | undefined;

/** One recorded call: what we sent, and what we were asked to send it with. */
interface Recorded {
  readonly params: Params;
  readonly options: Options;
}

class FakeMessages implements AnthropicMessagesLike {
  readonly calls: Recorded[] = [];

  constructor(private readonly reply: (call: number) => Anthropic.Beta.BetaMessage | Error) {}

  create(
    params: Params,
    options?: { readonly timeout?: number },
  ): Promise<Anthropic.Beta.BetaMessage> {
    this.calls.push({ params, options });
    const next = this.reply(this.calls.length - 1);
    return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
  }

  /** The single call these tests make; fails loudly rather than returning undefined. */
  only(): Recorded {
    expect(this.calls).toHaveLength(1);
    const call = this.calls[0];
    if (call === undefined) {
      throw new Error('unreachable: length asserted above');
    }
    return call;
  }
}

/**
 * A response fixture. The BetaMessage shape carries a dozen fields this adapter
 * never reads (usage counters, container, diagnostics); they are filled with
 * their null/zero forms so the fixture is a REAL response object rather than a
 * cast, and so a future SDK field that the adapter starts depending on shows up
 * here as a type error instead of as `undefined` at runtime.
 */
function response(
  content: Anthropic.Beta.BetaContentBlock[],
  stopReason: Anthropic.Beta.BetaStopReason | null,
  stopDetails: Anthropic.Beta.BetaRefusalStopDetails | null = null,
): Anthropic.Beta.BetaMessage {
  return {
    id: 'msg_test',
    type: 'message',
    role: 'assistant',
    model: ANTHROPIC_MODEL,
    content,
    stop_reason: stopReason,
    stop_details: stopDetails,
    stop_sequence: null,
    container: null,
    context_management: null,
    diagnostics: null,
    usage: {
      input_tokens: 1,
      output_tokens: 1,
      cache_creation: null,
      cache_creation_input_tokens: null,
      cache_read_input_tokens: null,
      fallback_credit: null,
      inference_geo: null,
      iterations: null,
      output_tokens_details: null,
      server_tool_use: null,
      service_tier: null,
      speed: null,
    },
  };
}

function textBlock(text: string): Anthropic.Beta.BetaTextBlock {
  return { type: 'text', text, citations: null };
}

function toolUseBlock(name: string, input: unknown): Anthropic.Beta.BetaToolUseBlock {
  return { type: 'tool_use', id: 'toolu_test', name, input };
}

/** A turn as `conversation.service.ts` composes one. */
function turn(overrides: Partial<LlmTurnInput> = {}): LlmTurnInput {
  return {
    system: 'You are an estate-planning assistant.',
    history: [{ role: 'user', text: 'Which documents do I have?' }],
    tools: [
      {
        name: 'list_documents',
        description: "The inventory of the signed-in user's documents.",
        parameters: [],
      },
      {
        name: 'get_document_text',
        description: 'Fetch the text of one version of one document.',
        parameters: [
          { name: 'documentId', description: 'The document id.', required: true, type: 'string' },
          { name: 'version', description: '', required: true, type: 'integer' },
        ],
      },
    ],
    toolResults: [],
    ...overrides,
  };
}

function gatewayReturning(reply: (call: number) => Anthropic.Beta.BetaMessage | Error): {
  gateway: AnthropicLlmGateway;
  transport: FakeMessages;
} {
  const transport = new FakeMessages(reply);
  return { gateway: new AnthropicLlmGateway(transport), transport };
}

describe('a normal message turn', () => {
  it('returns the model’s text as a message outcome', async () => {
    const { gateway } = gatewayReturning(() =>
      response([textBlock('You have three documents on file.')], 'end_turn'),
    );

    await expect(gateway.complete(turn())).resolves.toEqual({
      kind: 'message',
      text: 'You have three documents on file.',
    });
  });

  it('joins multiple text blocks and trims', async () => {
    const { gateway } = gatewayReturning(() =>
      response([textBlock('  First part.'), textBlock('Second part.  ')], 'end_turn'),
    );

    await expect(gateway.complete(turn())).resolves.toEqual({
      kind: 'message',
      text: 'First part.\nSecond part.',
    });
  });

  it('sends the conversation as alternating turns, with tool results as a user turn', async () => {
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    await gateway.complete(
      turn({
        history: [
          { role: 'user', text: 'first question' },
          { role: 'assistant', text: 'first answer' },
          { role: 'user', text: 'second question' },
        ],
        toolResults: [
          { tool: 'list_documents', outcome: 'ok', text: '<<<UNTRUSTED_DATA…>>>' },
          { tool: 'get_document_text', outcome: 'denied_no_consent', text: 'Not run: no consent.' },
        ],
      }),
    );

    const { messages } = transport.only().params;
    expect(messages.map((m) => m.role)).toEqual(['user', 'assistant', 'user', 'user']);
    expect(messages[0]?.content).toBe('first question');
    // The retrievals ride in a trailing user turn carrying both the framed
    // result and the platform-authored refusal — see `renderMessages` on why
    // native tool_result blocks are not reconstructable from this port.
    const quoted = messages[3]?.content;
    expect(typeof quoted).toBe('string');
    expect(quoted).toContain('list_documents');
    expect(quoted).toContain('<<<UNTRUSTED_DATA…>>>');
    expect(quoted).toContain('denied_no_consent');
  });

  it('drops turns that could not form a valid request', async () => {
    // Both guards are defensive — the request schema forbids a blank turn, and
    // a conversation always opens with a user one — but they are exercised
    // because the failure they prevent is a provider 400, which presents to the
    // user as the assistant being down rather than as the impossible row it is.
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    await gateway.complete(
      turn({
        history: [
          { role: 'assistant', text: 'an orphaned opening turn' },
          { role: 'user', text: '   ' },
          { role: 'user', text: 'the real question' },
        ],
      }),
    );

    expect(transport.only().params.messages).toEqual([
      { role: 'user', content: 'the real question' },
    ]);
  });

  it('caches the platform-authored prefix and nothing user-specific', async () => {
    // The breakpoint must sit on the system block: render order is
    // tools → system → messages, so it covers only constants. If it ever
    // migrated into `messages`, one user's estate content would become a
    // cacheable prefix — this asserts it has not.
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    await gateway.complete(turn());

    const { system, messages } = transport.only().params;
    expect(system).toEqual([
      {
        type: 'text',
        text: 'You are an estate-planning assistant.',
        cache_control: { type: 'ephemeral' },
      },
    ]);
    expect(JSON.stringify(messages)).not.toContain('cache_control');
  });

  it('declares each tool with its required parameters', async () => {
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    await gateway.complete(turn());

    expect(transport.only().params.tools).toEqual([
      {
        name: 'list_documents',
        description: "The inventory of the signed-in user's documents.",
        input_schema: {
          type: 'object',
          properties: {},
          required: [],
          additionalProperties: false,
        },
      },
      {
        name: 'get_document_text',
        description: 'Fetch the text of one version of one document.',
        input_schema: {
          type: 'object',
          // Each property carries its declared type, derived from the tool's
          // own zod schema rather than guessed here — a property with no type
          // leaves the provider to invent one, and a wrong guess returns as
          // `invalid_input` from the executor's re-validation with no visible
          // cause.
          properties: {
            documentId: { type: 'string', description: 'The document id.' },
            version: { type: 'integer' },
          },
          required: ['documentId', 'version'],
          additionalProperties: false,
        },
      },
    ]);
  });

  it('omits the tools key entirely when there are none to declare', async () => {
    // An empty array is not the same as an absent key to the API, and "no
    // tools this turn" is the honest encoding of a turn with no retrievals
    // available.
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    await gateway.complete(turn({ tools: [] }));

    expect(transport.only().params).not.toHaveProperty('tools');
  });
});

describe('a tool_use turn', () => {
  it('becomes a tool_call outcome carrying the model’s arguments', async () => {
    const { gateway } = gatewayReturning(() =>
      response(
        [toolUseBlock('get_document_text', { documentId: 'doc-1', version: 2 })],
        'tool_use',
      ),
    );

    await expect(gateway.complete(turn())).resolves.toEqual({
      kind: 'tool_call',
      name: 'get_document_text',
      input: { documentId: 'doc-1', version: 2 },
    });
  });

  it('takes the tool call in preference to any prose beside it', async () => {
    // The port cannot express "a message AND a tool call", and the turn loop
    // needs the retrieval to make progress.
    const { gateway } = gatewayReturning(() =>
      response([textBlock('Let me look that up.'), toolUseBlock('list_documents', {})], 'tool_use'),
    );

    await expect(gateway.complete(turn())).resolves.toMatchObject({
      kind: 'tool_call',
      name: 'list_documents',
    });
  });

  it('collapses non-object arguments to an empty object', async () => {
    // `input` is model output typed `unknown`. An empty object routes the call
    // into the executor's existing `invalid_input` path rather than into a
    // crash or a spread of numeric keys.
    for (const malformed of ['not an object', 42, null, ['a', 'b']]) {
      const { gateway } = gatewayReturning(() =>
        response([toolUseBlock('list_documents', malformed)], 'tool_use'),
      );
      await expect(gateway.complete(turn())).resolves.toEqual({
        kind: 'tool_call',
        name: 'list_documents',
        input: {},
      });
    }
  });
});

describe('failing closed', () => {
  it('answers a refusal safely, without throwing and without reading stop_details', async () => {
    // A refusal is a successful HTTP 200 whose content may be empty or partial
    // and whose stop_details carries provider prose about why an estate
    // question was declined. Neither may reach the transcript.
    const explanation = 'Declined: SENSITIVE-PROVIDER-EXPLANATION-TEXT';
    const { gateway } = gatewayReturning(() =>
      response([textBlock('A partial, disclaimed half-answer.')], 'refusal', {
        type: 'refusal',
        category: 'cyber',
        explanation,
        fallback_credit_token: null,
        fallback_has_prefill_claim: null,
        recommended_model: null,
      }),
    );

    const output = await gateway.complete(turn());

    expect(output).toEqual({ kind: 'message', text: PROVIDER_UNAVAILABLE_MESSAGE });
    expect(JSON.stringify(output)).not.toContain(explanation);
    expect(JSON.stringify(output)).not.toContain('cyber');
    // The partial content is dropped too — a refusal's content is not an answer.
    expect(JSON.stringify(output)).not.toContain('half-answer');
  });

  it.each([
    ['max_tokens' as const],
    ['model_context_window_exceeded' as const],
    ['pause_turn' as const],
  ])('answers safely when the turn stopped on %s', async (stopReason) => {
    // A truncated estate answer reads as a complete one — "the will names three
    // beneficiaries" without "…but it is unsigned" — which is worse than no
    // answer at all.
    const { gateway } = gatewayReturning(() =>
      response([textBlock('The will names three beneficiaries')], stopReason),
    );

    await expect(gateway.complete(turn())).resolves.toEqual({
      kind: 'message',
      text: PROVIDER_UNAVAILABLE_MESSAGE,
    });
  });

  it('answers safely when a rate limit is thrown, without leaking the provider’s text', async () => {
    const body = 'rate_limit_error: RETRY-AFTER-DETAIL-AND-ORG-ID';
    const { gateway } = gatewayReturning(
      () => new Anthropic.RateLimitError(429, { message: body }, body, new Headers()),
    );

    const output = await gateway.complete(turn());

    expect(output).toEqual({ kind: 'message', text: PROVIDER_UNAVAILABLE_MESSAGE });
    expect(JSON.stringify(output)).not.toContain('RETRY-AFTER-DETAIL-AND-ORG-ID');
  });

  it('answers safely when the connection fails, without leaking the cause', async () => {
    const { gateway } = gatewayReturning(
      () =>
        new Anthropic.APIConnectionError({
          message: 'connect ECONNREFUSED 10.0.0.7:443',
          cause: new Error('ECONNREFUSED'),
        }),
    );

    const output = await gateway.complete(turn());

    expect(output).toEqual({ kind: 'message', text: PROVIDER_UNAVAILABLE_MESSAGE });
    expect(JSON.stringify(output)).not.toContain('10.0.0.7');
  });

  it('answers safely when the request was rejected as malformed', async () => {
    const { gateway } = gatewayReturning(
      () => new Anthropic.BadRequestError(400, { message: 'bad' }, 'bad', new Headers()),
    );

    await expect(gateway.complete(turn())).resolves.toEqual({
      kind: 'message',
      text: PROVIDER_UNAVAILABLE_MESSAGE,
    });
  });

  it('answers safely when the response carries neither text nor a tool call', async () => {
    const { gateway } = gatewayReturning(() => response([], 'end_turn'));

    await expect(gateway.complete(turn())).resolves.toEqual({
      kind: 'message',
      text: PROVIDER_UNAVAILABLE_MESSAGE,
    });
  });

  it('does not call the provider at all when there is nothing to send', async () => {
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    const output = await gateway.complete(turn({ history: [], toolResults: [] }));

    expect(output).toEqual({ kind: 'message', text: PROVIDER_UNAVAILABLE_MESSAGE });
    expect(transport.calls).toHaveLength(0);
  });
});

describe('failures that must stay loud', () => {
  it.each([
    [
      'a rejected credential',
      new Anthropic.AuthenticationError(401, {}, 'unauthorized', new Headers()),
    ],
    ['a forbidden key', new Anthropic.PermissionDeniedError(403, {}, 'forbidden', new Headers())],
  ])('throws a reason token on %s rather than answering blandly', async (_label, err) => {
    // Answering 401/403 with a polite apology would hide a deployment defect
    // forever: every turn "works", every user gets the same sentence, nothing
    // pages. The M8 lesson about a container that stays up with a dead audit
    // trail.
    const { gateway } = gatewayReturning(() => err);

    await expect(gateway.complete(turn())).rejects.toThrow(AnthropicGatewayError);
    await expect(gateway.complete(turn())).rejects.toThrow('provider_credentials_rejected');
  });

  it('does not carry the provider’s message on the thrown error', async () => {
    // Deliberately NOT written as `rejects.toThrow(expect.not.stringContaining(…))`:
    // that form passes vacuously (mutation-tested — an error whose message was
    // the provider's own still satisfied it), which is exactly the shape of
    // green-but-inert assertion this repo keeps finding in review. The error is
    // caught and inspected instead.
    const { gateway } = gatewayReturning(
      () =>
        new Anthropic.AuthenticationError(
          401,
          {},
          'invalid x-api-key sk-ant-LEAKED',
          new Headers(),
        ),
    );

    const thrown: unknown = await gateway.complete(turn()).then(
      () => null,
      (err: unknown) => err,
    );

    expect(thrown).toBeInstanceOf(AnthropicGatewayError);
    const error = thrown as AnthropicGatewayError;
    expect(error.reason).toBe('provider_credentials_rejected');
    expect(error.message).toBe('provider_credentials_rejected');
    expect(`${error.message}\n${error.stack ?? ''}`).not.toContain('sk-ant-LEAKED');
    // No `cause`: chaining the original would re-attach the provider's message
    // to anything that walks the cause chain — a logger, a serializer, a
    // reporting SDK — which is the leak this class exists to prevent.
    expect((error as Error).cause).toBeUndefined();
  });

  it('rethrows a non-SDK error unchanged so the defect is visible', async () => {
    // A bug in this adapter or the SDK must not be absorbed into a plausible
    // apology; the service's error filter is what keeps it off the wire.
    const bug = new TypeError('cannot read properties of undefined');
    const { gateway } = gatewayReturning(() => bug);

    await expect(gateway.complete(turn())).rejects.toBe(bug);
  });
});

describe('the request itself', () => {
  it('names the model exactly, with no date suffix', async () => {
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    await gateway.complete(turn());

    expect(transport.only().params.model).toBe('claude-opus-5');
    expect(ANTHROPIC_MODEL).toBe('claude-opus-5');
  });

  it('never sends a parameter this model removed', async () => {
    // temperature, top_p and top_k are removed on this model and return 400;
    // so does thinking.budget_tokens. "We simply never set them" is exactly the
    // kind of property that survives right up until someone adds a knob, so it
    // is pinned rather than assumed.
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    await gateway.complete(
      turn({
        toolResults: [{ tool: 'list_documents', outcome: 'ok', text: 'framed data' }],
      }),
    );

    const { params } = transport.only();
    const serialized = JSON.stringify(params);
    for (const forbidden of ['temperature', 'top_p', 'top_k', 'budget_tokens']) {
      expect(params).not.toHaveProperty(forbidden);
      expect(serialized).not.toContain(forbidden);
    }
    // Thinking is on by default on this model; omitting the key is equivalent
    // to `{ type: 'adaptive' }` and is one less thing to migrate.
    expect(params).not.toHaveProperty('thinking');
    expect(params.max_tokens).toBe(MAX_OUTPUT_TOKENS);
  });

  it('requests server-side refusal fallbacks by default', async () => {
    const { gateway, transport } = gatewayReturning(() => response([textBlock('ok')], 'end_turn'));

    await gateway.complete(turn());

    const { params } = transport.only();
    expect(params.fallbacks).toBe('default');
    expect(params.betas).toEqual([REFUSAL_FALLBACK_BETA]);
  });

  it('omits fallbacks when a deployment turns them off', async () => {
    // The switch exists because enabling fallbacks means the SAME estate
    // payload is re-run on a second model, so the zero-data-retention
    // commitment has to cover that model too (docs/03 §4 TB5). A deployment
    // whose provider agreement does not must be able to opt out without a code
    // change.
    const transport = new FakeMessages(() => response([textBlock('ok')], 'end_turn'));
    const gateway = new AnthropicLlmGateway(transport, { fallbacks: false });

    await gateway.complete(turn());

    const { params } = transport.only();
    expect(params).not.toHaveProperty('fallbacks');
    expect(params).not.toHaveProperty('betas');
  });

  it('passes the configured deadline through in milliseconds', async () => {
    // The turn service holds a pooled connection and a row lock open across
    // this call; the deadline is what bounds them.
    const transport = new FakeMessages(() => response([textBlock('ok')], 'end_turn'));
    const gateway = new AnthropicLlmGateway(transport, { requestTimeoutMs: 30_000 });

    await gateway.complete(turn());

    expect(transport.only().options).toEqual({ timeout: 30_000 });
  });

  it('reports its adapter name for the turn audit event', () => {
    expect(new AnthropicLlmGateway(new FakeMessages(() => response([], 'end_turn'))).name).toBe(
      'anthropic',
    );
  });
});
