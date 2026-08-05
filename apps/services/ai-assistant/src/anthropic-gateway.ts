import Anthropic from '@anthropic-ai/sdk';
import type {
  LlmGateway,
  LlmToolDeclaration,
  LlmToolResult,
  LlmTurnInput,
  LlmTurnOutput,
} from './llm-gateway';

/**
 * The live model provider — the far side of the TB5 boundary (docs/01 §2.8,
 * docs/03 §4 TB5). This is the only file in the platform that speaks to a
 * third-party model, and the only file allowed to import `@anthropic-ai/sdk`
 * (the catalog entry says the same thing: the SDK exists in this service
 * because an isolating service is the point).
 *
 * WHAT THIS ADAPTER IS RESPONSIBLE FOR, and equally what it is not. It is a
 * TRANSLATOR, not a policy layer. The controls that make an estate assistant
 * safe all live upstream of it and none of them are re-implemented here:
 *
 *   * the egress assertion runs over the COMPLETE payload before every call
 *     into this class (`conversation.service.ts` → `assertOutboundClean`), so
 *     an SSN or a card number never reaches `create()` at all;
 *   * retrieved estate content arrives ALREADY framed as untrusted data, and
 *     this file never unwraps, re-frames or re-orders it;
 *   * the subject is not expressible in any tool schema rendered below,
 *     because `LlmToolDeclaration` was derived from zod objects that
 *     `assertSubjectFree` validated at boot;
 *   * every tool is read-only, so nothing the model asks for is a write.
 *
 * The two properties this file owns are FAIL CLOSED and DO NOT LEAK. Every
 * abnormal outcome — a safety refusal, a rate limit, a dead connection, a
 * response this code cannot parse, a turn that ran past its output budget —
 * collapses to the SAME fixed, platform-authored sentence. Provider error
 * text, `stop_details.explanation`, HTTP bodies and stack traces are treated
 * as untrusted for logging as well as for prompting: none of them is returned,
 * and none is written anywhere (`no-console` is enforced repo-wide, and this
 * class deliberately holds no logger to be tempted by).
 *
 * The uniformity is deliberate rather than lazy. Distinguishing "the safety
 * classifier declined" from "we are rate limited" hands whoever composed the
 * prompt — possibly through text in an uploaded PDF (docs/03 risk #6) — a
 * probe for which control fired. It is the same reasoning that collapses
 * "someone else's conversation" and "no such conversation" into one 404 in
 * `conversation.service.ts`, and that gives every M9 notification one subject
 * line.
 *
 * SERVER-SIDE REFUSAL FALLBACKS, and what enabling them MEANS for TB5. With
 * `fallbacks` on (the default, per Anthropic's guidance for this model), a
 * request the model's safety classifiers decline is re-run SERVER-SIDE on a
 * different model. That is a real capability win — a benign estate question
 * that trips a classifier gets answered instead of failing — but it is also a
 * disclosure fact that belongs in the threat model, not in a footnote: THE
 * SAME ESTATE PAYLOAD IS SENT TO A SECOND MODEL. Every zero-data-retention,
 * no-training and residency commitment the platform relies on for
 * `claude-opus-5` must therefore hold for the fallback model too. It is a
 * boolean option, defaulted on but switchable from configuration, precisely so
 * that a deployment whose provider agreement does not cover the fallback can
 * turn it off without a code change.
 */

/**
 * The model. A bare id with no date suffix, pinned as a constant rather than
 * read from configuration: which model sees estate content is a threat-model
 * decision (see the fallback note above), so changing it should be a reviewed
 * commit, not an environment variable somebody can edit at deploy time.
 */
export const ANTHROPIC_MODEL = 'claude-opus-5';

/**
 * Output ceiling for one non-streaming call.
 *
 * This turn loop is deliberately NON-STREAMING: streaming would be the first
 * streaming transport in this repo, and the port it implements
 * (`LlmGateway.complete`) is a single request/response step by design so that
 * the egress gate can inspect a complete outbound payload before each one.
 * Non-streaming in turn caps how large the output budget can safely be — past
 * roughly this size the SDK's own HTTP timeout becomes the failure mode.
 *
 * Note that on this model thinking is ON BY DEFAULT and `max_tokens` bounds
 * thinking PLUS the visible answer together, so this number is not a
 * "16k-character reply" budget; it is headroom for both.
 */
export const MAX_OUTPUT_TOKENS = 16000;

/**
 * The beta that enables `fallbacks: 'default'` — server-picked fallback routed
 * by refusal category, rather than a model list this repo would have to
 * maintain and migrate when a pinned fallback is retired.
 */
export const REFUSAL_FALLBACK_BETA = 'server-side-fallback-2026-07-01';

/**
 * The one thing this adapter says when it cannot produce a real answer.
 *
 * Platform-authored, non-technical, and identical for every failure mode (see
 * the class docstring on why the uniformity is a control). It names no
 * provider, no model, no status code and no cause, and it does not promise
 * that retrying will work — an apology that overstates what the platform knows
 * is its own small dishonesty in a transcript that is meant to be evidence.
 */
export const PROVIDER_UNAVAILABLE_MESSAGE =
  'I was not able to produce an answer for that. Please try asking again, or rephrase the question.';

/** Preamble introducing this turn's retrievals. Platform text, never content. */
const TOOL_RESULT_PREAMBLE =
  'Results of the read-only lookups performed for the request above, in the order they ran. ' +
  'Use them to answer. A lookup that was refused or returned nothing is not evidence of ' +
  'absence — say plainly what you could not read.';

/**
 * The provider surface this adapter needs, narrowed to one method.
 *
 * The SDK CLIENT IS NOT CONSTRUCTED HERE. It is built where configuration
 * lives and injected, for the reason the Plaid live client is built the same
 * way: no real credentials exist anywhere in this project, so the entire spec
 * for this file runs against a fake transport, and a class that news up its own
 * client cannot be driven by one. It is also what keeps the API key out of
 * this module's reach entirely.
 *
 * `Anthropic['beta']['messages']` satisfies this structurally, so the wiring is
 * `new AnthropicLlmGateway(client.beta.messages, …)` — the object, not a
 * detached method, so the SDK keeps its own `this`.
 */
export interface AnthropicMessagesLike {
  create(
    params: Anthropic.Beta.Messages.MessageCreateParamsNonStreaming,
    options?: { readonly timeout?: number },
  ): Promise<Anthropic.Beta.BetaMessage>;
}

export interface AnthropicGatewayOptions {
  /**
   * Deadline for one provider call, in MILLISECONDS — the unit the TypeScript
   * SDK uses (the Python SDK's seconds is a well-worn way to set a timeout a
   * thousand times longer than intended).
   *
   * This is load-bearing rather than hygienic. `conversation.service.ts` holds
   * a pooled connection and a row lock open across the whole turn, and its own
   * docstring names this adapter's request deadline as what bounds them. Note
   * the SDK retries by default (`maxRetries` is 2), so the worst-case wall
   * clock for one `complete()` is roughly this value times the attempt count —
   * size it against the transaction, not against a single hop.
   */
  readonly requestTimeoutMs?: number;
  /**
   * Server-side refusal fallbacks. Defaults to ON. Read the class docstring
   * before turning this on for a deployment whose provider agreement covers
   * only the primary model.
   */
  readonly fallbacks?: boolean;
}

/**
 * Stop reasons that mean "there is no answer in this response", other than a
 * refusal (which is handled first and separately, because its content must not
 * be read at all).
 *
 * `max_tokens` and `model_context_window_exceeded` both leave a TRUNCATED
 * answer in `content`, and a truncated answer is the most dangerous thing this
 * adapter could return: it reads as complete. An estate answer cut off before
 * its qualification — "the will names three beneficiaries" without "…but the
 * document is unsigned" — is worse than no answer. `pause_turn` cannot occur
 * with no server-side tools declared, and this adapter implements no
 * resumption, so it collapses here rather than being half-handled.
 */
const NON_ANSWER_STOP_REASONS: ReadonlySet<string> = new Set([
  'max_tokens',
  'model_context_window_exceeded',
  'pause_turn',
]);

export class AnthropicLlmGateway implements LlmGateway {
  readonly name = 'anthropic';

  constructor(
    private readonly messages: AnthropicMessagesLike,
    private readonly options: AnthropicGatewayOptions = {},
  ) {}

  async complete(input: LlmTurnInput): Promise<LlmTurnOutput> {
    const messages = renderMessages(input);
    if (messages.length === 0) {
      // Unreachable by construction — the turn service appends the user's
      // message to `history` before the first call — but a request with no
      // messages is a guaranteed 400, and spending a provider round trip to
      // discover that is worse than answering here.
      return safeAnswer();
    }

    let response: Anthropic.Beta.BetaMessage;
    try {
      response = await this.messages.create(
        this.buildRequest(input, messages),
        this.requestOptions(),
      );
    } catch (err) {
      return this.classifyFailure(err);
    }
    return interpret(response);
  }

  /**
   * Translate one turn into a Messages request.
   *
   * PARAMETERS DELIBERATELY ABSENT. `temperature`, `top_p` and `top_k` are
   * removed on this model and return 400; `thinking.budget_tokens` likewise.
   * `thinking` itself is omitted entirely, which on this model is exactly
   * equivalent to `{ type: 'adaptive' }` — sending the explicit form would be
   * one more thing to migrate for no behavioural difference. The spec asserts
   * the absence of all four, because "we simply never set it" is the kind of
   * property that survives until someone adds a knob.
   */
  private buildRequest(
    input: LlmTurnInput,
    messages: Anthropic.Beta.BetaMessageParam[],
  ): Anthropic.Beta.Messages.MessageCreateParamsNonStreaming {
    const tools = input.tools.map(toolSchema);
    return {
      model: ANTHROPIC_MODEL,
      max_tokens: MAX_OUTPUT_TOKENS,
      // PROMPT CACHING, and why the breakpoint is safe HERE and nowhere else.
      // The render order is tools → system → messages, so a breakpoint on the
      // system block covers the tool declarations and the standing instruction
      // and nothing after them. Both are platform-authored CONSTANTS: the
      // instruction is a module constant in conversation.service.ts, and the
      // declarations come from a registry that is identical for every user.
      // No volatile value — no timestamp, no conversation id, no user id —
      // precedes the breakpoint, which is what makes this both effective (the
      // prefix is byte-identical across calls) and safe: THE CACHED PREFIX
      // CONTAINS NO ESTATE CONTENT, so one user's conversation can never be
      // served out of a prefix another user's turn wrote. Everything
      // user-specific sits after it, in `messages`, uncached.
      system: [{ type: 'text', text: input.system, cache_control: { type: 'ephemeral' } }],
      messages,
      // An empty `tools` array is not the same as no tools to the API; the
      // registry is never empty in practice, and omitting the key is the
      // honest encoding of "no tools this turn".
      ...(tools.length > 0 ? { tools } : {}),
      ...(this.fallbacksEnabled()
        ? { betas: [REFUSAL_FALLBACK_BETA], fallbacks: 'default' as const }
        : {}),
    };
  }

  private fallbacksEnabled(): boolean {
    return this.options.fallbacks ?? true;
  }

  private requestOptions(): { readonly timeout: number } | undefined {
    const timeout = this.options.requestTimeoutMs;
    return timeout === undefined ? undefined : { timeout };
  }

  /**
   * Decide what a thrown provider failure means. THE ONLY THING THAT ESCAPES
   * THIS METHOD IS A CATEGORY DECISION — never the error's message, body or
   * request id.
   *
   * Three outcomes, and the split is about who can act on the failure:
   *
   *   * an operational failure (rate limit, connection, a bad request we
   *     built, an overloaded provider) is the user's turn not working right
   *     now. It becomes the safe answer, the turn commits, and the transcript
   *     records that the question was asked. `RateLimitError`,
   *     `APIConnectionError` and `BadRequestError` are named explicitly even
   *     though the base-class check below would catch all three: they are the
   *     cases the spec pins, and naming them is what documents that they were
   *     considered rather than swept up.
   *
   *   * a CREDENTIAL failure (401/403) is a deployment defect, and answering
   *     it with a polite apology would hide it forever — every turn would
   *     "work", every user would get the same bland sentence, and nothing
   *     would page. That is the M8 lesson about a container that stays up with
   *     a dead audit trail. It is rethrown, as a typed error carrying a REASON
   *     TOKEN and nothing else (the PlaidGatewayError precedent), so the turn
   *     fails loudly without any provider text reaching a response body.
   *
   *   * anything that is not an SDK error at all is a bug in this adapter or
   *     in the SDK. It is rethrown UNCHANGED, because a defect that a safe
   *     message silently absorbs is a defect nobody ever fixes, and because a
   *     stack trace is what makes it fixable. The service's error filter is
   *     what keeps it from reaching the caller.
   *
   * Note there is no retry here. The SDK already retries the retryable
   * statuses (`maxRetries` defaults to 2), and a second retry layer inside a
   * turn holding a database row lock would multiply the worst-case hold time
   * without improving the odds.
   */
  private classifyFailure(err: unknown): LlmTurnOutput {
    if (
      err instanceof Anthropic.AuthenticationError ||
      err instanceof Anthropic.PermissionDeniedError
    ) {
      throw new AnthropicGatewayError('provider_credentials_rejected');
    }
    if (
      err instanceof Anthropic.RateLimitError ||
      err instanceof Anthropic.APIConnectionError ||
      err instanceof Anthropic.BadRequestError ||
      err instanceof Anthropic.APIError
    ) {
      return safeAnswer();
    }
    throw err;
  }
}

/**
 * A provider failure the platform must not paper over. Carries a reason TOKEN
 * only — never a provider response body, which can carry request ids, model
 * names and echoed prompt fragments (the PlaidGatewayError rule, applied to
 * the one third party with estate content in its request payloads).
 */
export class AnthropicGatewayError extends Error {
  constructor(readonly reason: 'provider_credentials_rejected') {
    super(reason);
    this.name = 'AnthropicGatewayError';
  }
}

/** The fixed non-answer. A function so no caller can mutate a shared object. */
function safeAnswer(): LlmTurnOutput {
  return { kind: 'message', text: PROVIDER_UNAVAILABLE_MESSAGE };
}

/**
 * Read the provider's response.
 *
 * THE ORDER OF THE FIRST CHECK IS THE CONTROL. A safety refusal arrives as a
 * successful HTTP 200 whose `content` may be empty or partial and whose
 * `stop_details` may be null, so `stop_reason` is consulted BEFORE anything
 * reads `content` — code that indexes `content[0]` first breaks on exactly the
 * responses that matter most. `stop_details` is never read at all: it is
 * populated only on a refusal, and its `explanation` is provider prose about
 * why an estate question was declined, which is precisely the sort of text
 * that must not become an assistant's reply or a log line.
 */
function interpret(response: Anthropic.Beta.BetaMessage): LlmTurnOutput {
  const stopReason = response.stop_reason;
  if (stopReason === 'refusal') {
    return safeAnswer();
  }
  if (stopReason !== null && NON_ANSWER_STOP_REASONS.has(stopReason)) {
    return safeAnswer();
  }

  // A tool request outranks any prose accompanying it: the port cannot express
  // "a message AND a tool call" (see `LlmTurnOutput`), and the turn loop needs
  // the retrieval to make progress. Only the FIRST tool_use is taken — the
  // port is one step at a time, and the loop will come back for the next.
  for (const block of response.content) {
    if (block.type === 'tool_use') {
      return { kind: 'tool_call', name: block.name, input: asArguments(block.input) };
    }
  }

  const text = response.content
    .filter((block): block is Anthropic.Beta.BetaTextBlock => block.type === 'text')
    .map((block) => block.text)
    .join('\n')
    .trim();
  // No text and no tool call is an unparseable turn — an empty content array,
  // or a response made entirely of block types this adapter does not consume.
  // It fails closed like every other abnormal outcome rather than appending an
  // empty assistant message to a transcript that is meant to be evidence.
  return text.length > 0 ? { kind: 'message', text } : safeAnswer();
}

/**
 * Coerce the model's tool arguments to an object. `input` is typed `unknown`
 * by the SDK and is model output, so it is genuinely arbitrary.
 *
 * A non-object collapses to `{}` rather than being forwarded or thrown on. The
 * executor validates every call against the tool's own zod schema and reports
 * `invalid_input` as an ordinary outcome the model is told about, so the empty
 * object routes a malformed call into the path that already exists for
 * malformed calls. Arrays are excluded deliberately: a JSON array is an object
 * to `typeof`, and spreading one would produce numeric-keyed arguments that
 * fail validation in a much more confusing way.
 */
function asArguments(input: unknown): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return {};
  }
  return { ...(input as Record<string, unknown>) };
}

/**
 * Render the conversation for the provider.
 *
 * TOOL RESULTS TRAVEL AS A USER TURN, not as native `tool_result` blocks, and
 * that is a considered choice rather than an omission. The native protocol
 * requires each result to carry the `tool_use_id` of the assistant block that
 * requested it, and `LlmTurnInput` carries no ids: it hands over tool NAME,
 * outcome and text. The two ways to get ids back are both worse. Holding
 * per-instance state across `complete()` calls is disqualified outright — this
 * gateway is a singleton serving concurrent turns for different users, and one
 * user's tool_use ids and content leaking into another's request is a Zone B
 * breach, not a bug. Synthesising ids means also synthesising the assistant
 * `tool_use` blocks that "requested" them, including arguments this adapter
 * never saw — fabricating a record of what the model previously said, inside
 * the one product where the transcript is the evidence.
 *
 * So the results are quoted as data in a user turn. Nothing is lost that
 * matters: the model still sees which tool ran, what it returned and whether
 * it was refused, and every `ok` result is still wrapped in the untrusted-data
 * frame the turn service applied — this function does not re-frame or unwrap
 * it, because framing text twice teaches a reader that the markers are
 * decorative.
 *
 * A consequence worth stating: because history holds only committed message
 * text, no assistant message here ever ends in a dangling `tool_use`, so a
 * following user turn is always well-formed.
 */
function renderMessages(input: LlmTurnInput): Anthropic.Beta.BetaMessageParam[] {
  const messages: Anthropic.Beta.BetaMessageParam[] = [];
  for (const turn of input.history) {
    const text = turn.text.trim();
    // The API rejects an empty text block, and a blank turn cannot exist under
    // the request schema. Dropping it beats turning an impossible row into a
    // 400 that presents to the user as the provider being down.
    if (text.length === 0) {
      continue;
    }
    // The first message must be `user`. A conversation always opens with one,
    // so this only fires on a transcript that has somehow lost its first turn.
    if (messages.length === 0 && turn.role !== 'user') {
      continue;
    }
    messages.push({ role: turn.role, content: text });
  }
  if (input.toolResults.length > 0) {
    messages.push({ role: 'user', content: renderToolResults(input.toolResults) });
  }
  return messages;
}

/**
 * Quote this turn's retrievals.
 *
 * The header line interpolates `result.tool`, and that value is SAFE BY
 * CONSTRUCTION rather than by sanitisation here: `ToolExecutor.record` returns
 * the RESOLVED tool's own name — a compile-time constant from this service's
 * registry — and a hallucinated name is replaced with the `unknown` token
 * before it ever leaves the executor, precisely so that attacker-composed text
 * cannot ride a tool name into a prompt or into the audit stream. `outcome` is
 * a three-value enum. If either ever became free text, this line would need
 * the same delimiter neutralisation `frameUntrusted` applies to bodies.
 */
function renderToolResults(results: readonly LlmToolResult[]): string {
  const parts: string[] = [TOOL_RESULT_PREAMBLE];
  for (const result of results) {
    parts.push(`[lookup: ${result.tool} — outcome: ${result.outcome}]\n${result.text}`);
  }
  return parts.join('\n\n');
}

/**
 * Render one declaration as a provider tool definition.
 *
 * NOTHING HERE IS GUESSED. Every fact this renderer emits — name, description,
 * requiredness, and the scalar `type` — was derived from the tool's own zod
 * schema by `parameterTypeOf`, so the declaration the provider sees and the
 * object the executor re-parses on every call have ONE source. A hand-written
 * `"type": "string"` here would be a second, unvalidated description of the
 * same contract, and a wrong guess would make the model send an argument the
 * executor then refuses as `invalid_input` — a failure whose cause is two
 * layers away. That is also why `parameterTypeOf` throws on a shape it cannot
 * map rather than defaulting: an unmappable parameter is a decision someone
 * owes, taken at boot.
 *
 * The honest remaining gap: the tools' zod fields mostly have no `.describe()`,
 * so most parameter descriptions are empty strings and are omitted below. That
 * is a change to the tool definitions, not to this renderer.
 *
 * `additionalProperties: false` is advisory without `strict: true`, but it
 * tells the model not to invent arguments, and the executor's zod parse strips
 * unknown keys anyway — so it can only reduce malformed calls, never change
 * what a well-formed one does.
 */
function toolSchema(declaration: LlmToolDeclaration): Anthropic.Beta.BetaTool {
  const properties: Record<string, Record<string, unknown>> = {};
  const required: string[] = [];
  for (const parameter of declaration.parameters) {
    properties[parameter.name] = {
      type: parameter.type,
      ...(parameter.description.length > 0 ? { description: parameter.description } : {}),
    };
    if (parameter.required) {
      required.push(parameter.name);
    }
  }
  return {
    name: declaration.name,
    description: declaration.description,
    input_schema: {
      type: 'object',
      properties,
      required,
      additionalProperties: false,
    },
  };
}
