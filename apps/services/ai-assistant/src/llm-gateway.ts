/**
 * The model-provider port — the seam docs/01 §2.8 and docs/03 §4 TB5 require:
 * "every external integration (LLM providers included) goes through an
 * isolating service", and inside that service through ONE interface, so there
 * is exactly one place where estate content crosses to a third party.
 *
 * The live Anthropic adapter is M10 PR2. Until it exists `loadConfig` REFUSES
 * `LLM_MODE=anthropic` outright, in every environment — a config that selects
 * an unwired provider must fail at boot, not per request — so the deterministic
 * stub below is the only implementation this build can run. That is also why
 * the port is shaped around a SINGLE STEP rather than a streamed conversation:
 * a turn is a loop the conversation service drives (ask, maybe run a read-only
 * tool, ask again), and keeping the provider's job to "given this state, say
 * what happens next" is what lets the egress assertion inspect a complete
 * outbound payload before every single provider call.
 */

/**
 * One declared tool parameter, flattened out of the tool's zod schema.
 *
 * The declaration deliberately carries no JSON Schema: a provider-shaped schema
 * blob would be a second description of the tool's input living next to the zod
 * object that actually validates it, and the two would drift. The adapter's job
 * in PR2 is to render this into whatever the provider's API wants; the
 * authority stays `AssistantTool.input`, which is also what `assertSubjectFree`
 * inspects — so a parameter that cannot exist in the registry cannot appear
 * here either.
 */
export interface LlmToolParameter {
  readonly name: string;
  readonly description: string;
  readonly required: boolean;
}

export interface LlmToolDeclaration {
  readonly name: string;
  readonly description: string;
  readonly parameters: readonly LlmToolParameter[];
}

/** One prior turn of the conversation, decrypted from `assistant_messages`. */
export interface LlmTurn {
  readonly role: 'user' | 'assistant';
  readonly text: string;
}

/**
 * The result of one tool invocation, as the model will see it.
 *
 * `outcome` mirrors `ToolOutcome` and the `assistant_tool_calls` CHECK exactly,
 * so a refusal is visible to the model AS a refusal — it can say "I could not
 * look that up because you have not granted that permission" instead of
 * inventing a plausible answer from nothing, which is what a silently omitted
 * result produces. `text` for an `ok` outcome is retrieved estate content and
 * arrives here ALREADY FRAMED as untrusted data by the conversation service.
 */
export interface LlmToolResult {
  readonly tool: string;
  readonly outcome: 'ok' | 'denied_no_consent' | 'error';
  readonly text: string;
}

/** Everything that would leave the platform for one provider call. */
export interface LlmTurnInput {
  /** Standing instruction, including the untrusted-data rule. Platform-authored. */
  readonly system: string;
  /** Prior turns plus the turn just taken, oldest first. */
  readonly history: readonly LlmTurn[];
  /** The read-only tools available for this turn. */
  readonly tools: readonly LlmToolDeclaration[];
  /** Results of the tools already run within THIS turn, in call order. */
  readonly toolResults: readonly LlmToolResult[];
}

/**
 * What a provider may say next. A discriminated union rather than an optional
 * `toolCall` field: "a message AND a tool call" is not a state this service
 * knows how to persist (one assistant row per turn), and a shape that cannot
 * express it needs no branch that handles it.
 */
export type LlmTurnOutput =
  | { readonly kind: 'message'; readonly text: string }
  | { readonly kind: 'tool_call'; readonly name: string; readonly input: Record<string, unknown> };

export interface LlmGateway {
  /** Adapter token recorded on `assistant.turn.completed` — never a model output. */
  readonly name: string;
  complete(input: LlmTurnInput): Promise<LlmTurnOutput>;
}

/**
 * Flatten everything in an outbound payload into one string for the egress
 * assertion (`privacy/egress.ts`).
 *
 * The walk is GENERIC rather than field-by-field, and that is the whole point.
 * A hand-written flattener that names `system`, `history`, `tools` and
 * `toolResults` inspects exactly the fields someone remembered; the next field
 * added to `LlmTurnInput` would leave the platform unexamined, and the failure
 * would be silent and permanent. Walking the object instead means a new field
 * is covered by construction — the same reasoning as
 * `credentialsHeldIn`'s deep walk in @estate/auth-guard, which exists because a
 * credential folded into a nested config object would otherwise have escaped
 * its fence.
 *
 * Numbers are stringified alongside strings: a card number that arrived as a
 * JSON number is still a card number, and the Luhn detector cannot see what
 * this function does not emit.
 */
export function flattenForInspection(input: LlmTurnInput): string {
  const parts: string[] = [];
  collectScalars(input, parts, new WeakSet<object>());
  return parts.join('\n');
}

function collectScalars(value: unknown, out: string[], seen: WeakSet<object>): void {
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (typeof value === 'number' || typeof value === 'bigint') {
    out.push(String(value));
    return;
  }
  if (typeof value !== 'object' || value === null) {
    return;
  }
  // Cycles are impossible in the shapes above, but a guard costs nothing and a
  // hang inside a security gate would present as an outage, not as a refusal.
  if (seen.has(value)) {
    return;
  }
  seen.add(value);
  if (Array.isArray(value)) {
    for (const entry of value) {
      collectScalars(entry, out, seen);
    }
    return;
  }
  for (const entry of Object.values(value)) {
    collectScalars(entry, out, seen);
  }
}

/** Words a tool name splits into, for the stub's deterministic matching. */
function nameTokens(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^a-zA-Z0-9]+/)
    .map((token) => token.toLowerCase())
    .filter((token) => token.length > 0);
}

/**
 * The dev/test gateway. DETERMINISTIC and offline: it makes no network call,
 * holds no credential, and returns the same output for the same input forever.
 *
 * It is not a mock in the test-double sense — it is the implementation the
 * whole platform runs on until PR2, including the local stack, so it has one
 * real job: EXERCISE THE FULL TOOL LOOP. A stub that only ever answered with
 * prose would leave the tool executor, the consent gate, the
 * `assistant_tool_calls` writes, the untrusted-data framing and the egress
 * assertion untravelled outside unit tests, and those are the controls this
 * milestone exists to build.
 *
 * The behaviour, derived entirely from the input:
 *
 *   * If the latest user turn names a declared tool that has not run yet this
 *     turn, request it — once. Skipping tools already present in
 *     `toolResults` is what makes the loop TERMINATE rather than lean on the
 *     conversation service's iteration cap; the cap is a backstop against a
 *     misbehaving provider, not the stub's exit condition.
 *   * A tool with REQUIRED parameters is not called, because the stub has no
 *     way to invent an id and a guessed one would be a fabricated retrieval.
 *     It answers by naming what it would need, which is also the honest
 *     behaviour for a real model missing an argument.
 *   * Otherwise summarize: how many retrievals ran, and the fact that no model
 *     provider answered. The summary quotes NO retrieved content — an operator
 *     reading a stub transcript should never mistake it for a model's words.
 */
export class StubLlmGateway implements LlmGateway {
  readonly name = 'stub';

  complete(input: LlmTurnInput): Promise<LlmTurnOutput> {
    return Promise.resolve(this.decide(input));
  }

  private decide(input: LlmTurnInput): LlmTurnOutput {
    const prompt = lastUserText(input.history).toLowerCase();
    const alreadyRun = new Set(input.toolResults.map((result) => result.tool));
    const candidate = input.tools.find(
      (tool) =>
        !alreadyRun.has(tool.name) &&
        nameTokens(tool.name).every((token) => prompt.includes(token)),
    );

    if (candidate) {
      const missing = candidate.parameters.filter((param) => param.required).map((p) => p.name);
      if (missing.length > 0) {
        return {
          kind: 'message',
          text: `(stub gateway) I would use "${candidate.name}" but it requires ${missing.join(', ')}.`,
        };
      }
      return { kind: 'tool_call', name: candidate.name, input: {} };
    }

    const ran = input.toolResults.length;
    const refused = input.toolResults.filter((r) => r.outcome === 'denied_no_consent').length;
    return {
      kind: 'message',
      text:
        `(stub gateway) No model provider is configured in this environment, so this is not ` +
        `an answer. Retrievals this turn: ${ran} (${refused} refused for want of consent).`,
    };
  }
}

/** The most recent user turn, or '' when the history somehow has none. */
function lastUserText(history: readonly LlmTurn[]): string {
  for (let i = history.length - 1; i >= 0; i -= 1) {
    const turn = history[i];
    if (turn !== undefined && turn.role === 'user') {
      return turn.text;
    }
  }
  return '';
}
