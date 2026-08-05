import { z } from 'zod';
import type { ConsentScope } from '../consent';
import type { LlmParameterType } from '../llm-gateway';

/**
 * The assistant's tool contract.
 *
 * THE SUBJECT IS NEVER A PARAMETER. A tool is handed the authority it runs
 * under — a verified session subject and that caller's own bearer — and it
 * declares only the arguments that describe WHAT to fetch, never WHOSE data to
 * fetch. This is the structural answer to docs/03 risk #6 (prompt injection via
 * uploaded documents, rated High likelihood): injected text can persuade the
 * model to CALL a tool, but it cannot express whose estate it wants, because
 * no tool schema has a field in which to say so. Framing document text as data
 * is the layer that can be argued with; this is the layer that cannot.
 *
 * The corollary is that every tool is READ-ONLY (docs/03 §4 TB5: "tool scopes
 * for the assistant are read-only"). There is no write tool, no send tool, no
 * outbound-fetch tool and no web search, so the worst an injection achieves is
 * a misleading answer to the owner about the owner's own data — which is
 * exactly why the risk register rates the impact Medium, and what keeps it
 * there.
 */

/** Authority for one tool invocation. Supplied by the executor, never by the model. */
export interface ToolContext {
  /**
   * The VERIFIED session subject, taken from CallerGuard's introspected
   * session. Never a model-supplied value, never a request-body field.
   */
  readonly userId: string;
  /**
   * The caller's own bearer, forwarded to peer services unchanged. This is why
   * the service needs no credential of its own: it can reach exactly what this
   * user could already reach, and nothing else.
   */
  readonly bearer: string;
}

/**
 * The result of one invocation. The three cases mirror the `outcome` CHECK on
 * `assistant_tool_calls` exactly, so the type and the constraint cannot drift:
 * a refusal or an error has no data to carry, and the database refuses a row
 * that claims otherwise.
 */
export type ToolOutcome =
  | { readonly outcome: 'ok'; readonly data: unknown }
  | {
      readonly outcome: 'denied_no_consent';
      /**
       * Which required scopes were not granted. Safe to put in a prompt and in
       * a response: these are compile-time constants from the closed
       * `CONSENT_SCOPES` vocabulary, never user or model text. Naming them is
       * what lets the assistant say "turn on document access" instead of the
       * unactionable "something was denied" — a refusal the user cannot act on
       * teaches them the feature is broken rather than gated.
       */
      readonly missing: readonly ConsentScope[];
    }
  | { readonly outcome: 'error'; readonly reason: string };

export interface AssistantTool {
  /** Stable identifier, recorded on `assistant_tool_calls.tool_name`. */
  readonly name: string;
  /** Shown to the model. Describes what it returns and when to reach for it. */
  readonly description: string;
  /**
   * The consent scopes this tool requires — ALL of them, not any of them.
   * Declaring at least one is mandatory (there is no unscoped tool) and
   * `tool-registry.spec.ts` proves every registered tool carries a non-empty
   * set, so a tool cannot ship with its gate forgotten.
   *
   * A SET rather than a single scope because M10 PR3's analysers read across
   * domains: missing-document detection needs the document inventory AND the
   * profile facts that decide which instruments are expected. Requiring the
   * union is strictly narrower than the alternative of minting one coarse
   * `assistant.analysis` grant that would imply asset, document and profile
   * reads together — and it keeps every existing tool's gate exactly where it
   * was, as a one-element set.
   */
  readonly scopes: readonly ConsentScope[];
  /** Argument declaration. Must not name a subject — see `assertSubjectFree`. */
  readonly input: z.ZodObject<z.ZodRawShape>;
  execute(ctx: ToolContext, input: Record<string, unknown>): Promise<ToolOutcome>;
}

/**
 * Words that name a PERSON whose data is being selected. A parameter
 * containing one would let a caller — or an injected instruction the model
 * relayed — nominate a subject other than the session's own.
 *
 * This is deliberately broader than the obvious `userId`: the failure mode is
 * a well-meaning future tool adding `ownerUserId` "just for the estate view",
 * which is how the executor's session-scoping gets bypassed without anyone
 * editing the executor.
 *
 * `account` is deliberately NOT here. In this product it names a financial
 * resource rather than a person, so banning it would block a legitimate future
 * tool; a resource id is safe because authorization still happens downstream
 * against the forwarded bearer, which is a different control from this one.
 */
const SUBJECT_WORDS: ReadonlySet<string> = new Set([
  'user',
  'users',
  'uid',
  'owner',
  'owners',
  'subject',
  'principal',
  'actor',
  'actors',
  'tenant',
  'behalf',
  'onbehalf',
  'impersonate',
]);

/**
 * Split an identifier into lowercase words across camelCase and snake_case.
 * Matching whole words rather than substrings is what makes `ownerUserId` fail
 * while `assetId` passes — an earlier anchored-regex version of this check
 * silently admitted every camelCase compound, which is the exact shape of
 * parameter a future tool would add.
 */
function identifierWords(param: string): string[] {
  return param
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^a-zA-Z0-9]+/)
    .map((word) => word.toLowerCase())
    .filter((word) => word.length > 0);
}

/**
 * Map one zod field to its JSON Schema type, unwrapping optional/nullable/
 * default so a wrapper does not erase the type underneath.
 *
 * Throws rather than defaulting to 'string' for an unmapped shape: a silently
 * mistyped parameter is a provider that sends the wrong thing and a tool that
 * refuses it, with the cause two layers away. Every tool here takes flat
 * scalars, so an exotic shape means someone added one and should say what it
 * should look like on the wire.
 */
export function parameterTypeOf(name: string, schema: z.ZodTypeAny): LlmParameterType {
  // Narrowed on each branch rather than through a shared ternary: zod's
  // `removeDefault()` is typed loosely enough that a combined expression
  // resolves to `any`, and an `any` here would silently defeat the exhaustive
  // check below — the one place this function must not guess.
  let inner: z.ZodTypeAny = schema;
  for (;;) {
    if (inner instanceof z.ZodOptional || inner instanceof z.ZodNullable) {
      inner = (inner as z.ZodOptional<z.ZodTypeAny> | z.ZodNullable<z.ZodTypeAny>).unwrap();
    } else if (inner instanceof z.ZodDefault) {
      inner = (inner as z.ZodDefault<z.ZodTypeAny>).removeDefault();
    } else {
      break;
    }
  }
  if (inner instanceof z.ZodString) {
    return 'string';
  }
  if (inner instanceof z.ZodBoolean) {
    return 'boolean';
  }
  if (inner instanceof z.ZodNumber) {
    return inner.isInt ? 'integer' : 'number';
  }
  throw new ToolContractError(
    `tool parameter "${name}" has no declarable wire type: add one to parameterTypeOf`,
  );
}

export class ToolContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ToolContractError';
  }
}

/**
 * Refuse a tool whose input declares a subject. Thrown at registry
 * construction, which happens at boot — so the failure is a process that will
 * not start, not a request that quietly reads the wrong estate.
 */
/**
 * True for a subject word, including the run-together `<word>id` / `<word>ids`
 * spellings that carry no boundary to split on — `userid` and `ownerid` are the
 * lowercase forms a developer writes when naming a parameter after a SQL
 * column, and the word splitter cannot see them.
 *
 * Derived from SUBJECT_WORDS by suffix rather than enumerated, so a word added
 * above is covered in every spelling without a second list to keep in sync. It
 * deliberately does NOT use substring matching: `uid` is a substring of
 * `liquidity` and `actor` of `factor`, so a contains-check would refuse
 * plausible estate parameters and a fence that cries wolf gets deleted.
 */
function isSubjectWord(word: string): boolean {
  if (SUBJECT_WORDS.has(word)) {
    return true;
  }
  if (word.endsWith('ids') && SUBJECT_WORDS.has(word.slice(0, -3))) {
    return true;
  }
  return word.endsWith('id') && SUBJECT_WORDS.has(word.slice(0, -2));
}

/**
 * Refuse a tool that declares no consent scope.
 *
 * An empty set would make `permits`-for-every-scope vacuously true, so the tool
 * would run for a user who has granted nothing — a gate that reads as present
 * and is not, which is the vacuous-check failure this codebase has now found
 * three times (the M4 legal-hold zero-callers, the M6 reset teardown, PR1's own
 * Cedar PEP). Boot-time, like every other tool-contract rule here.
 */
export function assertScoped(tool: AssistantTool): void {
  if (tool.scopes.length === 0) {
    throw new ToolContractError(
      `tool "${tool.name}" declares no consent scope: every retrieval is gated, and an empty set gates nothing`,
    );
  }
}

/**
 * The scope set as ONE audit-safe token: sorted, de-duplicated, joined with
 * ':'. `assistant_tool_calls.scope` is a single TEXT column and audit detail
 * values must match SAFE_TOKEN_PATTERN (`[A-Za-z0-9_.:-]{1,128}`), so a
 * comma-joined list is not expressible and an array column would mean
 * backfilling an append-only table whose UPDATE is revoked.
 *
 * Sorted so the same set always produces the same token — evidence that changes
 * spelling with declaration order is evidence somebody has to normalize before
 * they can count it.
 */
export function scopeToken(scopes: readonly ConsentScope[]): string {
  return [...new Set(scopes)].sort().join(':');
}

export function assertSubjectFree(tool: AssistantTool): void {
  for (const param of Object.keys(tool.input.shape)) {
    const offending = identifierWords(param).find(isSubjectWord);
    if (offending !== undefined) {
      throw new ToolContractError(
        `tool "${tool.name}" declares subject-selecting parameter "${param}": the subject comes from the verified session, never from tool input`,
      );
    }
  }
}

/**
 * The closed set of tools the assistant may call. Construction validates the
 * whole set, so an invalid tool is a boot failure rather than a runtime
 * surprise, and duplicate names are refused because `assistant_tool_calls`
 * records a name and ambiguous evidence is not evidence.
 */
export class ToolRegistry {
  private readonly byName: ReadonlyMap<string, AssistantTool>;

  constructor(tools: readonly AssistantTool[]) {
    const byName = new Map<string, AssistantTool>();
    for (const tool of tools) {
      assertSubjectFree(tool);
      assertScoped(tool);
      if (byName.has(tool.name)) {
        throw new ToolContractError(`duplicate tool name "${tool.name}"`);
      }
      byName.set(tool.name, tool);
    }
    this.byName = byName;
  }

  /** Null for an unknown name — a model may hallucinate one, and that is a refusal, not a crash. */
  get(name: string): AssistantTool | null {
    return this.byName.get(name) ?? null;
  }

  list(): readonly AssistantTool[] {
    return [...this.byName.values()];
  }
}
