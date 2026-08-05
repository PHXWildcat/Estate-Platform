import { z } from 'zod';
import type { ConsentScope } from '../consent';

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
  | { readonly outcome: 'denied_no_consent' }
  | { readonly outcome: 'error'; readonly reason: string };

export interface AssistantTool {
  /** Stable identifier, recorded on `assistant_tool_calls.tool_name`. */
  readonly name: string;
  /** Shown to the model. Describes what it returns and when to reach for it. */
  readonly description: string;
  /**
   * The consent scope this tool requires. Declaring it is mandatory — there is
   * no unscoped tool — and `registry.spec.ts` proves every registered tool
   * carries one, so a tool cannot ship with its gate forgotten.
   */
  readonly scope: ConsentScope;
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
