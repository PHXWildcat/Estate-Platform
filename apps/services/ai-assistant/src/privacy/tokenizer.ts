import { inspectEgress } from './egress';

/**
 * PII tokenization before any model call (docs/03 §4 TB5) — the half that
 * SUBSTITUTES rather than refuses.
 *
 * `egress.ts` is the fail-closed assertion for values that must never leave in
 * any form: an SSN gets no placeholder, because a round-tripped SSN is still an
 * SSN that crossed TB5. This module is the complementary half — values that
 * legitimately participate in an estate conversation ("the Elm Street house",
 * "Dad's 2019 will") but have no business reaching a third-party provider as
 * themselves. They travel as stable, meaningless placeholders and are restored
 * before the user sees the answer.
 *
 * ===========================================================================
 * WHY BY FIELD, NOT BY REGEX OVER PROSE
 * ===========================================================================
 *
 * The tempting design is a detector that finds names in text. It does not work
 * without NER, and a half-working one is worse than none: it mangles ordinary
 * words ("Will", "Trust", "Grant", "Rose" are all estate vocabulary AND names),
 * misses the names it was built for, and leaves everyone believing a control
 * exists. So this tokenizer never guesses. The assistant's tool results are
 * structured JSON with schemas this repo owns (clients/*.client.ts), so
 * `TOOL_FIELD_RULES` below names the exact JSON paths that carry user-authored
 * identifiers. Replacing a known field's value is precise by construction and
 * has no false positives at all.
 *
 * The cost of that precision is that coverage is a LIST, and a list goes stale.
 * `assertTokenizerCoversTools` is the answer: it refuses a tool this module has
 * never made a decision about, in either direction, so a new retrieval arrives
 * with a tokenization decision or the process does not start
 * (the `assertSubjectFree` precedent in tools/registry.ts).
 *
 * ===========================================================================
 * THE LIMITS, STATED PLAINLY — THESE ARE RECORDED GAPS, NOT OVERSIGHTS
 * ===========================================================================
 *
 * 1. `get_document_text` IS NOT TOKENIZED. It returns the user's own document
 *    PROSE — a will, a deed, a page of OCR — which is not field-structured, so
 *    there is nothing here to key on. Names inside a will reach the provider as
 *    written. That is accepted for three reasons that hold together and would
 *    not hold apart: the content is the user's OWN, it is gated behind the
 *    separate `assistant.documents.content` consent scope precisely because it
 *    is a strictly larger disclosure (tools/document.tools.ts), and it is
 *    framed as untrusted data. Closing it needs NER over legal prose, with its
 *    own accuracy, cost and vendor questions — its own decision, not a detail
 *    of this one.
 *
 * 2. MOST OF THE REGISTRY IS DORMANT TODAY, deliberately. PR1's peer clients
 *    already drop personal names before they exist as values in this process
 *    (`profile.client.ts` discards `legalName`, family `name` and `dob`;
 *    beneficiaries come back as contact ids). So no PERSON placeholder is
 *    minted by the shipped tool surface. The PERSON rules are kept anyway, for
 *    the failure this codebase keeps finding in review: someone widens a client
 *    schema for a good reason and the privacy layer, being somewhere else,
 *    silently does not follow. A dormant rule costs a line and fires the moment
 *    the field appears.
 *
 * 3. OPAQUE IDS ARE NOT TOKENIZED. `assetId`, `documentId` and `contactId` are
 *    UUIDs: not user-authored, carrying no information about a person or a
 *    property, and already meaningless outside this platform — a token is what
 *    they are. Tokenizing them would also force a DETOKENIZATION PATH ON THE
 *    INBOUND SIDE, because the model hands `assetId` back as a tool argument to
 *    a schema that demands a UUID; that trades a real failure mode on the
 *    tool-calling path for very little. The accepted residual is that a
 *    provider retaining logs could observe the same opaque id across
 *    conversations. Nothing about the user is recoverable from it.
 *
 * ===========================================================================
 * WHY THIS CANNOT WEAKEN `egress.ts`
 * ===========================================================================
 *
 * Substitution and refusal interact badly if nobody thinks about it. If a user
 * titles an asset "dad's account 123-45-6789", tokenizing that title to
 * ⟦ASSET_1⟧ removes the SSN from the outbound payload — so `assertEgressClean`
 * then finds nothing, passes, and the fail-closed gate has been silenced by the
 * privacy layer. The turn proceeds; the control never fires; the operator never
 * learns that an SSN is sitting in an asset title.
 *
 * So the tokenizer REFUSES TO HANDLE a value that trips the egress detectors:
 * it leaves it exactly as it found it, and the assertion downstream still sees
 * it and still refuses the turn. The valuable property is that this holds
 * WHATEVER ORDER the two are called in — the tokenizer cannot be the thing that
 * handles an SSN, so it cannot be the thing that hides one.
 */

/**
 * The kinds of identifier this module knows how to stand in for.
 *
 * The kind is part of the placeholder because it is the only thing the model
 * gets to know about the value it replaced. "⟦ASSET_1⟧ is worth more than
 * ⟦ASSET_2⟧" is a sentence worth being able to write; "⟦X_1⟧" is not.
 */
export type TokenKind = 'ASSET' | 'DOCUMENT' | 'PERSON';

/**
 * Placeholder delimiters: U+27E6/U+27E7 MATHEMATICAL WHITE SQUARE BRACKET.
 *
 * Chosen because they are effectively absent from estate prose, from legal
 * documents and from a model's own prose, which is what makes the two rules
 * below safe: detokenization can match them exactly with no risk of eating
 * ordinary text, and a placeholder that escapes to a user is unmistakably a
 * placeholder rather than a plausible wrong value.
 */
const OPEN = '⟦';
const CLOSE = '⟧';

/** Matches a well-formed placeholder anywhere in a string. Used only in `replace`. */
const PLACEHOLDER_GLOBAL = /⟦[A-Z]+_\d+⟧/g;

/** Matches a string that is ENTIRELY one placeholder. Non-global: no `lastIndex` state. */
const PLACEHOLDER_EXACT = /^⟦[A-Z]+_\d+⟧$/;

/**
 * Shortest mapped value that `tokenizeText` will hunt for in free text.
 *
 * Structured fields are replaced at ANY length: the schema said the field is a
 * title, so there is no ambiguity to weigh. Free text is different — an asset
 * titled "IRA" or "Car" would otherwise be substituted everywhere those letters
 * appear in a sentence. The failure is one-directional (over-replacement mangles
 * a history message, it never leaks one), so the floor is set for readability
 * rather than for safety, and it is deliberately low.
 */
const MIN_TEXT_MATCH_LENGTH = 4;

/**
 * One tokenizable field, as a path through a tool's JSON result.
 *
 * Paths are matched against OBJECT KEYS ONLY — arrays are transparent, so
 * `['title']` matches the title of every element of a top-level array as well
 * as a top-level `title`. That is what a list-returning tool needs, and it
 * keeps the rules readable without an index or wildcard syntax to get wrong.
 * Matching is exact and depth-anchored: `['title']` will not match a `title`
 * nested two levels down that nobody has thought about.
 */
interface FieldRule {
  readonly path: readonly string[];
  readonly kind: TokenKind;
}

/**
 * THE SPECIFICATION: for every tool the assistant can call, which fields of its
 * result carry a user-authored identifier.
 *
 * An empty array is a DECISION, not an omission — it records that this tool's
 * result was examined and returns only ids, enums, dates, decimal strings and
 * booleans. `assertTokenizerCoversTools` is what makes the distinction between
 * "decided: nothing" and "never considered" enforceable.
 *
 * Rules marked DORMANT describe fields the current peer-client schemas strip
 * before they reach this process. See limit 2 in the module docstring.
 */
const TOOL_FIELD_RULES: ReadonlyMap<string, readonly FieldRule[]> = new Map<
  string,
  readonly FieldRule[]
>([
  // Totals only: two decimal strings and two counts. Nothing user-authored.
  ['get_estate_summary', []],

  // `title` is free text the user wrote — "Mom's house on Elm St", "Joint
  // account with Sarah". The single highest-value rule in this file, and the
  // reason the module exists. `category` is a closed vocabulary, `estValue` is
  // a decimal string, `valuationAsOf` a date, `ownershipPct` a number and
  // `inTrust` a boolean: none is an identifier and none is touched.
  ['list_assets', [{ path: ['title'], kind: 'ASSET' }]],

  // Contact ids, designation enums and share percentages (see
  // clients/assets.client.ts — beneficiaries are ids, never names, and that is
  // the assets API's own shape). The `name` rule is DORMANT: it fires only if
  // BeneficiariesViewSchema is ever widened to carry one.
  ['get_asset_beneficiaries', [{ path: ['beneficiaries', 'name'], kind: 'PERSON' }]],

  // Same inventory shape from both document tools; `title` is user-supplied
  // plaintext by the M4 decision that accepts it as low-sensitivity label
  // metadata. Everything else on the row is an id, an enum, a version number,
  // a timestamp or a boolean.
  ['list_documents', [{ path: ['title'], kind: 'DOCUMENT' }]],
  ['search_documents', [{ path: ['title'], kind: 'DOCUMENT' }]],

  // DELIBERATELY EMPTY, and the most important empty in this file: `text` is
  // the document's own prose, already framed as untrusted data, and it is NOT
  // field-structured. See limit 1 in the module docstring. Adding `text` here
  // would be worse than leaving it — a placeholder over a whole will destroys
  // the answer without protecting anything.
  ['get_document_text', []],

  // State of residence, marital status and two counts of children. The tool
  // returns COUNTS rather than rows precisely so that no name can appear
  // (tools/profile.tools.ts); the DORMANT rule covers a future edit that
  // returns members instead.
  ['get_profile_facts', [{ path: ['members', 'name'], kind: 'PERSON' }]],

  // ---------------------------------------------------------------------
  // The deterministic analysers (M10 PR3).
  //
  // An analyser result is codes, severities, counts and money strings — with
  // ONE user-authored field: `subject.label`, the title of the asset or
  // document a finding is about. So every analyser gets the same rule, keyed on
  // the path the findings actually use, and the finding CODES travel untouched
  // because a code is the whole point of the design (the model explains a
  // token; it does not repeat a title).
  //
  // The kind differs per analyser because the subject differs: funding and
  // beneficiary findings are about assets, missing-document findings are about
  // documents. Estate-tax findings are estate-level and carry a null label, so
  // its rule is DORMANT in the same sense as the PERSON rules — declared so a
  // later per-asset tax finding cannot ship untokenized.
  // ---------------------------------------------------------------------
  ['analyze_funding', [{ path: ['findings', 'subject', 'label'], kind: 'ASSET' }]],
  ['analyze_beneficiary_conflicts', [{ path: ['findings', 'subject', 'label'], kind: 'ASSET' }]],
  ['analyze_missing_documents', [{ path: ['findings', 'subject', 'label'], kind: 'DOCUMENT' }]],
  ['estimate_estate_tax', [{ path: ['findings', 'subject', 'label'], kind: 'ASSET' }]],
]);

export class TokenizerCoverageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenizerCoverageError';
  }
}

/**
 * Refuse a tool set this module has not made a decision about, in EITHER
 * direction.
 *
 * A tool with no entry would silently ship whatever it returns to a provider
 * untokenized — the exact failure the field-based design trades a maintenance
 * burden to avoid. A stale entry for a tool that no longer exists is the same
 * drift seen from the other side, and it is worth failing on because it means
 * the rules were last reviewed against a different tool surface.
 *
 * Intended to run at boot next to `ToolRegistry` construction, so this is a
 * process that will not start rather than a request that quietly leaks.
 */
export function assertTokenizerCoversTools(toolNames: readonly string[]): void {
  const declared = new Set(TOOL_FIELD_RULES.keys());
  const missing = toolNames.filter((name) => !declared.has(name));
  if (missing.length > 0) {
    throw new TokenizerCoverageError(
      `tool(s) ${missing.join(', ')} have no tokenization decision: add a rule list ` +
        '(an empty one records "this result carries no user-authored identifier")',
    );
  }
  const present = new Set(toolNames);
  const stale = [...declared].filter((name) => !present.has(name));
  if (stale.length > 0) {
    throw new TokenizerCoverageError(
      `tokenization rules name tool(s) ${stale.join(', ')} that no longer exist: ` +
        'the rules were last reviewed against a different tool surface',
    );
  }
}

/** True for a string that is exactly one placeholder. */
export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_EXACT.test(value);
}

/** Escape a literal for inclusion in a regex alternation. */
function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Walk JSON the way `JSON.stringify` does — own enumerable keys, arrays
 * transparent — because `JSON.stringify` is literally what happens to this
 * value next (`ConversationService.quoteResult`). Matching its traversal means
 * there is no shape that ships but was not inspected.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function pathsEqual(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((segment, i) => segment === b[i]);
}

/**
 * Per-conversation substitution of user-authored identifiers.
 *
 * STATE IS PER-INSTANCE AND IN MEMORY ONLY. There is no module-level map, no
 * cache and no persistence: the mapping is the one artifact that could turn a
 * placeholder back into someone's data, so it lives exactly as long as the
 * request that built it and is never written to a row, a log or a metric. That
 * is also why nothing here exposes the values — `size` reports a count, which
 * is all any caller has a legitimate use for.
 *
 * The maps are `#private` FIELDS rather than TypeScript `private` ones, and the
 * difference is the whole point: `private` is erased at compile time, so the
 * maps stayed own enumerable properties and `Object.values(tokenizer)` handed
 * back every mapped title in plaintext — which a structured logger, an error
 * serializer or a debug dump reaches without anyone deciding to. `#` fields are
 * non-enumerable and genuinely unreachable from outside the class, so the
 * sentence above is enforced by the runtime instead of by the type checker.
 * (Caught by this module's own spec asserting a property it did not yet have.)
 *
 * STABILITY. Within one instance, a value always maps to the same placeholder,
 * so the model can carry "the same house" across every iteration of the turn
 * loop. Across separate HTTP requests the instance is rebuilt and the numbering
 * may differ; that is harmless because ALL of a single provider call's content
 * is mapped by the one instance, so the model never sees two numbering schemes
 * at once. Making the numbering stable across requests would mean persisting
 * the map, which is precisely what must not happen.
 */
export class Tokenizer {
  /** `${kind}\0${value}` → placeholder. Keyed by kind so two kinds never collide. */
  readonly #byValue = new Map<string, string>();

  /** placeholder → original value. The only path back, and it never leaves this object. */
  readonly #byPlaceholder = new Map<string, string>();

  /** Per-kind counters, so numbering reads as ASSET_1, ASSET_2, DOCUMENT_1. */
  readonly #counters = new Map<TokenKind, number>();

  /** How many distinct values are mapped. A count, deliberately never the values. */
  get size(): number {
    return this.#byPlaceholder.size;
  }

  /**
   * Replace the registered identifier fields of one tool result.
   *
   * Returns a NEW value; the input is not mutated, because the caller persists
   * the full untokenized result to `assistant_tool_calls` (encrypted) and the
   * transcript must record what was actually retrieved, not what was shipped.
   *
   * An unregistered tool name tokenizes NOTHING rather than throwing. The fence
   * against that is `assertTokenizerCoversTools` at boot: by the time a turn is
   * running, a throw here would take down a live conversation over a
   * configuration mistake that a boot check should already have caught.
   */
  tokenizeToolResult(toolName: string, data: unknown): unknown {
    const rules = TOOL_FIELD_RULES.get(toolName);
    if (rules === undefined || rules.length === 0) {
      return data;
    }
    return this.mapValue(data, rules, []);
  }

  /**
   * Replace ALREADY-MAPPED values where they appear in free text.
   *
   * This is what keeps prior turns consistent. The assistant's reply is stored
   * detokenized — it is the record the user reads back — so when that reply is
   * replayed as history on the next request, the real titles would otherwise
   * travel to the provider in prose having been carefully removed from the
   * structured results.
   *
   * This is NOT the prose detector the module docstring rejects. It never
   * guesses: it substitutes only exact occurrences of values a schema already
   * identified as user-authored this turn. The residual is that such a value
   * may coincide with an ordinary word, in which case a history message reads
   * slightly mangled — over-replacement, which fails toward privacy, and the
   * length floor keeps it rare.
   */
  tokenizeText(text: string): string {
    if (this.#byPlaceholder.size === 0) {
      return text;
    }
    // ONE pass over an alternation, longest value first, rather than a
    // replacement loop: a loop would rescan its own output, so a short mapped
    // value could match inside a placeholder a longer one had just produced and
    // corrupt it. Regex alternation is leftmost-first, so the ordering is also
    // what gives longest-match preference between overlapping values.
    const byLength = [...this.#byPlaceholder.entries()]
      .map(([placeholder, value]) => ({ placeholder, value }))
      .filter((entry) => entry.value.length >= MIN_TEXT_MATCH_LENGTH)
      .sort((a, b) => b.value.length - a.value.length);
    if (byLength.length === 0) {
      return text;
    }
    const lookup = new Map(byLength.map((entry) => [entry.value, entry.placeholder]));
    const pattern = new RegExp(byLength.map((entry) => escapeRegExp(entry.value)).join('|'), 'g');
    return text.replace(pattern, (match) => lookup.get(match) ?? match);
  }

  /**
   * Restore real values in text coming BACK from the model.
   *
   * Only exact placeholders this instance minted are resolved. A model that
   * invents ⟦ASSET_9⟧ for an index that was never issued — or echoes a
   * placeholder shape out of a document — leaves a harmless literal on screen,
   * never a value from somewhere else. There is no arithmetic on the index and
   * no nearest-match: an unknown placeholder has no answer, so it gets none.
   *
   * Single pass by construction (`replace` does not rescan what it inserted),
   * so a restored value that happens to contain placeholder-shaped text cannot
   * be resolved a second time.
   *
   * Resolving is safe by scope rather than by check: every value in this map
   * was put there from a tool result fetched on THIS caller's own bearer, so
   * the only thing detokenization can reveal to the user is the user's own
   * data — which is what they asked about.
   */
  detokenize(text: string): string {
    if (this.#byPlaceholder.size === 0) {
      return text;
    }
    return text.replace(PLACEHOLDER_GLOBAL, (match) => this.#byPlaceholder.get(match) ?? match);
  }

  /** Recursive walk. Arrays are transparent; only object keys advance the path. */
  private mapValue(value: unknown, rules: readonly FieldRule[], path: readonly string[]): unknown {
    if (Array.isArray(value)) {
      return value.map((element) => this.mapValue(element, rules, path));
    }
    if (!isRecord(value)) {
      return value;
    }
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      const childPath = [...path, key];
      const rule = rules.find((candidate) => pathsEqual(candidate.path, childPath));
      out[key] =
        rule !== undefined && typeof child === 'string'
          ? this.placeholderFor(rule.kind, child)
          : this.mapValue(child, rules, childPath);
    }
    return out;
  }

  /**
   * Mint or reuse the placeholder for one value.
   *
   * THE EGRESS INTERLOCK LIVES HERE (module docstring, final section). A value
   * that trips the egress detectors is returned UNCHANGED and is never mapped,
   * so `assertEgressClean` downstream still finds it and still refuses the
   * turn. Substituting it would remove the evidence and silently convert a
   * fail-closed control into a pass — the tokenizer must not be the thing that
   * handles an SSN, because then it becomes the thing that hides one.
   */
  private placeholderFor(kind: TokenKind, value: string): string {
    if (value.trim().length === 0) {
      // Nothing to protect, and minting a placeholder for an empty title would
      // burn an index and tell the model a name exists where none does.
      return value;
    }
    if (!inspectEgress(value).clean) {
      return value;
    }
    // The separator is an explicit NUL escape, not a literal control byte in
    // source: a title can contain a space or a pipe, so a printable separator
    // could be crafted to collide with another kind's entry.
    const key = `${kind}\u0000${value}`;
    const existing = this.#byValue.get(key);
    if (existing !== undefined) {
      return existing;
    }
    const index = (this.#counters.get(kind) ?? 0) + 1;
    this.#counters.set(kind, index);
    const placeholder = `${OPEN}${kind}_${index}${CLOSE}`;
    this.#byValue.set(key, placeholder);
    this.#byPlaceholder.set(placeholder, value);
    return placeholder;
  }
}
