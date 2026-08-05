import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { missingScopes } from './consent';
import { ConsentsRepo } from './consents.repo';
import type {
  ExecutedToolCall,
  ToolExecutorPort,
  ToolInvocationRequest,
} from './conversation.service';
import type { Queryable } from './db';
import { EventsService, type PendingAudit } from './events.service';
import { FieldCipher, toolResultField } from './field-cipher';
import {
  scopeToken,
  ToolRegistry,
  type AssistantTool,
  type ToolContext,
  type ToolOutcome,
} from './tools';

/**
 * The one path from "the model asked for a tool" to "estate data exists in this
 * process". Everything a conversation is ever told about a user's estate comes
 * through here, so the ORDER OF THE STEPS BELOW IS THE CONTROL — not the
 * individual checks, which would each be satisfiable in the wrong sequence:
 *
 *   1. resolve the name        — a hallucinated tool is a refusal, not a crash
 *   2. CONSENT                 — before parsing, before executing, before anything
 *   3. validate the arguments  — after consent, so an invalid call to a tool the
 *                                user never consented to still reports as the
 *                                consent failure it primarily is
 *   4. execute                 — under the VERIFIED subject and the caller's bearer
 *   5. record the row          — with ciphertext only when there is a result
 *   6. audit                   — last, because a retrieval that could not be
 *                                recorded must not reach the prompt
 *
 * Steps 2 and 4 are the pair that matters. A consent gate that runs after
 * execution is not a gate: the peer read has already happened, the data is
 * already in this process, and the "denial" is a decision about whether to
 * admit it. So `permits` is consulted first and a denial RETURNS — the tool's
 * `execute` is never called, which the spec proves with a spy that would record
 * the call.
 *
 * The subject is never in question at any step. It comes from the ToolContext
 * the caller built out of CallerGuard's verified session; no tool declares a
 * subject parameter (tools/registry.ts refuses one at boot), and nothing here
 * reads a user id out of `rawInput`. A model reading an injected instruction
 * can choose WHICH TOOL to call and WHAT ARGUMENTS to pass; it can never choose
 * WHOSE estate answers (docs/03 §4 TB5, risk #6).
 */

/**
 * A model may invent a tool name, and that name is attacker-influencable text —
 * it can be composed from a sentence someone wrote into a PDF. It is therefore
 * never emitted: audit detail is IDs and enum tokens only (docs/02 §6), and the
 * one thing worth recording about a hallucinated call is that it happened. The
 * constant below is what reaches the append-only store instead of the name.
 *
 * The @estate/audit-emitter schema gate would reject most such strings anyway
 * (SAFE_TOKEN_PATTERN forbids whitespace), but a control that depends on the
 * payload happening to contain a space is not a control — and a rejected audit
 * event would surface as a thrown turn rather than a recorded refusal.
 */
const UNKNOWN_TOOL_TOKEN = 'unknown';

/**
 * There is no scope to report for a tool that does not exist. `none` is a
 * token, not an empty string, so the event says "no scope was involved" rather
 * than leaving a field that reads as missing data.
 */
const NO_SCOPE_TOKEN = 'none';

/**
 * The closed vocabulary of refusal reasons that may reach the audit stream.
 *
 * `ToolOutcome.reason` is typed `string`, and a tool is ordinary code that a
 * future edit could have return a downstream error message. Clamping at the
 * EGRESS rather than trusting every producer is the M4 lesson from scanner
 * signature names: the audit trail is append-only, so a leak into it cannot be
 * taken back, and the cheapest place to be certain is the last one.
 */
const AUDIT_REASON_TOKENS: ReadonlySet<string> = new Set([
  'unknown_tool',
  'invalid_input',
  'upstream_unavailable',
  'unsupported_content',
  'tool_error',
  // M10 PR3: the estate-tax analyser's reference-data gate. Named rather than
  // collapsed into the generic token because a control firing must not read as
  // an outage — an operator seeing this needs to get the tax table reviewed,
  // not to check whether a peer is up.
  'reference_unreviewed',
]);

/** Everything else collapses to a generic token rather than being emitted. */
function auditReason(reason: string): string {
  return AUDIT_REASON_TOKENS.has(reason) ? reason : 'error';
}

@Injectable()
export class ToolExecutor implements ToolExecutorPort {
  constructor(
    private readonly registry: ToolRegistry,
    private readonly consents: ConsentsRepo,
    private readonly cipher: FieldCipher,
    private readonly events: EventsService,
  ) {}

  /**
   * Run one tool call for one turn.
   *
   * `tx` IS THE TURN'S OWN TRANSACTION, handed down rather than opened here.
   * That is the reason this class holds no `Db`: a retrieval that happened must
   * not survive a turn that did not, so the `assistant_tool_calls` row commits
   * with the user's message and the assistant's reply or with neither. A row
   * written on a pooled connection would commit independently, leaving evidence
   * of a read inside a conversation that has no record of asking for it.
   *
   * `ctx` carries the VERIFIED session subject and that caller's own bearer;
   * `request.conversationId` is a conversation the caller has already been shown
   * to own (the turn service establishes that, under a row lock, before
   * composing anything). `request.name` and `request.input` are the only
   * model-supplied values, and neither can widen who is being read.
   *
   * Never throws for a bad tool call — an unknown name, invalid arguments, a
   * missing consent and a dead peer are all outcomes, because they are all
   * things the model must be told about and the transcript must record. It DOES
   * propagate a failure to persist or to audit: at that point the evidence
   * cannot be written, and a retrieval with no record of it is not one this
   * service is willing to have performed.
   */
  async execute(
    tx: Queryable,
    ctx: ToolContext,
    request: ToolInvocationRequest,
    pending: PendingAudit[],
  ): Promise<ExecutedToolCall> {
    // 1. Resolve. A model may hallucinate a name; that is a recorded refusal.
    // No `assistant_tool_calls` row is written, because no retrieval was
    // attempted and the row's NOT NULL `scope` would have to be invented — a
    // fabricated scope in the table that exists to evidence scopes is worse
    // than a conversation-anchored refusal event.
    const tool = this.registry.get(request.name);
    if (tool === null) {
      pending.push(() =>
        this.events.toolRefused(ctx.userId, request.conversationId, {
          tool: UNKNOWN_TOOL_TOKEN,
          scope: NO_SCOPE_TOKEN,
          reason: 'unknown_tool',
        }),
      );
      // The reported name is the CONSTANT, not what the model said: the turn
      // service quotes this back into the next prompt, and a hallucinated name
      // can be composed from a sentence an attacker wrote into a PDF. It is
      // withheld from the prompt for the same reason it is withheld from the
      // append-only audit store.
      return {
        toolName: UNKNOWN_TOOL_TOKEN,
        outcome: { outcome: 'error', reason: 'unknown_tool' },
      };
    }

    // 2. CONSENT, before anything else touches the tool. `missingScopes`
    // requires the master switch AND every scope this tool declares; a user who
    // has never answered and a user who has revoked produce the same empty set,
    // so the deny-by-default posture is structural rather than conventional.
    //
    // ALL of the tool's scopes, never any: an analyser reading two domains
    // discloses both, and a partial run would answer "no conflicts found" from
    // data the user never agreed to have looked at.
    const granted = await this.consents.grantedScopes(ctx.userId);
    const missing = missingScopes(granted, tool.scopes);
    if (missing.length > 0) {
      return await this.record(
        tx,
        ctx,
        request,
        tool,
        { outcome: 'denied_no_consent', missing },
        pending,
      );
    }

    // 3. Validate. The failure NEVER echoes the input: an argument may be
    // composed from untrusted document text, and an error message is a channel
    // out of this process just like any other (the house rule that a response
    // body is a token and nothing else).
    const parsed = tool.input.safeParse(request.input);
    if (!parsed.success) {
      return await this.record(
        tx,
        ctx,
        request,
        tool,
        { outcome: 'error', reason: 'invalid_input' },
        pending,
      );
    }

    // 4. Execute under the verified subject. A throwing tool is contained here:
    // one bad peer response must not take down a turn, and the failure is
    // reported as the generic token rather than as whatever the exception said.
    let outcome: ToolOutcome;
    try {
      outcome = await tool.execute(ctx, { ...parsed.data });
    } catch {
      outcome = { outcome: 'error', reason: 'tool_error' };
    }

    // 5 + 6.
    return await this.record(tx, ctx, request, tool, outcome, pending);
  }

  /**
   * Persist the append-only `assistant_tool_calls` row, then emit exactly one
   * audit event mirroring its outcome.
   *
   * A REFUSAL IS RECORDED AS LOUDLY AS A SUCCESS. The DDL carries
   * 'denied_no_consent' and 'error' in its outcome CHECK for exactly these
   * rows: a consent gate that fires and leaves no trace is indistinguishable
   * from a tool nobody called, which is the M9 rule that a control firing must
   * not read as an outage. The row is the evidence; the event is the alarm.
   *
   * The row id is generated BEFORE the ciphertext so the AAD can bind it
   * (`toolResultField`), which is what stops a database-tamper adversary
   * pairing one retrieval's bytes with another call's tool_name, scope or
   * outcome (docs/03 TB4, and the rationale in full on field-cipher.ts). Under
   * one DEK per user, that binding is the only thing holding the result to the
   * consent scope that admitted it.
   *
   * `message_id` is the USER TURN that triggered the retrieval, not the reply
   * it informs: tool calls happen while COMPOSING a turn, so the assistant
   * message does not exist yet, while the user's message was appended inside
   * this same transaction before the provider loop began. Recording it is what
   * makes "which question caused this read" answerable from the row alone; the
   * column stays nullable because a future caller may have no message to name.
   */
  private async record(
    tx: Queryable,
    ctx: ToolContext,
    request: ToolInvocationRequest,
    tool: AssistantTool,
    outcome: ToolOutcome,
    pending: PendingAudit[],
  ): Promise<ExecutedToolCall> {
    const toolCallId = randomUUID();

    // Ciphertext when and only when there is a result. The DDL enforces the
    // same thing twice over — result_ct and dek_id travel together, and a
    // non-'ok' outcome may carry neither — so a future edit that tried to store
    // retrieved content on a denial would be refused by the database, not by
    // this comment.
    let resultCt: Buffer | null = null;
    let dekId: string | null = null;
    if (outcome.outcome === 'ok') {
      const sealed = await this.cipher.encrypt(
        ctx.userId,
        toolResultField(toolCallId),
        // `?? null` so an undefined payload seals as the JSON literal `null`
        // rather than as an absent value: the pair CHECK wants a ciphertext
        // whenever the outcome is 'ok', and "the tool returned nothing" is
        // itself a fact the transcript should be able to state.
        JSON.stringify(outcome.data ?? null),
      );
      resultCt = sealed.ciphertext;
      dekId = sealed.dekId;
    }

    await tx.query(
      `INSERT INTO assistant_tool_calls
         (id, conversation_id, message_id, tool_name, scope, outcome, result_ct, dek_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        toolCallId,
        request.conversationId,
        request.messageId,
        tool.name,
        // The scope SET, as one sorted token (`scopeToken`). The column is a
        // single TEXT field and the audit detail below must match
        // SAFE_TOKEN_PATTERN, so this is the one encoding both accept — and
        // recording the whole set matters more than its shape: the row exists
        // to evidence which grants admitted this retrieval, and a row naming
        // one of two would understate the disclosure.
        scopeToken(tool.scopes),
        outcome.outcome,
        resultCt,
        dekId,
      ],
    );

    // The audit event mirrors the row's outcome, so the two can never disagree.
    // `tool` and `scope` are taken from the RESOLVED tool — compile-time
    // constants from this service's own registry — never from the name the
    // model supplied, even when the two happen to be equal.
    const scope = scopeToken(tool.scopes);
    if (outcome.outcome === 'ok') {
      pending.push(() =>
        this.events.toolInvoked(ctx.userId, request.conversationId, {
          tool: tool.name,
          scope,
          toolCallId,
        }),
      );
    } else {
      pending.push(() =>
        this.events.toolRefused(ctx.userId, request.conversationId, {
          tool: tool.name,
          scope,
          reason:
            outcome.outcome === 'denied_no_consent' ? 'no_consent' : auditReason(outcome.reason),
        }),
      );
    }

    // The reported name is the RESOLVED tool's own, a compile-time constant
    // from this service's registry — never the string the model supplied, even
    // when the two happen to be equal.
    return { toolName: tool.name, outcome };
  }
}
