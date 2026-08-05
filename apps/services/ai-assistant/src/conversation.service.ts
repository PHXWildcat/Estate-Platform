import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
// Value import, not `import type`: AssistantAuthz is constructor-injected, and
// a type-only import is erased, which leaves Nest's `design:paramtypes`
// metadata undefined for this parameter and the provider unresolvable at boot.
import { AssistantAuthz, conversationResource } from './authz.service';
import { missingScopes } from './consent';
import { ConsentsRepo } from './consents.repo';
import { ConversationsRepo } from './conversations.repo';
import { Db, isUniqueViolation, type Queryable } from './db';
import { LLM_GATEWAY } from './di-tokens';
import { EventsService, flushPendingAudit, type PendingAudit } from './events.service';
import { FieldCipher, messageField, toolResultField } from './field-cipher';
import {
  flattenForInspection,
  type LlmGateway,
  type LlmToolDeclaration,
  type LlmToolResult,
  type LlmTurn,
  type LlmTurnInput,
} from './llm-gateway';
import { MessagesRepo, type MessageRow } from './messages.repo';
import { ToolCallsRepo } from './tool-calls.repo';
import { assertEgressClean, EgressRefusedError } from './privacy/egress';
import { Tokenizer } from './privacy/tokenizer';
import { frameUntrusted, UNTRUSTED_DATA_INSTRUCTION } from './privacy/framing';
import {
  parameterTypeOf,
  ToolRegistry,
  type ToolContext,
  type ToolOutcome,
} from './tools/registry';

/**
 * Hard ceiling on provider round-trips within ONE turn.
 *
 * A tool-calling loop is unbounded by construction: the provider decides
 * whether to call another tool, and the provider's context contains untrusted
 * document text (docs/03 §4 TB5, risk #6). An injected "keep fetching" would
 * otherwise spend the user's money, hold a pooled database connection and hold
 * a row lock for as long as it could keep the model interested. Six is enough
 * for any real chain over this tool surface (inventory → search → read, twice)
 * and small enough that hitting it is a signal rather than a cost.
 *
 * Exceeding it ends the turn with a plain platform-authored message. It is
 * deliberately NOT an error: the user's turn and every retrieval it caused are
 * real events that must persist and stay auditable, and discarding them to
 * report a 500 would erase the evidence of exactly the behaviour worth looking
 * at.
 */
export const MAX_TOOL_ITERATIONS = 6;

/**
 * How much of a tool result is quoted into the prompt. The full result is
 * persisted (encrypted) on `assistant_tool_calls` regardless — this bounds what
 * LEAVES the platform, which matters because a document-content read can return
 * megabytes and an unbounded quote would put the whole of a scanned will into
 * every subsequent provider call of the turn.
 */
export const TOOL_RESULT_PROMPT_CHARS = 8000;

/** Marker appended when a quoted result was cut. Platform text, never content. */
const TRUNCATION_MARKER = '\n[truncated]';

/** Ends a turn that used up the iteration budget without producing an answer. */
export const ITERATION_CAP_MESSAGE =
  'I stopped after looking things up several times without reaching an answer. ' +
  'Please try asking a narrower question.';

/**
 * The standing system instruction. Platform-authored, constant, and the only
 * text in a prompt that is allowed to be an instruction at all — everything
 * retrieved is wrapped by `frameUntrusted` and disclaimed by the rule quoted in
 * here (docs/03 §4 TB5; CLAUDE.md's standing untrusted-input rule).
 */
export const SYSTEM_INSTRUCTION = [
  'You are an estate-planning assistant. You are speaking with one signed-in user',
  'about that user’s own estate records, and you can read those records only',
  'through the read-only tools declared to you. You cannot change anything, send',
  'anything, or reach anything outside this platform. If a tool returns no data,',
  'say so plainly — never fill the gap with an assumption about the estate. You',
  'give general information, not legal advice, and you say so when a question',
  'needs a lawyer.',
  '',
  UNTRUSTED_DATA_INSTRUCTION,
].join('\n');

/** Injection token for the tool executor (its class lives in `src/tools/`). */
export const TOOL_EXECUTOR = Symbol('TOOL_EXECUTOR');

/** One retrieval the provider asked for, with the authority to run it supplied separately. */
export interface ToolInvocationRequest {
  readonly conversationId: string;
  /** The user message that triggered it — `assistant_tool_calls.message_id`. */
  readonly messageId: string;
  /** The tool name the MODEL produced. Unknown names are a refusal, not a crash. */
  readonly name: string;
  /** The model's raw arguments, validated by the executor against the tool's schema. */
  readonly input: unknown;
}

/** What the executor reports back: enough to record and to tell the model. */
export interface ExecutedToolCall {
  readonly toolName: string;
  readonly outcome: ToolOutcome;
}

/**
 * The port this service drives. The executor owns the consent decision, the
 * `assistant_tool_calls` write and the `assistant.tool.invoked` /
 * `assistant.tool.refused` audit events — this service owns the transaction it
 * runs in, which is why `tx` is a parameter rather than something the executor
 * opens for itself: a retrieval that happened must not survive a turn that did
 * not.
 */
export interface ToolExecutorPort {
  execute(
    tx: Queryable,
    ctx: ToolContext,
    request: ToolInvocationRequest,
    /** Audit emissions the executor DEFERS until the turn commits. */
    pending: PendingAudit[],
  ): Promise<ExecutedToolCall>;
}

export interface ConversationDto {
  conversationId: string;
  createdAt: string;
  updatedAt: string;
}

export interface TranscriptMessageDto {
  messageId: string;
  seq: number;
  role: 'user' | 'assistant';
  text: string;
  createdAt: string;
}

export interface TranscriptDto {
  conversationId: string;
  messages: TranscriptMessageDto[];
}

export interface TurnDto {
  conversationId: string;
  messageId: string;
  text: string;
  toolCalls: number;
}

/**
 * The conversation spine: storage, the provider loop, and the boundary every
 * piece of estate content crosses on its way to a model.
 *
 * THE SUBJECT IS ALWAYS `userId`, and `userId` always came from CallerGuard's
 * verified session. It is threaded into the Cedar PRINCIPAL of every
 * single-conversation decision, into the ownership predicate of the list query,
 * into the DEK subject of every encryption, into the audit actor of every event
 * and into the `ToolContext` every tool runs under. No method here accepts a
 * subject from a request body or from model output, which is the structural
 * half of the answer to prompt injection; the framing in `privacy/framing.ts`
 * is only the advisory half.
 *
 * ACCESS TO ONE CONVERSATION IS A POLICY DECISION, NOT A QUERY PREDICATE. The
 * three single-conversation paths — `transcript`, `remove`, `takeTurn` — read
 * the row by id and then ask `AssistantAuthz` (assistant.cedar). The row they
 * read is genuinely capable of belonging to someone else, which is what makes
 * the call a control rather than a formality, and it is the reason the
 * owner-scoped single-row readers this service used to carry were removed
 * rather than kept alongside: a resolver that cannot return a stranger's row
 * turns the decision that follows it into decoration.
 *
 * ONE TRANSACTION PER TURN. The user's message, every tool call it triggered
 * and the assistant's reply land together or not at all — a transcript that
 * records half an exchange is an account of something that never happened, and
 * this transcript is the only evidence of what the assistant was asked and what
 * it read. The accepted cost is that a pooled connection and a row lock are
 * held across the provider call; PR2's live adapter brings the request deadline
 * that bounds it, and the iteration cap above bounds the number of them.
 */
@Injectable()
export class ConversationService {
  constructor(
    private readonly db: Db,
    private readonly conversations: ConversationsRepo,
    private readonly messages: MessagesRepo,
    private readonly toolCalls: ToolCallsRepo,
    private readonly cipher: FieldCipher,
    private readonly authz: AssistantAuthz,
    private readonly consents: ConsentsRepo,
    private readonly events: EventsService,
    private readonly registry: ToolRegistry,
    @Inject(LLM_GATEWAY) private readonly gateway: LlmGateway,
    @Inject(TOOL_EXECUTOR) private readonly executor: ToolExecutorPort,
  ) {}

  async create(userId: string): Promise<ConversationDto> {
    const row = await this.conversations.create(this.db, randomUUID(), userId);
    await this.events.conversationStarted(userId, row.id);
    return toConversationDto(row);
  }

  async list(userId: string): Promise<ConversationDto[]> {
    const rows = await this.conversations.listLiveByUser(this.db, userId);
    return rows.map(toConversationDto);
  }

  /**
   * A user reading their own history back. Decrypts under the
   * `assistant_transcript_read` purpose so an auditor can tell human reads
   * apart from the service's own `assistant_history_read` bursts without seeing
   * any plaintext (the distinction is set out in `field-cipher.ts`).
   */
  async transcript(userId: string, conversationId: string): Promise<TranscriptDto> {
    // THE TWO REFUSALS BELOW ARE DELIBERATELY THE SAME REFUSAL: a conversation
    // that does not exist and a conversation that belongs to somebody else
    // answer identically. The null row raises the uniform not-found; a Cedar
    // denial raises the SAME exception with the same body from
    // `AssistantAuthz.assertCan`. Answering 403 for the second case
    // would confirm that the id names a real conversation, which turns an
    // id-guessing loop into an oracle for "does this person use the assistant,
    // and how many conversations do they have" — a question about someone's
    // estate planning that the platform must never answer to a stranger
    // (docs/03's no-enumeration-oracle rule; documents and settlement collapse
    // the same distinction).
    const conversation = await this.conversations.getLiveById(this.db, conversationId);
    if (!conversation) {
      throw notFound();
    }
    this.authz.assertCan(
      userId,
      'read',
      conversationResource(conversation.id, conversation.user_id),
    );
    const rows = await this.messages.listByConversation(this.db, conversationId);
    const messages: TranscriptMessageDto[] = [];
    for (const row of rows) {
      messages.push({
        messageId: row.id,
        seq: row.seq,
        role: row.role,
        text: await this.openMessage(userId, row, 'assistant_transcript_read'),
        createdAt: row.created_at.toISOString(),
      });
    }
    return { conversationId, messages };
  }

  async remove(userId: string, conversationId: string): Promise<void> {
    const deleted = await this.db.withTransaction(userId, async (tx) => {
      const conversation = await this.conversations.getLiveById(tx, conversationId);
      if (!conversation) {
        throw notFound();
      }
      this.authz.assertCan(
        userId,
        'delete',
        conversationResource(conversation.id, conversation.user_id),
      );
      // The write keeps its own owner predicate (see ConversationsRepo). It is
      // no longer the access decision, so a false here means a concurrent
      // delete committed between this read and this update — a lost race, which
      // reports as the same not-found.
      return this.conversations.softDelete(tx, conversationId, userId);
    });
    if (!deleted) {
      throw notFound();
    }
    // Emitted after the commit: an audit event asserting a deletion that rolled
    // back would be a false record in an append-only store (the M9 rule that
    // the irreversible step goes last, applied to evidence).
    await this.events.conversationDeleted(userId, conversationId);
  }

  /**
   * One turn: append the user's message, let the provider drive the read-only
   * tool loop, append the answer.
   */
  async takeTurn(
    userId: string,
    bearer: string,
    conversationId: string,
    text: string,
  ): Promise<TurnDto> {
    const ctx: ToolContext = { userId, bearer };
    const declarations = this.declarations();

    // Audit for this turn is BUFFERED and emitted after the commit. Kafka does
    // not enrol in the transaction, so an event sent from inside one that later
    // rolls back is a permanent record of a row that never existed — and the
    // egress-refusal path below rolls back by design. `remove()` states the same
    // rule; a turn is the same shape. `assistant.egress.refused` is deliberately
    // NOT buffered: it references no row created here and is true whatever
    // happens to the transaction, so buffering it would silence the control at
    // the exact moment it fires.
    const pending: PendingAudit[] = [];
    const result = await this.db.withTransaction(userId, async (tx) => {
      // Liveness from the row, authority from the policy, and the row lock held
      // for the rest of the turn. Both refusals are the uniform not-found (see
      // `transcript` for why they must be indistinguishable).
      const conversation = await this.conversations.lockLiveById(tx, conversationId);
      if (!conversation) {
        throw notFound();
      }
      this.authz.assertCan(
        userId,
        'converse',
        conversationResource(conversation.id, conversation.user_id),
      );

      /*
       * THE MASTER SWITCH GATES THE TURN ITSELF (M10 security review).
       *
       * Until this check existed the only consent read on the whole path was
       * per-tool, inside the executor — so a user with no consent row, or one
       * who had just switched the assistant OFF, could still drive a provider
       * call: the tools all denied, but the system prompt, this turn's text and
       * the whole prior transcript still crossed TB5. Three places already
       * claimed otherwise (consents.controller.ts, analysis.controller.ts's
       * "a feature that keeps computing after being switched off is not off",
       * and the consent UI's "nothing about your estate is analysed"), and the
       * transcript replay made it more than theoretical: a turn after
       * revocation re-sends estate prose retrieved while consent was live.
       *
       * It sits AFTER the ownership check so a stranger's conversation id still
       * answers the uniform 404 rather than revealing whether that user has the
       * assistant enabled — consent state must not become an oracle about
       * someone else's account.
       */
      const granted = await this.consents.grantedScopes(userId);
      if (missingScopes(granted, []).length > 0) {
        throw new ForbiddenException({ error: 'assistant_disabled' });
      }

      const priorRows = await this.messages.listByConversation(tx, conversationId);
      const history: LlmTurn[] = [];
      for (const row of priorRows) {
        history.push({
          role: row.role,
          text: await this.openMessage(userId, row, 'assistant_history_read'),
        });
      }

      const last = priorRows.at(-1);
      const userSeq = last === undefined ? 0 : last.seq + 1;
      const userMessageId = randomUUID();
      await this.append(tx, userId, conversationId, userMessageId, userSeq, 'user', text);
      pending.push(() => this.events.messageSent(userId, conversationId, userMessageId));
      history.push({ role: 'user', text });

      /*
       * ONE tokenizer per turn, held on the stack and never persisted or
       * cached. Placeholders are stable WITHIN a turn so the model can reason
       * about "the same house" across iterations, and meaningless outside it.
       *
       * The stored transcript keeps REAL text: a user reading their own history
       * must see their own estate, not our placeholders. Tokenization is a
       * property of the provider hop, not of the record.
       *
       * SEEDED FROM PRIOR RETRIEVALS BEFORE THE FIRST PROVIDER CALL (M10
       * security review). The map used to be filled only by this turn's own
       * tool results, which arrive AFTER the first `complete()` — so the
       * history pass below ran against an empty map every time, and the whole
       * prior transcript went to the provider verbatim. Since replies are
       * stored detokenized by design, those were real titles: turn 1 protected
       * "Mom's house on Elm St" inside a structured result, and turn 2 shipped
       * it in prose. Re-deriving the map from the conversation's own recorded
       * retrievals closes that and makes the documented property true — a title
       * tokenized in turn 1 keeps its placeholder in turn 5.
       */
      const tokenizer = new Tokenizer();
      await this.seedTokenizer(tx, userId, conversationId, tokenizer);

      const toolResults: LlmToolResult[] = [];
      let answer: string | null = null;
      for (let iteration = 0; iteration < MAX_TOOL_ITERATIONS; iteration += 1) {
        const input: LlmTurnInput = {
          system: SYSTEM_INSTRUCTION,
          // Prior turns are stored as real text and tokenized on the way OUT,
          // so a title the user typed in turn 1 carries the same placeholder in
          // turn 5.
          history: history.map((turn) => ({ ...turn, text: tokenizer.tokenizeText(turn.text) })),
          tools: declarations,
          toolResults,
        };
        // The gate runs on the TOKENIZED payload — exactly the bytes that will
        // be sent — and before EVERY provider call, not once per turn: each
        // iteration carries one more tool result, and a retrieved SSN enters
        // the payload at the iteration that fetched it.
        //
        // Tokenizing first is safe because the tokenizer refuses to replace a
        // value that fails the egress check, returning it unchanged for this
        // gate to catch. Without that interlock the privacy layer would disarm
        // the fail-closed control by hiding an SSN inside a placeholder.
        await this.assertOutboundClean(userId, conversationId, input);

        const output = await this.gateway.complete(input);
        if (output.kind === 'message') {
          answer = output.text;
          break;
        }
        const executed = await this.executor.execute(
          tx,
          ctx,
          {
            conversationId,
            messageId: userMessageId,
            name: output.name,
            input: output.input,
          },
          pending,
        );
        toolResults.push(this.quoteResult(executed, tokenizer));
      }

      // Detokenize before the reply is persisted OR returned: placeholders are
      // an artefact of the provider hop and must not reach the user or the
      // transcript. An invented placeholder the tokenizer never minted is left
      // as a harmless literal rather than resolved to someone's data.
      const replyText = answer === null ? ITERATION_CAP_MESSAGE : tokenizer.detokenize(answer);
      const replyId = randomUUID();
      await this.append(tx, userId, conversationId, replyId, userSeq + 1, 'assistant', replyText);
      await this.conversations.touch(tx, conversationId);
      pending.push(() =>
        this.events.turnCompleted(userId, conversationId, replyId, {
          toolCalls: toolResults.length,
          gateway: this.gateway.name,
        }),
      );

      return {
        conversationId,
        messageId: replyId,
        text: replyText,
        toolCalls: toolResults.length,
      };
    });

    // The rows are durable; only now may the stream assert they exist.
    await flushPendingAudit(pending);
    return result;
  }

  /** Seal one turn under the owner's DEK and append it (append-only table). */
  private async append(
    tx: Queryable,
    userId: string,
    conversationId: string,
    messageId: string,
    seq: number,
    role: 'user' | 'assistant',
    text: string,
  ): Promise<void> {
    // The AAD binds this message id, so the id must exist before the sealing.
    const sealed = await this.cipher.encrypt(userId, messageField(messageId), text);
    if (sealed.ciphertext === null) {
      // Unreachable: `text` is non-empty by schema. Guards the NOT NULL column
      // rather than letting a null reach Postgres as a constraint violation.
      throw new InternalServerErrorException({ error: 'internal_error' });
    }
    try {
      await this.messages.insert(tx, {
        id: messageId,
        conversationId,
        seq,
        role,
        contentCt: sealed.ciphertext,
        dekId: sealed.dekId,
      });
    } catch (err) {
      if (isUniqueViolation(err)) {
        // Another turn committed this seq first. Backstop behind the row lock;
        // the honest answer is "retry", never a silently renumbered turn.
        throw new ConflictException({ error: 'conversation_busy' });
      }
      throw err;
    }
  }

  /** Decrypt one stored turn (audited by FieldCrypto under `purpose`). */
  private async openMessage(userId: string, row: MessageRow, purpose: string): Promise<string> {
    const text = await this.cipher.decrypt({
      ownerUserId: userId,
      dekId: row.dek_id,
      field: messageField(row.id),
      ciphertext: row.content_ct,
      actorId: userId,
      purpose,
    });
    if (text === null) {
      // content_ct is NOT NULL, so null here means the row is unreadable. Fail
      // rather than substitute an empty turn: a transcript with a silently
      // blank message misrepresents what was said, and a prompt built from one
      // asks the model to reason about a conversation that did not happen.
      throw new InternalServerErrorException({ error: 'internal_error' });
    }
    return text;
  }

  /**
   * Run the egress assertion over the COMPLETE outbound payload and refuse the
   * turn if it trips (docs/03 §4 TB5). The refusal is audited before it is
   * raised — a control that fires silently is indistinguishable from one that
   * never fired (the M9 rule) — and the audit carries the detector CATEGORY
   * only, never the matched value, or the control would become its own leak.
   *
   * Throwing rolls the transaction back, so the user's message does not persist
   * either. That is the intended reading: this turn did not happen.
   */
  private async assertOutboundClean(
    userId: string,
    conversationId: string,
    input: LlmTurnInput,
  ): Promise<void> {
    try {
      assertEgressClean(flattenForInspection(input));
    } catch (err) {
      if (err instanceof EgressRefusedError) {
        await this.events.egressRefused(userId, conversationId, { detector: err.detector });
        throw new UnprocessableEntityException({ error: 'egress_refused' });
      }
      throw err;
    }
  }

  /**
   * Render one tool outcome for the model.
   *
   * A successful result is retrieved estate content — user-authored titles,
   * document text, OCR output — so it is FRAMED as untrusted data before it
   * touches the prompt, and truncated first so that framing (which neutralizes
   * delimiter escapes) still applies to every byte that ships.
   *
   * A refusal or an error carries no content by construction (the
   * `assistant_tool_calls` CHECK says the same thing in SQL), and its message
   * is platform-authored: the `error` outcome's `reason` is deliberately NOT
   * quoted, because a downstream failure string is the kind of value that ends
   * up carrying a hostname, a path, or a fragment of someone's data into a
   * provider payload.
   */
  private quoteResult(executed: ExecutedToolCall, tokenizer: Tokenizer): LlmToolResult {
    const { toolName, outcome } = executed;
    if (outcome.outcome === 'denied_no_consent') {
      // The scope names ARE quoted, unlike the `error` reason below, and the
      // difference is where the string comes from: these are compile-time
      // constants from the closed CONSENT_SCOPES vocabulary, so there is no
      // path by which retrieved content or a provider response reaches this
      // sentence. Naming them makes the refusal actionable — the assistant can
      // tell the user which switch to turn on.
      return {
        tool: toolName,
        outcome: 'denied_no_consent',
        text:
          'Not run: the user has not granted every consent scope this tool requires. ' +
          `Missing: ${outcome.missing.join(', ')}.`,
      };
    }
    if (outcome.outcome === 'error') {
      return { tool: toolName, outcome: 'error', text: 'This lookup did not return data.' };
    }
    // Tokenize BEFORE serializing: the rules address fields of the structured
    // result, and JSON.stringify is exactly what happens to it next.
    const tokenized = tokenizer.tokenizeToolResult(toolName, outcome.data);
    const serialized = JSON.stringify(tokenized) ?? 'null';
    const clipped =
      serialized.length > TOOL_RESULT_PROMPT_CHARS
        ? serialized.slice(0, TOOL_RESULT_PROMPT_CHARS) + TRUNCATION_MARKER
        : serialized;
    return {
      tool: toolName,
      outcome: 'ok',
      text: frameUntrusted({ kind: 'tool_result', ref: toolName }, clipped),
    };
  }

  /**
   * Re-derive this conversation's placeholder map from the retrievals it has
   * already recorded (M10 security review).
   *
   * The values are read from `assistant_tool_calls`, decrypted under the same
   * per-user DEK and AAD that sealed them, and pushed back through the ordinary
   * `tokenizeToolResult` path — the SAME rules, so a field that is tokenized
   * when it is fetched is tokenized when it is replayed, with no second copy of
   * the rule table to drift.
   *
   * Nothing is returned and nothing is stored: the map lives on the turn's
   * stack exactly as before. What changes is only that it is no longer empty
   * when the first provider call renders the history.
   *
   * A ROW THAT WILL NOT OPEN IS SKIPPED, not fatal. A tool result whose DEK was
   * crypto-shredded, or whose ciphertext a TB4 adversary moved between rows, is
   * evidence of something worth an operator's attention — but the honest
   * consequence for THIS turn is a placeholder that cannot be re-derived, and
   * refusing the turn outright would let a single unreadable historical row
   * lock a user out of their own conversation for good. The decrypt failure is
   * still recorded by `FieldCrypto`'s own audit path.
   */
  private async seedTokenizer(
    tx: Queryable,
    userId: string,
    conversationId: string,
    tokenizer: Tokenizer,
  ): Promise<void> {
    const rows = await this.toolCalls.listResultsByConversation(tx, conversationId);
    for (const row of rows) {
      let plaintext: string | null;
      try {
        plaintext = await this.cipher.decrypt({
          ownerUserId: userId,
          dekId: row.dek_id,
          field: toolResultField(row.id),
          ciphertext: row.result_ct,
          actorId: userId,
          purpose: 'assistant_tokenizer_reseed',
        });
      } catch {
        continue;
      }
      if (plaintext === null) {
        continue;
      }
      let data: unknown;
      try {
        data = JSON.parse(plaintext);
      } catch {
        continue;
      }
      // The return value is discarded on purpose: the point is the SIDE EFFECT
      // on the tokenizer's map, not a tokenized copy of an old result.
      tokenizer.tokenizeToolResult(row.tool_name, data);
    }
  }

  /**
   * Flatten the registry into provider-facing declarations. Derived from the
   * zod schemas rather than hand-written, so a tool cannot describe itself to a
   * model differently from the way it validates — and so `assertSubjectFree`,
   * which inspects those same schemas at boot, governs what can appear here.
   */
  private declarations(): LlmToolDeclaration[] {
    return this.registry.list().map((tool) => ({
      name: tool.name,
      description: tool.description,
      parameters: Object.entries(tool.input.shape).map(([name, schema]) => ({
        name,
        description: schema.description ?? '',
        required: !schema.isOptional(),
        type: parameterTypeOf(name, schema),
      })),
    }));
  }
}

/**
 * The uniform not-found. Someone else's conversation, a deleted one and one
 * that never existed all end here: any distinction would confirm that a
 * conversation id belongs to a real user (docs/03's no-enumeration-oracle
 * rule, the same shape as documents' and settlement's 404s).
 */
function notFound(): NotFoundException {
  return new NotFoundException({ error: 'not_found' });
}

function toConversationDto(row: {
  id: string;
  created_at: Date;
  updated_at: Date;
}): ConversationDto {
  return {
    conversationId: row.id,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}
