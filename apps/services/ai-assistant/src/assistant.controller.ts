import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { CallerGuard, requireCaller, type CallerRequest } from '@estate/auth-guard';
import {
  ConversationService,
  type ConversationDto,
  type TranscriptDto,
  type TurnDto,
} from './conversation.service';
import { bearerTokenOf } from './bearer';
import { CreateConversationSchema, parseBody, TurnSchema, UuidSchema } from './schemas';

/**
 * The assistant's conversation surface. Every route is owner-scoped to the
 * VERIFIED session subject — `requireCaller(req).userId`, never a path
 * parameter, never a body field, never a value the model produced. A
 * conversation id in the path selects WHICH conversation; the service's
 * ownership predicate decides whether it is the caller's, and answers a uniform
 * 404 when it is not.
 *
 * STEP-UP PLACEMENT (docs/01 §5). Nothing here is gated, deliberately. §5's
 * list covers vault open, document generation, data export, fiduciary changes,
 * deletion requests and emergency-access configuration; talking to the
 * assistant about your own estate is none of those, and a step-up on every
 * conversational turn would be a prompt users learn to clear reflexively —
 * which devalues it at the routes where it is the actual control. The gate that
 * governs what this surface may READ sits on the consent grant instead
 * (`consents.controller.ts`), which is where the widening actually happens.
 * Conversation DELETE is a soft delete of the caller's own transcript with no
 * effect on any estate record, so it is not the "deletion request" §5 means.
 */
@Controller('v1/conversations')
@UseGuards(CallerGuard)
export class AssistantController {
  constructor(private readonly conversations: ConversationService) {}

  /**
   * Open a conversation. The body must be empty — see CreateConversationSchema:
   * there is no title column to fill, and a smuggled field is refused rather
   * than dropped.
   */
  @Post()
  @HttpCode(201)
  create(@Req() req: CallerRequest, @Body() body: unknown): Promise<ConversationDto> {
    parseBody(CreateConversationSchema, body ?? {});
    return this.conversations.create(requireCaller(req).userId);
  }

  @Get()
  @HttpCode(200)
  list(@Req() req: CallerRequest): Promise<ConversationDto[]> {
    return this.conversations.list(requireCaller(req).userId);
  }

  /** The decrypted transcript. Every message opened here is an audited decrypt. */
  @Get(':conversationId')
  @HttpCode(200)
  transcript(
    @Req() req: CallerRequest,
    @Param('conversationId') conversationId: string,
  ): Promise<TranscriptDto> {
    return this.conversations.transcript(
      requireCaller(req).userId,
      parseBody(UuidSchema, conversationId),
    );
  }

  /**
   * Soft delete (CLAUDE.md: no hard deletes anywhere). The ciphertext survives;
   * erasure is crypto-shredding the user's assistant DEK, a separate act.
   */
  @Delete(':conversationId')
  @HttpCode(204)
  remove(
    @Req() req: CallerRequest,
    @Param('conversationId') conversationId: string,
  ): Promise<void> {
    return this.conversations.remove(
      requireCaller(req).userId,
      parseBody(UuidSchema, conversationId),
    );
  }

  /**
   * Take one turn. The three arguments that matter arrive from three different
   * places on purpose: the SUBJECT from the verified session, the AUTHORITY
   * from the caller's own forwarded bearer, and only the TEXT from the request
   * body — which `TurnSchema.strict()` refuses to let carry anything else.
   */
  @Post(':conversationId/turns')
  @HttpCode(200)
  takeTurn(
    @Req() req: CallerRequest,
    @Param('conversationId') conversationId: string,
    @Body() body: unknown,
  ): Promise<TurnDto> {
    const caller = requireCaller(req);
    const input = parseBody(TurnSchema, body);
    return this.conversations.takeTurn(
      caller.userId,
      bearerTokenOf(req),
      parseBody(UuidSchema, conversationId),
      input.text,
    );
  }
}
