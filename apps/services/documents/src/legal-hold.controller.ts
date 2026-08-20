import { BadRequestException, Body, Controller, HttpCode, Put, UseGuards } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { z } from 'zod';
import { DocumentsService } from './documents.service';

const SetLegalHoldSchema = z
  .object({
    ownerUserId: z.string().uuid(),
    hold: z.boolean(),
    /** The settlement case the hold derives from, for the audit trail. */
    caseId: z.string().uuid(),
  })
  .strict();

function parseBody<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}

/**
 * Internal legal-hold API (M7 PR2). Closes the M4 gap: `legal_hold` was
 * ENFORCED from day one (a held document cannot be deleted by anyone through
 * the API) but had no writer, because the decision log assigned the setting
 * surface to settlement (`docs/06-decision-log.md`, 2026-07-23).
 *
 * Service-credential guarded, not CallerGuard: a legal hold is imposed by the
 * platform on an estate under administration, and the decedent has no session
 * with which to authorize it. Idempotent, so settlement can re-drive it.
 */
@Controller('internal/v1/legal-hold')
@UseGuards(ServiceCredentialGuard)
export class LegalHoldController {
  constructor(private readonly documents: DocumentsService) {}

  @Put()
  @HttpCode(200)
  setHold(@Body() body: unknown): Promise<{ changed: number }> {
    const input = parseBody(SetLegalHoldSchema, body);
    return this.documents.setEstateLegalHold(input.ownerUserId, input.hold, input.caseId);
  }
}
