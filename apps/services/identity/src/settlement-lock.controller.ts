import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  Inject,
  Param,
  Put,
  UseGuards,
} from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { z } from 'zod';
import { CLOCK, type Clock } from './di-tokens';
import { SettlementLockService } from './settlement-lock.service';

const UuidSchema = z.string().uuid();

const SetStateSchema = z
  .object({
    state: z.enum(['deceased_pending', 'settlement', 'active']),
    caseId: z.string().uuid(),
  })
  .strict();

function parse<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}

/**
 * Internal settlement-lock API (M7, docs/03 §5.1 control 4). Guarded by the
 * shared service credential, NOT a user session: these transitions run on
 * behalf of a settlement case, and the decedent's bearer token cannot exist
 * for them by construction. Identity still enforces its own transition table
 * (SettlementLockService) — the credential authenticates the calling service,
 * it does not authorize arbitrary status writes.
 */
@Controller('internal/v1/settlement-lock')
@UseGuards(ServiceCredentialGuard)
export class SettlementLockController {
  constructor(
    private readonly settlementLock: SettlementLockService,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  @Put(':userId')
  @HttpCode(200)
  async setState(
    @Param('userId') userId: string,
    @Body() body: unknown,
  ): Promise<{ status: string }> {
    const id = parse(UuidSchema, userId);
    const input = parse(SetStateSchema, body);
    return this.settlementLock.setState(id, input.state, input.caseId, this.clock());
  }

  @Get(':userId/liveness')
  @HttpCode(200)
  async liveness(
    @Param('userId') userId: string,
  ): Promise<{ status: string; lastStepUpAt: string | null }> {
    const id = parse(UuidSchema, userId);
    const result = await this.settlementLock.liveness(id);
    return {
      status: result.status,
      lastStepUpAt: result.lastStepUpAt?.toISOString() ?? null,
    };
  }
}
