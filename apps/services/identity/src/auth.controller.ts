import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { MfaLevel } from '@estate/contracts';
import { z } from 'zod';
import { AuthService, type IssuedTokens, type StepUpResult } from './auth.service';
import { SessionGuard, type AuthedRequest, type SessionContext } from './session.guard';
import { StepUpGuard } from './stepup.guard';

const RegisterSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(12).max(256),
});

// Login deliberately validates only shape, not email format: a malformed
// identifier must take the same code path (and produce the same generic 401)
// as a well-formed unknown one.
const LoginSchema = z.object({
  email: z.string().min(1).max(320),
  password: z.string().min(1).max(1024),
});

const RefreshSchema = z.object({
  refreshToken: z.string().min(1).max(1024),
});

const CodeSchema = z.object({
  code: z.string().regex(/^\d{6}$/),
});

function parseBody<T extends z.ZodTypeAny>(schema: T, body: unknown): z.infer<T> {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    // Field names only — never echo submitted values.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}

function requireAuth(request: AuthedRequest): SessionContext {
  const auth = request.auth;
  if (!auth) {
    // Unreachable behind SessionGuard; guards against wiring mistakes.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return auth;
}

@Controller('v1/auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  @HttpCode(201)
  async register(@Body() body: unknown): Promise<{ status: string }> {
    const { email, password } = parseBody(RegisterSchema, body);
    await this.auth.register(email, password);
    // Identical response whether or not the email already had an account.
    return { status: 'ok' };
  }

  @Post('login')
  @HttpCode(200)
  async login(@Body() body: unknown): Promise<IssuedTokens> {
    const { email, password } = parseBody(LoginSchema, body);
    return this.auth.login(email, password);
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(@Body() body: unknown): Promise<IssuedTokens> {
    const { refreshToken } = parseBody(RefreshSchema, body);
    return this.auth.refresh(refreshToken);
  }

  /** Session introspection for the BFF: context of the presented token only. */
  @Get('session')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  session(@Req() request: AuthedRequest): {
    userId: string;
    sessionId: string;
    mfaLevel: MfaLevel;
    stepupExpiresAt: string | null;
  } {
    const auth = requireAuth(request);
    return {
      userId: auth.userId,
      sessionId: auth.sessionId,
      mfaLevel: auth.mfaLevel,
      stepupExpiresAt: auth.stepupExpiresAt?.toISOString() ?? null,
    };
  }

  @Post('totp/enroll')
  @HttpCode(201)
  @UseGuards(SessionGuard)
  async enrollTotp(
    @Req() request: AuthedRequest,
  ): Promise<{ methodId: string; otpauthUri: string }> {
    const auth = requireAuth(request);
    return this.auth.enrollTotp(auth.userId, auth.sessionId);
  }

  @Post('totp/verify')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async verifyTotp(
    @Req() request: AuthedRequest,
    @Body() body: unknown,
  ): Promise<{ verified: boolean }> {
    const auth = requireAuth(request);
    const { code } = parseBody(CodeSchema, body);
    await this.auth.verifyTotp(auth.userId, auth.sessionId, code);
    return { verified: true };
  }

  @Post('stepup')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async stepUp(@Req() request: AuthedRequest, @Body() body: unknown): Promise<StepUpResult> {
    const auth = requireAuth(request);
    const { code } = parseBody(CodeSchema, body);
    return this.auth.stepUp(auth.userId, auth.sessionId, code);
  }

  /**
   * Demo endpoint proving the step-up window end to end: reachable only with
   * a live session AND a fresh (≤5 min) step-up. Stands in for data export,
   * which is on the docs/01 §5 step-up-mandatory list.
   */
  @Post('export-demo')
  @HttpCode(204)
  @UseGuards(SessionGuard, StepUpGuard)
  exportDemo(): void {
    // 204 No Content — the guards are the feature.
  }
}
