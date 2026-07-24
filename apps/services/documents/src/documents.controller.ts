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
import { CallerGuard, requireCaller, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import {
  DocumentsService,
  type ContentDto,
  type DocumentDto,
  type GenerateResult,
  type VersionDto,
} from './documents.service';
import {
  GenerateDocumentSchema,
  IfMatchSchema,
  NewVersionSchema,
  parse,
  StatusTransitionSchema,
  UuidSchema,
  VersionParamSchema,
} from './schemas';

/** Optional If-Match version token from the request headers. */
function ifMatchOf(req: CallerRequest): number | undefined {
  const raw = req.headers['if-match'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return parse(IfMatchSchema, value);
}

/**
 * Document commands + queries (owner-only in M4).
 *
 * GENERATION IS STEP-UP GATED (docs/01 §5: document generation is a
 * mandatory step-up action) — StepUpGuard checks the VERIFIED session's
 * step-up freshness, on both initial generation and regeneration. Deletion
 * requests are equally step-up gated.
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class DocumentsController {
  constructor(private readonly documents: DocumentsService) {}

  @Post('documents/generate')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  generate(@Req() req: CallerRequest, @Body() body: unknown): Promise<GenerateResult> {
    return this.documents.generate(requireCaller(req).userId, parse(GenerateDocumentSchema, body));
  }

  @Get('documents')
  @HttpCode(200)
  list(@Req() req: CallerRequest): Promise<DocumentDto[]> {
    return this.documents.list(requireCaller(req).userId);
  }

  @Get('documents/:documentId')
  @HttpCode(200)
  get(@Req() req: CallerRequest, @Param('documentId') documentId: string): Promise<DocumentDto> {
    return this.documents.get(requireCaller(req).userId, parse(UuidSchema, documentId));
  }

  @Get('documents/:documentId/versions')
  @HttpCode(200)
  versions(
    @Req() req: CallerRequest,
    @Param('documentId') documentId: string,
  ): Promise<VersionDto[]> {
    return this.documents.listVersions(requireCaller(req).userId, parse(UuidSchema, documentId));
  }

  @Get('documents/:documentId/versions/:version/content')
  @HttpCode(200)
  content(
    @Req() req: CallerRequest,
    @Param('documentId') documentId: string,
    @Param('version') version: string,
  ): Promise<ContentDto> {
    return this.documents.getContent(
      requireCaller(req).userId,
      parse(UuidSchema, documentId),
      parse(VersionParamSchema, version),
    );
  }

  @Post('documents/:documentId/versions')
  @UseGuards(StepUpGuard)
  @HttpCode(201)
  newVersion(
    @Req() req: CallerRequest,
    @Param('documentId') documentId: string,
    @Body() body: unknown,
  ): Promise<GenerateResult> {
    return this.documents.newVersion(
      requireCaller(req).userId,
      parse(UuidSchema, documentId),
      parse(NewVersionSchema, body),
      ifMatchOf(req),
    );
  }

  @Post('documents/:documentId/status')
  @HttpCode(200)
  transition(
    @Req() req: CallerRequest,
    @Param('documentId') documentId: string,
    @Body() body: unknown,
  ): Promise<DocumentDto> {
    return this.documents.transitionStatus(
      requireCaller(req).userId,
      parse(UuidSchema, documentId),
      parse(StatusTransitionSchema, body),
    );
  }

  @Delete('documents/:documentId')
  @UseGuards(StepUpGuard)
  @HttpCode(200)
  async remove(
    @Req() req: CallerRequest,
    @Param('documentId') documentId: string,
  ): Promise<{ deleted: true }> {
    await this.documents.softDelete(requireCaller(req).userId, parse(UuidSchema, documentId));
    return { deleted: true };
  }
}
