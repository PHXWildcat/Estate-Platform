import { Controller, Get, HttpCode, Query, UseGuards } from '@nestjs/common';
import { CallerGuard } from '@estate/auth-guard';
import { z } from 'zod';
import { Db } from './db';
import { parse, StateQuerySchema } from './schemas';
import { ExecutionRequirementsSchema, VariableDeclSchema } from './template-model';
import { TemplatesRepo, type TemplateRow } from './templates.repo';

export interface TemplateCatalogEntry {
  templateId: string;
  docType: string;
  state: string;
  version: number;
  legalReviewAt: string;
  executionRequirements: unknown;
  variables: unknown;
}

const VariablesColumnSchema = z.array(VariableDeclSchema);

/**
 * The template catalog: which instruments can be generated for a state, and
 * what intake each requires (so a client can build the questionnaire).
 * Template metadata is product content, not user data — any authenticated
 * caller may read it; there is deliberately no mutation surface (templates
 * publish via the CLI from in-repo sources only).
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class TemplatesController {
  constructor(
    private readonly templates: TemplatesRepo,
    private readonly db: Db,
  ) {}

  @Get('templates')
  @HttpCode(200)
  async list(@Query('state') state: string): Promise<TemplateCatalogEntry[]> {
    const rows = await this.templates.listActiveByState(this.db, parse(StateQuerySchema, state));
    return rows.map(toCatalogEntry);
  }
}

function toCatalogEntry(row: TemplateRow): TemplateCatalogEntry {
  return {
    templateId: row.id,
    docType: row.doc_type,
    state: row.state,
    version: row.version,
    legalReviewAt: row.legal_review_at.toISOString(),
    // Re-validated on the way out so a corrupted column cannot leak arbitrary
    // JSON into API responses.
    executionRequirements: ExecutionRequirementsSchema.parse(row.execution_requirements),
    variables: VariablesColumnSchema.parse(row.variables),
  };
}
