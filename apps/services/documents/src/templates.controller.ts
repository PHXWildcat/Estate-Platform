import { Controller, Get, HttpCode, Query, Req, UseGuards } from '@nestjs/common';
import { CallerGuard, requireCaller, type CallerRequest } from '@estate/auth-guard';

import { Db } from './db';
import { EventsService } from './events.service';
import { parse, StateQuerySchema } from './schemas';
import { TemplateEngine, TemplateIntegrityError } from './template-engine';
import type { TemplateSource } from './template-model';
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

/**
 * The template catalog: which instruments can be generated for a state, and
 * what intake each requires (so a client can build the questionnaire).
 * Template metadata is product content, not user data — any authenticated
 * caller may read it; there is deliberately no mutation surface (templates
 * publish via the CLI from in-repo sources only).
 *
 * SERVED FROM THE sha256-VERIFIED SOURCE, NOT FROM THE ROW. The `templates`
 * table carries `variables` and `execution_requirements` as JSONB, and this
 * route used to return those columns with a shape-only re-validation. That was
 * enough to keep arbitrary JSON out of a response, and not enough for what the
 * columns are USED FOR: a client builds its intake questionnaire from
 * `variables` and shows the signing formalities from `execution_requirements`,
 * so a tampered row could put a different set of questions and a different
 * statement of what a will requires in front of an owner (docs/03 TB4, risk
 * #8). The M4 review made the verified SOURCE authoritative for the formalities
 * GATE for exactly this reason; the M12 review found the DISPLAY had been left
 * behind. `TemplateEngine.load` verifies `body_sha256` before parsing, so both
 * now come from the same bytes the renderer will use — and the engine caches by
 * (id, sha), so steady state costs no object-store round trip.
 *
 * A TEMPLATE THAT FAILS VERIFICATION IS OMITTED, not degraded: offering to
 * generate an instrument from a body nobody can vouch for is the fail-open this
 * exists to prevent. The failure is audited, because it is the signal the pin
 * exists to produce.
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class TemplatesController {
  constructor(
    private readonly templates: TemplatesRepo,
    private readonly db: Db,
    private readonly engine: TemplateEngine,
    private readonly events: EventsService,
  ) {}

  @Get('templates')
  @HttpCode(200)
  async list(
    @Req() req: CallerRequest,
    @Query('state') state: string,
  ): Promise<TemplateCatalogEntry[]> {
    const actor = requireCaller(req).userId;
    const rows = await this.templates.listActiveByState(this.db, parse(StateQuerySchema, state));
    const entries: TemplateCatalogEntry[] = [];
    for (const row of rows) {
      let source: TemplateSource;
      try {
        source = await this.engine.load(row);
      } catch (err) {
        if (err instanceof TemplateIntegrityError) {
          await this.events.templateIntegrityFailed(actor, null, row.id);
        }
        // Unverifiable, unparseable, or unreadable: it is not on offer.
        continue;
      }
      entries.push(toCatalogEntry(row, source));
    }
    return entries;
  }
}

function toCatalogEntry(row: TemplateRow, source: TemplateSource): TemplateCatalogEntry {
  return {
    templateId: row.id,
    docType: row.doc_type,
    state: row.state,
    version: row.version,
    legalReviewAt: row.legal_review_at.toISOString(),
    // From the verified body, so what a client asks and what it says about
    // signing match what the renderer will actually use.
    executionRequirements: source.executionRequirements,
    variables: source.variables,
  };
}
