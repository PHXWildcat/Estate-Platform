import {
  BadRequestException,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Query,
  Req,
  ServiceUnavailableException,
  UseGuards,
} from '@nestjs/common';
import { CallerGuard, requireCaller, type CallerRequest } from '@estate/auth-guard';
import type { AnalysisResult } from './analysis';
import { AnalysisService } from './analysis.service';
import { bearerTokenOf } from './bearer';
import { ConsentsRepo } from './consents.repo';
import { EventsService } from './events.service';

/**
 * The analysers as READ ROUTES (M10 PR3) — the same four analyses the tools
 * expose, reachable without a model.
 *
 * WHY THIS SURFACE EXISTS AT ALL. PR4's UI renders an estate-readiness panel:
 * how many instruments are missing, how much value sits outside the trust,
 * whether a designation is incomplete. Those numbers must be COMPUTED, not
 * narrated. Routing them through a conversation would mean the figure on the
 * screen is a token a language model emitted, with everything that implies for
 * a user who acts on it. Here the analyser computes and the response carries the
 * result; the model is not involved in this path at all.
 *
 * ===========================================================================
 * WHY THE CONSENT GATE IS NARROWER HERE THAN ON THE TOOLS, DELIBERATELY
 * ===========================================================================
 *
 * A tool requires every scope the analysis touches, because the findings are
 * rendered into a prompt and sent to a third-party model provider. THESE ROUTES
 * SEND NOTHING ANYWHERE. They fetch on the caller's own forwarded bearer,
 * compute in this process, and return the result to that same caller — who can
 * already read every input directly from assets, documents and profile with the
 * same token.
 *
 * The consent scopes gate EGRESS to a model provider (`consent.ts`: "each scope
 * is a distinct grant of estate data to a third-party model provider"). They are
 * not a second authorization layer over the user's own data, and treating them
 * as one would be a control that protects nobody while teaching users to grant
 * provider egress in order to see their own document checklist — the exact
 * over-granting the per-feature consent design exists to avoid.
 *
 * So these routes require the MASTER SWITCH only. `assistant.enabled` off means
 * the user has turned the assistant off, and a feature that keeps computing
 * after being switched off is not off.
 */

/** What every route here returns: the analyser's own result, unmodified. */
export type AnalysisDto = AnalysisResult<string, unknown>;

/** Closed set of analyser tokens for the audit trail. */
const ANALYZERS = {
  funding: 'funding',
  missingDocuments: 'missing_documents',
  beneficiaryConflicts: 'beneficiary_conflicts',
  estateTax: 'estate_tax',
} as const;

@Controller('v1/analysis')
@UseGuards(CallerGuard)
export class AnalysisController {
  constructor(
    private readonly analysis: AnalysisService,
    private readonly consents: ConsentsRepo,
    private readonly events: EventsService,
  ) {}

  @Get('funding')
  @HttpCode(200)
  async funding(@Req() req: CallerRequest): Promise<AnalysisDto> {
    const caller = requireCaller(req);
    await this.assertEnabled(caller.userId);
    return await this.record(caller.userId, ANALYZERS.funding, () =>
      this.analysis.funding(bearerTokenOf(req)),
    );
  }

  @Get('missing-documents')
  @HttpCode(200)
  async missingDocuments(@Req() req: CallerRequest): Promise<AnalysisDto> {
    const caller = requireCaller(req);
    await this.assertEnabled(caller.userId);
    return await this.record(caller.userId, ANALYZERS.missingDocuments, () =>
      this.analysis.missingDocuments(bearerTokenOf(req)),
    );
  }

  @Get('beneficiary-conflicts')
  @HttpCode(200)
  async beneficiaryConflicts(@Req() req: CallerRequest): Promise<AnalysisDto> {
    const caller = requireCaller(req);
    await this.assertEnabled(caller.userId);
    return await this.record(caller.userId, ANALYZERS.beneficiaryConflicts, () =>
      this.analysis.beneficiaryConflicts(bearerTokenOf(req)),
    );
  }

  @Get('estate-tax')
  @HttpCode(200)
  async estateTax(
    @Req() req: CallerRequest,
    @Query('taxYear') taxYear?: string,
  ): Promise<AnalysisDto> {
    const caller = requireCaller(req);
    await this.assertEnabled(caller.userId);
    const year = parseTaxYear(taxYear);
    return await this.record(caller.userId, ANALYZERS.estateTax, () =>
      this.analysis.estateTax(bearerTokenOf(req), year),
    );
  }

  /**
   * The master switch, and only the master switch — see the class docstring.
   *
   * 403 rather than 404: unlike a conversation id, the existence of this route
   * is not a secret about the caller, and "you have the assistant switched off"
   * is exactly the actionable answer. There is no enumeration oracle here
   * because there is nothing to enumerate — every route is about the caller
   * themselves.
   */
  private async assertEnabled(userId: string): Promise<void> {
    const granted = await this.consents.grantedScopes(userId);
    if (!granted.has('assistant.enabled')) {
      throw new ForbiddenException({
        error: 'assistant_disabled',
        message: 'The AI assistant is switched off for this account.',
      });
    }
  }

  /**
   * Run one analysis and record what happened, in that order.
   *
   * The audit event is emitted AFTER the analysis returns, so nothing ever
   * claims an analysis that did not run — the same after-the-fact ordering the
   * consent routes use, minus a transaction, because this path writes no rows.
   *
   * An `unavailable` result becomes a 503 rather than a 200 carrying an empty
   * answer: a client that rendered "0 findings" from a failed peer read would
   * tell a user their estate is in order on the strength of an outage.
   */
  private async record(
    userId: string,
    analyzer: string,
    run: () => Promise<AnalysisDto>,
  ): Promise<AnalysisDto> {
    const result = await run();
    if (result.status === 'ok') {
      await this.events.analysisCompleted(userId, {
        analyzer,
        findingCount: result.findings.length,
      });
      return result;
    }
    await this.events.analysisRefused(userId, { analyzer, reason: result.reason });
    if (result.status === 'refused') {
      // The reference-data gate. A 503 with the reason token, not a 200 with a
      // number nobody has reviewed (see analysis/reference/review.ts).
      throw new ServiceUnavailableException({
        error: result.reason,
        message: 'This analysis is unavailable in this environment.',
      });
    }
    throw new ServiceUnavailableException({
      error: result.reason,
      message: 'The information this analysis needs could not be read right now.',
    });
  }
}

/**
 * Parse the optional `taxYear` query parameter.
 *
 * Rejects rather than silently defaulting: a client that sends `taxYear=abc`
 * has a bug, and answering it with the latest year's figures would hide that
 * bug behind a plausible answer about someone's estate tax.
 */
function parseTaxYear(raw: string | undefined): number | undefined {
  if (raw === undefined) {
    return undefined;
  }
  if (!/^\d{4}$/.test(raw)) {
    throw new BadRequestException({
      error: 'invalid_tax_year',
      message: 'taxYear must be a year.',
    });
  }
  return Number(raw);
}
