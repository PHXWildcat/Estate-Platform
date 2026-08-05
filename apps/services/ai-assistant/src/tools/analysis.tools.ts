import { z } from 'zod';
import type { AnalysisService } from '../analysis.service';
import { LATEST_TAX_YEAR, type AnalysisResult } from '../analysis';
import type { AssistantTool, ToolContext, ToolOutcome } from './registry';

/**
 * The four analysers, as tools (M10 PR3).
 *
 * These are the first MULTI-SCOPE tools: an analysis that reads the document
 * inventory and the profile discloses both to the provider, so it declares both
 * and the executor requires both. All, never any — a beneficiary analysis run
 * without the asset scope would report "no conflicts" from data nobody agreed to
 * share, and "nothing found" is the finding a user acts on by doing nothing.
 *
 * WHAT REACHES THE MODEL IS THE FINDING, NOT THE JUDGEMENT. The analyser has
 * already decided what is wrong, in ordinary deterministic code, and hands over
 * enum codes with structured detail. The model's job is to explain a code in the
 * user's own terms and answer follow-up questions about it. That ordering is the
 * whole point of PR3: an estate-readiness number a user acts on should not be a
 * token sampled from a distribution, and a prompt injection in an uploaded deed
 * cannot invent a finding that the analyser did not compute.
 *
 * Every tool here takes no subject and no ids: the estate analysed is whichever
 * estate the forwarded bearer belongs to (tools/registry.ts).
 */

/** See estate.tools.ts: one refusal for every way a peer read can fail. */
const UPSTREAM_UNAVAILABLE: ToolOutcome = { outcome: 'error', reason: 'upstream_unavailable' };

/**
 * The reference-data gate, surfaced as its own refusal token rather than folded
 * into the generic upstream failure.
 *
 * A control firing must not read as an outage (the M9 rule): "the tax table has
 * not been reviewed" and "the assets service is down" call for completely
 * different reactions from an operator, and the audit stream carries this token
 * so the difference survives to the trail.
 */
const REFERENCE_UNREVIEWED: ToolOutcome = { outcome: 'error', reason: 'reference_unreviewed' };

const NoArgs = z.object({});

/**
 * The only argument any analyser takes. A YEAR, not a date: estate tax is
 * assessed on a year's figures, and `taxYear` names no subject (registry.ts
 * refuses parameters that do). Bounded so a model that hallucinates 20260 gets
 * `invalid_input` from the executor rather than a lookup miss the analyser has
 * to explain.
 */
const TaxArgs = z.object({
  taxYear: z
    .number()
    .int()
    .min(2000)
    .max(LATEST_TAX_YEAR + 5)
    .optional(),
});

/**
 * Map an analyser result onto a tool outcome.
 *
 * The three analyser statuses map onto three DIFFERENT tool outcomes, and
 * keeping them distinct is the point: `ok` with no findings is a real answer
 * ("nothing found"), `unavailable` is a read that did not happen, and `refused`
 * is a control that fired. Collapsing any two would let the model tell a user
 * their estate is fine on the strength of a failure.
 */
function toOutcome<TCode extends string, TSummary>(
  result: AnalysisResult<TCode, TSummary>,
): ToolOutcome {
  switch (result.status) {
    case 'ok':
      return { outcome: 'ok', data: result };
    case 'unavailable':
      return UPSTREAM_UNAVAILABLE;
    case 'refused':
      return REFERENCE_UNREVIEWED;
    default: {
      const exhausted: never = result;
      return { outcome: 'error', reason: `unhandled analysis status: ${String(exhausted)}` };
    }
  }
}

function analyzeFunding(analysis: AnalysisService): AssistantTool {
  return {
    name: 'analyze_funding',
    description:
      "Checks whether the signed-in user's assets are titled into a trust they " +
      'already have. Returns findings with enum codes (an asset outside the ' +
      'trust, funding in progress, a status that contradicts the title) plus ' +
      'totals. If no trust is on file it says so rather than treating that as a ' +
      'gap. Takes no arguments.',
    scopes: ['assistant.assets', 'assistant.documents.metadata'],
    input: NoArgs,
    async execute(ctx: ToolContext): Promise<ToolOutcome> {
      return toOutcome(await analysis.funding(ctx.bearer));
    },
  };
}

function analyzeMissingDocuments(analysis: AnalysisService): AssistantTool {
  return {
    name: 'analyze_missing_documents',
    description:
      'Compares the estate documents on file against the instruments an estate ' +
      'of this shape is expected to hold, including whether each one has ' +
      'actually been executed (a generated but unsigned will directs nothing). ' +
      'Conditions on household structure — a minor child on record makes a ' +
      'guardian designation expected. Takes no arguments.',
    scopes: ['assistant.documents.metadata', 'assistant.profile', 'assistant.assets'],
    input: NoArgs,
    async execute(ctx: ToolContext): Promise<ToolOutcome> {
      return toOutcome(await analysis.missingDocuments(ctx.bearer));
    },
  };
}

function analyzeBeneficiaryConflicts(analysis: AnalysisService): AssistantTool {
  return {
    name: 'analyze_beneficiary_conflicts',
    description:
      'Finds beneficiary problems across the asset ledger: designations that do ' +
      'not total 100%, an asset held in trust that also names beneficiaries ' +
      'directly (the designation passes it outside the trust), duplicate ' +
      'entries, and insurance or annuities with no designation at all. Reports ' +
      'contact ids only, never names. Takes no arguments.',
    scopes: ['assistant.assets'],
    input: NoArgs,
    async execute(ctx: ToolContext): Promise<ToolOutcome> {
      return toOutcome(await analysis.beneficiaryConflicts(ctx.bearer));
    },
  };
}

function estimateEstateTax(analysis: AnalysisService): AssistantTool {
  return {
    name: 'estimate_estate_tax',
    description:
      "Estimates the signed-in user's federal and state estate-tax exposure from " +
      'the asset ledger and state of residence. Reports the GROSS estate against ' +
      'the exemption — it excludes debts, prior gifts and trust structures the ' +
      'platform does not hold, and every result says so. In an inheritance-tax ' +
      'state it reports that exposure exists rather than a number, because the ' +
      "rate depends on each recipient's relationship, which is not recorded. " +
      'Optional taxYear; defaults to the latest year on file.',
    scopes: ['assistant.assets', 'assistant.profile'],
    input: TaxArgs,
    async execute(ctx: ToolContext, input: Record<string, unknown>): Promise<ToolOutcome> {
      // Re-parsed rather than cast, like every other tool with an argument: a
      // caller that bypassed the executor's validation still cannot reach the
      // analyser with an unvalidated value.
      const parsed = TaxArgs.safeParse(input);
      if (!parsed.success) {
        return { outcome: 'error', reason: 'invalid_input' };
      }
      return toOutcome(await analysis.estateTax(ctx.bearer, parsed.data.taxYear));
    },
  };
}

/** Every analyser tool, ordered as a conversation tends to want them. */
export function analysisTools(analysis: AnalysisService): readonly AssistantTool[] {
  return [
    analyzeFunding(analysis),
    analyzeMissingDocuments(analysis),
    analyzeBeneficiaryConflicts(analysis),
    estimateEstateTax(analysis),
  ];
}
