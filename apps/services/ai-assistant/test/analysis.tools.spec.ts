import { ANALYSIS_DISCLAIMER, type AnalysisResult } from '../src/analysis';
import type { AnalysisService } from '../src/analysis.service';
import { analysisTools } from '../src/tools/analysis.tools';
import type { AssistantTool, ToolContext, ToolOutcome } from '../src/tools';

/**
 * The tool wrappers around the analysers. Thin by design — they map an analyser
 * result onto a tool outcome — so what these tests protect is the MAPPING, which
 * is where a collapse between "nothing found", "the read failed" and "a control
 * fired" would do its damage.
 */

const CTX: ToolContext = {
  userId: 'a1000000-0000-4000-8000-00000000000a',
  bearer: 'caller-own-bearer',
};

const OK: AnalysisResult<string, unknown> = {
  status: 'ok',
  findings: [],
  summary: { trustOnFile: false },
  disclaimer: ANALYSIS_DISCLAIMER,
};

function toolsFor(result: AnalysisResult<string, unknown>): {
  tools: Map<string, AssistantTool>;
  years: (number | undefined)[];
} {
  const years: (number | undefined)[] = [];
  const service = {
    funding: () => Promise.resolve(result),
    missingDocuments: () => Promise.resolve(result),
    beneficiaryConflicts: () => Promise.resolve(result),
    estateTax: (_bearer: string, taxYear?: number) => {
      years.push(taxYear);
      return Promise.resolve(result);
    },
  } as unknown as AnalysisService;
  const tools = new Map(analysisTools(service).map((tool) => [tool.name, tool]));
  return { tools, years };
}

function run(
  tools: Map<string, AssistantTool>,
  name: string,
  input: Record<string, unknown> = {},
): Promise<ToolOutcome> {
  const tool = tools.get(name);
  if (tool === undefined) {
    throw new Error(`no such tool: ${name}`);
  }
  return tool.execute(CTX, input);
}

const NAMES = [
  'analyze_funding',
  'analyze_missing_documents',
  'analyze_beneficiary_conflicts',
  'estimate_estate_tax',
];

describe('the analyser tools', () => {
  it('are the four expected ones', () => {
    expect([...toolsFor(OK).tools.keys()]).toEqual(NAMES);
  });

  it('declare EVERY scope the analysis reads, not just one', () => {
    // The first multi-scope tools in the service. An analysis that reads the
    // document inventory and the profile discloses both to the provider, so it
    // must not run on one grant.
    const { tools } = toolsFor(OK);
    expect(tools.get('analyze_funding')?.scopes).toEqual([
      'assistant.assets',
      'assistant.documents.metadata',
    ]);
    expect(tools.get('analyze_missing_documents')?.scopes).toEqual([
      'assistant.documents.metadata',
      'assistant.profile',
      'assistant.assets',
    ]);
    expect(tools.get('estimate_estate_tax')?.scopes).toEqual([
      'assistant.assets',
      'assistant.profile',
    ]);
    // Beneficiary conflicts read the ledger and nothing else, so they declare
    // one scope — the set is the analysis's real reach, not a habit.
    expect(tools.get('analyze_beneficiary_conflicts')?.scopes).toEqual(['assistant.assets']);
  });

  it.each(NAMES)('%s passes a successful analysis through as data', async (name) => {
    const { tools } = toolsFor(OK);
    await expect(run(tools, name)).resolves.toEqual({ outcome: 'ok', data: OK });
  });

  it.each(NAMES)('%s reports an unreadable input as upstream_unavailable', async (name) => {
    // NOT as an empty result. "No findings" and "I could not look" are the two
    // sentences this whole layer exists to keep apart.
    const { tools } = toolsFor({
      status: 'unavailable',
      reason: 'upstream_unavailable',
      disclaimer: ANALYSIS_DISCLAIMER,
    });
    await expect(run(tools, name)).resolves.toEqual({
      outcome: 'error',
      reason: 'upstream_unavailable',
    });
  });

  it('reports the reference-data gate under its own reason token', async () => {
    // A control firing must not read as an outage (the M9 rule): the token
    // reaches the audit stream, where "get the tax table reviewed" and "a peer
    // is down" are different jobs for whoever is reading.
    const { tools } = toolsFor({
      status: 'refused',
      reason: 'reference_unreviewed',
      disclaimer: ANALYSIS_DISCLAIMER,
    });
    await expect(run(tools, 'estimate_estate_tax')).resolves.toEqual({
      outcome: 'error',
      reason: 'reference_unreviewed',
    });
  });
});

describe('estimate_estate_tax arguments', () => {
  it('accepts no arguments at all', async () => {
    const { tools, years } = toolsFor(OK);
    await run(tools, 'estimate_estate_tax');
    expect(years).toEqual([undefined]);
  });

  it('passes a plausible year through', async () => {
    const { tools, years } = toolsFor(OK);
    await run(tools, 'estimate_estate_tax', { taxYear: 2026 });
    expect(years).toEqual([2026]);
  });

  it('refuses a year the model invented, rather than looking it up', async () => {
    // The argument arrives from a model whose context contains untrusted
    // document text, so it is re-parsed here even though the executor already
    // validated it — the same belt-and-braces every other argument-taking tool
    // applies.
    const { tools, years } = toolsFor(OK);
    for (const bad of [20260, 1066, '2026', 2026.5, null]) {
      await expect(run(tools, 'estimate_estate_tax', { taxYear: bad })).resolves.toEqual({
        outcome: 'error',
        reason: 'invalid_input',
      });
    }
    expect(years).toEqual([]);
  });
});
