import type { AnalysisService } from '../analysis.service';
import type { AssetsClient, DocumentsClient, ProfileClient } from '../clients';
import { analysisTools } from './analysis.tools';
import { estateTools } from './estate.tools';
import { documentTools } from './document.tools';
import { profileTools } from './profile.tools';
import { ToolRegistry } from './registry';

/**
 * The assistant's whole tool surface, assembled in one place.
 *
 * THIS FILE IS THE ANSWER TO "WHAT CAN THE ASSISTANT DO?", and the answer is
 * deliberately short: eleven read-only operations over the caller's own estate,
 * across four consent scopes — seven retrievals (M10 PR1) and four deterministic
 * analyses over what those retrievals return (M10 PR3). There is no write tool,
 * no send tool, no outbound-fetch tool and no web search — docs/03 §4 TB5 states
 * the tool scopes are read-only, and this is where that stops being a sentence
 * and becomes the set of functions that exist. It is also why risk #6's impact stays Medium:
 * a successful prompt injection has no sink to reach, so the worst it achieves
 * is a misleading answer to the owner about the owner's own data.
 *
 * Adding a tool here is a REVIEW EVENT, not a chore. Each one widens what may
 * be shipped to a third-party model provider, so a new tool arrives with its
 * consent scope, its place in the completeness spec, and — if it is not a
 * read — a conversation about whether it belongs in this service at all.
 *
 * Construction validates the set: `ToolRegistry` refuses a duplicate name and
 * refuses any tool whose input names a subject, and it does so at boot, so a
 * contract violation is a process that will not start rather than a request
 * that quietly reads the wrong estate.
 */

/**
 * The peer clients the tools read through. Every one of them forwards the
 * CALLER'S OWN bearer per call (the bearer is not held here — it arrives with
 * each invocation in the ToolContext), which is why this service needs no
 * internal service credential in either direction: it can reach exactly what
 * the calling user could already reach, and nothing else.
 */
export interface ToolDependencies {
  readonly assets: AssetsClient;
  readonly documents: DocumentsClient;
  readonly profile: ProfileClient;
  /**
   * The analysers. Not a peer client: it reads through the three above and then
   * COMPUTES, which is why its tools return findings rather than records. It is
   * a dependency here for the same reason the clients are — so the registry can
   * be built against doubles in a spec.
   */
  readonly analysis: AnalysisService;
}

/**
 * Build the closed set of tools. The first three groups are named for the peer
 * they read, which is also how they group by consent scope — assets, documents
 * (two scopes: inventory and content), profile. The analysers come last because
 * they are the only ones that span those groups, and so the only ones that
 * declare more than one scope.
 */
export function buildToolRegistry(deps: ToolDependencies): ToolRegistry {
  return new ToolRegistry([
    ...estateTools(deps.assets),
    ...documentTools(deps.documents),
    ...profileTools(deps.profile),
    ...analysisTools(deps.analysis),
  ]);
}

export { analysisTools } from './analysis.tools';
export { estateTools } from './estate.tools';
export { documentTools } from './document.tools';
export { profileTools } from './profile.tools';
export {
  assertScoped,
  assertSubjectFree,
  scopeToken,
  ToolContractError,
  ToolRegistry,
  type AssistantTool,
  type ToolContext,
  type ToolOutcome,
} from './registry';
