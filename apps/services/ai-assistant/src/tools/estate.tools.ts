import { z } from 'zod';
import type { AssetsClient } from '../clients';
import type { AssistantTool, ToolContext, ToolOutcome } from './registry';

/**
 * The three retrieval tools behind the `assistant.assets` consent scope
 * (docs/01 §2.8: retrieval is read-only tool calls over the user's own
 * structured estate data, never a vector store).
 *
 * None of them names a subject, and that is structural rather than stylistic:
 * the estate they read is whichever estate the forwarded bearer belongs to, so
 * an instruction injected into a document the model is reading has no field in
 * which to nominate a different one (tools/registry.ts, docs/03 §4 TB5 risk
 * #6). The AssetsClient narrowing is the second half of the same property —
 * these tools can only surface what its schemas kept.
 *
 * Every method on the client answers `null` for every failure it can have, and
 * `null` means "this read did not happen", never "the estate is empty". So it
 * becomes `upstream_unavailable` here rather than an empty result: a model told
 * "no assets" will say so to a user who has twelve, and a confidently wrong
 * sentence about someone's estate is the failure mode this whole layer exists
 * to avoid.
 */

/**
 * The single refusal a failed peer read produces. Shared by every tool in this
 * file so the taxonomy cannot drift tool by tool — the client already collapsed
 * network errors, non-2xx, non-JSON and schema drift into one answer, and
 * re-expanding it here would only invite a caller to discriminate on something
 * the transport deliberately refuses to reveal.
 */
const UPSTREAM_UNAVAILABLE: ToolOutcome = { outcome: 'error', reason: 'upstream_unavailable' };

/**
 * Tools whose only input is the authority they run under. An empty object
 * schema is not the absence of a declaration — it is the declaration that this
 * tool takes nothing, which is what `assertSubjectFree` reads and what stops a
 * future edit adding "just an ownerUserId" without review.
 */
const NoArgs = z.object({});

/**
 * The one argument the beneficiary tool takes. `uuid()` is deliberate: these
 * ids arrive as TOOL ARGUMENTS chosen by a model whose context contains
 * untrusted document text, so constraining the shape at the boundary means a
 * hostile sentence cannot turn an id into a path or a query. The client
 * percent-encodes as well — two independent controls, because this is the one
 * place in the product where a URL path segment is influencable through prose.
 */
const BeneficiariesArgs = z.object({ assetId: z.string().uuid() });

/** Estate totals: the cheapest useful answer, and usually the first one wanted. */
function getEstateSummary(assets: AssetsClient): AssistantTool {
  return {
    name: 'get_estate_summary',
    description:
      "Totals across the signed-in user's asset ledger: total estimated value, " +
      'how many assets are recorded, how many carry a valuation, and how much ' +
      'sits in trust. Monetary values are decimal strings. Takes no arguments — ' +
      'it always reports on the signed-in user.',
    scope: 'assistant.assets',
    input: NoArgs,
    async execute(ctx: ToolContext): Promise<ToolOutcome> {
      const view = await assets.netWorth(ctx.bearer);
      return view === null ? UPSTREAM_UNAVAILABLE : { outcome: 'ok', data: view };
    },
  };
}

/** The ledger itself, narrowed by the client to what planning reasons about. */
function listAssets(assets: AssetsClient): AssistantTool {
  return {
    name: 'list_assets',
    description:
      "The signed-in user's assets: category, title, estimated value (a decimal " +
      'string, or null when unvalued), the date and ownership percentage on ' +
      'record, and whether the asset is held in trust. Takes no arguments.',
    scope: 'assistant.assets',
    input: NoArgs,
    async execute(ctx: ToolContext): Promise<ToolOutcome> {
      const view = await assets.listAssets(ctx.bearer);
      // An EMPTY list is a real answer and is reported as one; only a null —
      // the read having failed — becomes a refusal. The two must never merge.
      return view === null ? UPSTREAM_UNAVAILABLE : { outcome: 'ok', data: view };
    },
  };
}

/**
 * Designations on one asset — the gap-finding tool.
 *
 * Beneficiaries come back as CONTACT IDS and share percentages, never names:
 * that is the assets API's own shape and exactly the right one here, since the
 * question an assistant answers ("is this designation complete?") needs no
 * identity at all.
 *
 * An assetId that belongs to someone else, or to nobody, is refused DOWNSTREAM
 * by assets on the forwarded bearer and arrives here as null — so it reports as
 * `upstream_unavailable`, never as "this asset has no beneficiaries". A model
 * that narrated an authorization failure as a fact about an estate would be
 * inventing the most consequential kind of answer this product gives.
 */
function getAssetBeneficiaries(assets: AssetsClient): AssistantTool {
  return {
    name: 'get_asset_beneficiaries',
    description:
      "Beneficiary designations on one of the signed-in user's assets, by asset " +
      'id (from list_assets). Returns contact ids, designation types and share ' +
      'percentages — never names — plus whether each designation adds up to a ' +
      'complete 100%.',
    scope: 'assistant.assets',
    input: BeneficiariesArgs,
    async execute(ctx: ToolContext, input: Record<string, unknown>): Promise<ToolOutcome> {
      // Re-parsing is how the typed argument is obtained without a cast, and it
      // means a caller that bypassed the executor's validation still cannot
      // smuggle an unvalidated id into a peer URL. The executor parses first;
      // this is the belt to that pair of braces.
      const parsed = BeneficiariesArgs.safeParse(input);
      if (!parsed.success) {
        return { outcome: 'error', reason: 'invalid_input' };
      }
      const view = await assets.beneficiaries(ctx.bearer, parsed.data.assetId);
      return view === null ? UPSTREAM_UNAVAILABLE : { outcome: 'ok', data: view };
    },
  };
}

/** Every `assistant.assets` tool, in the order a conversation tends to want them. */
export function estateTools(assets: AssetsClient): readonly AssistantTool[] {
  return [getEstateSummary(assets), listAssets(assets), getAssetBeneficiaries(assets)];
}
