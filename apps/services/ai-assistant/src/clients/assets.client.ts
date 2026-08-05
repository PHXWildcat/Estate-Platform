import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { defaultFetch, pathSegment, readJson, type FetchLike } from './http';

/**
 * Read-only client for the assets service (apps/services/assets), forwarding
 * the caller's own bearer on every call.
 *
 * Retrieval for the assistant is READ-ONLY TOOL CALLS over the user's own
 * structured estate data, never a vector store (docs/01 §2.8) — so this client
 * is the whole of the assistant's asset knowledge, and its schemas are the
 * whole of what an asset can look like inside a prompt. Everything a method
 * cannot return is something no tool can leak.
 *
 * Every failure — network, non-2xx, non-JSON, schema drift — is `null`, and
 * `null` means "this read did not happen", never "the estate is empty". The
 * rationale lives on `readJson`: these reads feed a model, so a
 * partially-understood response must read as no data rather than as data.
 */

/**
 * One asset, narrowed to what a planning conversation actually reasons about.
 *
 * zod strips unknown keys, so this schema IS the narrowing: `costBasis`,
 * `location` and `notes` are on the wire and deliberately do not survive it.
 * Those are free-text fields a user wrote for themselves; a coverage or
 * beneficiary-gap answer needs none of them, and the smallest faithful shape is
 * the one that cannot surprise us later.
 *
 * `fundingStatus` WAS in that list and is now kept (M10 PR3). This file's own
 * rule is that widening it is a reviewed edit rather than a quiet one, so:
 * funding recommendations are half of docs/00 feature 6, the field is a closed
 * four-value enum the assets service owns (`unfunded | in_progress | funded |
 * na`), it identifies nobody, and without it the funding analyser would have to
 * INFER funding from `inTrust` alone — which cannot distinguish "not started"
 * from "retitling is under way" and would nag a user who is mid-transfer.
 *
 * `title` and `category` ARE user-supplied strings and reach the model as data,
 * never as instructions — the same rule the document-content view states at
 * length (docs/03 §4 TB5, risk #6).
 */
const AssetViewSchema = z.object({
  assetId: z.string().min(1),
  category: z.string().min(1),
  title: z.string(),
  // Money is a decimal STRING end to end and is NEVER parsed to a number
  // anywhere in this repo — binary floating point cannot represent an estate.
  estValue: z.string().nullable(),
  valuationAsOf: z.string().nullable(),
  ownershipPct: z.number(),
  inTrust: z.boolean(),
  /**
   * Trust-funding progress, or null when the owner has never said.
   *
   * A NULLISH STRING, not an enum, and not a required key. Both looseness are
   * deliberate: this is a peer service's vocabulary (`unfunded | in_progress |
   * funded | na` today), and `readJson` fails a read CLOSED on schema drift, so
   * a stricter shape here would turn "assets added a fifth status" or "assets
   * omitted the field" into "you have no assets" — a confidently empty estate,
   * which is the one answer this client exists to prevent. An unfamiliar value
   * is simply a status the analyser does not act on.
   */
  fundingStatus: z
    .string()
    .nullish()
    .transform((value) => value ?? null),
});
export type AssetView = z.infer<typeof AssetViewSchema>;

const AssetListSchema = z.array(AssetViewSchema);

/**
 * Estate totals. `byCategory` is dropped: the asset list already carries a
 * category and a value per row, so a breakdown would be a second, separately
 * drifting copy of the same facts in the same prompt.
 */
const NetWorthViewSchema = z.object({
  totalValue: z.string(),
  assetCount: z.number().int(),
  valuedAssetCount: z.number().int(),
  inTrustValue: z.string(),
});
export type NetWorthView = z.infer<typeof NetWorthViewSchema>;

/**
 * Beneficiary designations for one asset.
 *
 * Beneficiaries are CONTACT IDS, never names — that is the assets API's own
 * shape, and it is the right one here: the assistant reasons about whether the
 * designations are complete, which needs no identity at all. `totals` survives
 * the narrowing because `designationComplete` is precisely the gap an estate
 * assistant exists to notice.
 */
const BeneficiariesViewSchema = z.object({
  assetId: z.string().min(1),
  beneficiaries: z.array(
    z.object({
      contactId: z.string().min(1),
      designation: z.string().min(1),
      sharePct: z.number(),
    }),
  ),
  totals: z.array(
    z.object({
      designation: z.string().min(1),
      sharePct: z.number(),
      designationComplete: z.boolean(),
    }),
  ),
});
export type BeneficiariesView = z.infer<typeof BeneficiariesViewSchema>;

@Injectable()
export class AssetsClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(assetsUrl: string, fetchImpl?: FetchLike) {
    // Exactly one trailing slash, so a config value written either way
    // addresses the same routes (the house idiom).
    this.baseUrl = assetsUrl.replace(/\/$/, '');
    this.fetchImpl = fetchImpl ?? defaultFetch;
  }

  /** Estate totals, or null when the read did not happen. */
  netWorth(bearer: string): Promise<NetWorthView | null> {
    return readJson(this.fetchImpl, `${this.baseUrl}/v1/net-worth`, bearer, NetWorthViewSchema);
  }

  /**
   * The caller's own assets. Deliberately the OWNER route (`/v1/assets`), not
   * the executor estate route — the assistant answers for the person holding
   * the bearer, and settlement's staged-access grants are not a conversation
   * surface (docs/03 §5.1 control 5).
   */
  listAssets(bearer: string): Promise<AssetView[] | null> {
    return readJson(this.fetchImpl, `${this.baseUrl}/v1/assets`, bearer, AssetListSchema);
  }

  /** Designations on one asset. Assets applies its own owner check downstream. */
  beneficiaries(bearer: string, assetId: string): Promise<BeneficiariesView | null> {
    const url = `${this.baseUrl}/v1/assets/${pathSegment(assetId)}/beneficiaries`;
    return readJson(this.fetchImpl, url, bearer, BeneficiariesViewSchema);
  }
}
