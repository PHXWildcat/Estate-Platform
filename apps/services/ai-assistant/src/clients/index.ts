/**
 * The assistant's peer-read layer: every piece of estate data the model can
 * ever be told about enters this process through one of these three clients.
 *
 * They share one shape and one property. Each method takes the CALLER'S OWN
 * BEARER and forwards it — this service holds no internal service credential in
 * either direction (src/di-tokens.ts explains why that is the design), so it
 * reads exactly what the calling user could read for themselves and nothing
 * more. Each method answers `null` on every failure, uniformly, because these
 * reads feed a model and a partially-understood response must read as "no data"
 * rather than as data (the rationale in full sits on `readJson`).
 *
 * The view types are also the narrowing: zod strips what the schemas do not
 * name, so widening what the assistant can see means editing a schema in this
 * directory — the profile client is the clearest case, dropping legal name,
 * date of birth, SSN last four, address, phone and occupation before they exist
 * as values here.
 */

export {
  AssetsClient,
  type AssetView,
  type BeneficiariesView,
  type NetWorthView,
} from './assets.client';
export { DocumentsClient, type DocumentContentView, type DocumentView } from './documents.client';
export { ProfileClient, type FamilyMemberView, type ProfileFactsView } from './profile.client';

/** The transport seam, so tests (and app.module) can supply their own fetch. */
export { defaultFetch, type FetchLike } from './http';
