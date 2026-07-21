import { z } from 'zod';
import { defineEvent } from './envelope';

/**
 * Asset category vocabulary (docs/02 §3 `assets_view.category`). Lives in
 * contracts because it crosses the bus inside domain events and is shared
 * with future consumers (search indexer, analytics).
 */
export const ASSET_CATEGORIES = [
  'cash',
  'gold',
  'silver',
  'jewelry',
  'art',
  'collectible',
  'business',
  'llc',
  'private_equity',
  'crypto',
  'real_estate',
  'vehicle',
  'aircraft',
  'boat',
  'intellectual_property',
  'life_insurance',
  'ltc_insurance',
  'annuity',
  'safe_deposit_box',
  'digital_asset',
  'other',
] as const;
export const AssetCategorySchema = z.enum(ASSET_CATEGORIES);
export type AssetCategory = z.infer<typeof AssetCategorySchema>;

/**
 * Ledger event-type vocabulary. The encrypted event payloads themselves never
 * cross the bus — only these type tags do — so the full payload schemas live
 * in the asset service, not here.
 */
export const ASSET_EVENT_TYPES = [
  'AssetCreated',
  'AssetDetailsUpdated',
  'ValuationRecorded',
  'OwnershipChanged',
  'BeneficiaryDesignated',
  'BeneficiaryRemoved',
  'AssetRetired',
] as const;
export const AssetEventTypeSchema = z.enum(ASSET_EVENT_TYPES);
export type AssetEventType = z.infer<typeof AssetEventTypeSchema>;

/**
 * Domain event published after a ledger append commits. IDs and enums only:
 * no titles, values, or other Zone B payload — carrying those would require
 * the application-layer Kafka payload encryption of docs/01 §4, which is not
 * built yet. Consumers needing detail must read it from the owning service.
 */
export const AssetLedgerAppendedEvent = defineEvent(
  'asset.ledger.appended',
  1,
  z.object({
    assetId: z.string().uuid(),
    ledgerEventId: z.string().uuid(),
    eventType: AssetEventTypeSchema,
    category: AssetCategorySchema.optional(),
  }),
);
export type AssetLedgerAppended = z.infer<typeof AssetLedgerAppendedEvent>;
