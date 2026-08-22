/**
 * Asset-category display labels — one spelling for the whole app (M24 PR3
 * hoist out of AssetsPanel, which keeps only its create-form subset).
 *
 * The VOCABULARY is owned by the `assets_view` CHECK constraint
 * (apps/services/assets/migrations/001_financial_schema.sql); this map is a
 * display companion and is TOTAL over that vocabulary (the lib/documents.ts
 * rule: a token arriving without wording is a compile error, not a raw token
 * on someone's screen). `categories.test.ts` derives the DDL's member set and
 * pins this map to it in both directions, so neither side can grow alone.
 */

/** docs/02 §3 `assets_view.category`. */
export type AssetCategory =
  | 'cash'
  | 'gold'
  | 'silver'
  | 'jewelry'
  | 'art'
  | 'collectible'
  | 'business'
  | 'llc'
  | 'private_equity'
  | 'crypto'
  | 'real_estate'
  | 'vehicle'
  | 'aircraft'
  | 'boat'
  | 'intellectual_property'
  | 'life_insurance'
  | 'ltc_insurance'
  | 'annuity'
  | 'safe_deposit_box'
  | 'digital_asset'
  | 'other';

export const CATEGORY_LABELS: Record<AssetCategory, string> = {
  cash: 'Cash',
  gold: 'Gold',
  silver: 'Silver',
  jewelry: 'Jewelry',
  art: 'Art',
  collectible: 'Collectible',
  business: 'Business',
  llc: 'LLC',
  private_equity: 'Private equity',
  crypto: 'Crypto',
  real_estate: 'Real estate',
  vehicle: 'Vehicle',
  aircraft: 'Aircraft',
  boat: 'Boat',
  intellectual_property: 'Intellectual property',
  life_insurance: 'Life insurance',
  ltc_insurance: 'Long-term-care insurance',
  annuity: 'Annuity',
  safe_deposit_box: 'Safe deposit box',
  digital_asset: 'Digital asset',
  other: 'Other',
};

/** A member the DDL grows past this build still renders, as its raw token. */
export function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category as AssetCategory] ?? category;
}

/**
 * The categories the dashboard's insurance facet counts — docs/04 M24 scope:
 * insurance "as the data model has it", three asset CATEGORIES rather than a
 * policy model. The vocabulary source is the same DDL CHECK; the test above
 * asserts every member here is a real DDL member with a label.
 */
export const INSURANCE_CATEGORIES = ['life_insurance', 'ltc_insurance', 'annuity'] as const;
