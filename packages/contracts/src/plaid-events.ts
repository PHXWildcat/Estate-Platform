import { z } from 'zod';
import { defineEvent } from './envelope';

/**
 * Plaid item status vocabulary (docs/02 §3 `plaid_items.status`). Lives in
 * contracts because it crosses the bus inside domain events.
 */
export const PLAID_ITEM_STATUSES = ['healthy', 'login_required', 'error', 'revoked'] as const;
export const PlaidItemStatusSchema = z.enum(PLAID_ITEM_STATUSES);
export type PlaidItemStatus = z.infer<typeof PlaidItemStatusSchema>;

/** Account kind vocabulary (docs/02 §3 `accounts.kind`). */
export const ACCOUNT_KINDS = [
  'checking',
  'savings',
  'brokerage',
  'retirement',
  'loan',
  'credit_card',
  'mortgage',
  'investment',
  'other',
] as const;
export const AccountKindSchema = z.enum(ACCOUNT_KINDS);
export type AccountKind = z.infer<typeof AccountKindSchema>;

/**
 * Domain events for the Plaid isolating service. IDs, enums, and counts only:
 * no institution names, balances, masks, or tokens — carrying values would
 * require the docs/01 §4 Zone B Kafka payload crypto, which is not built yet.
 * Consumers needing detail must read it from the owning service.
 */
export const PlaidItemLinkedEvent = defineEvent(
  'plaid.item.linked',
  1,
  z.object({
    itemId: z.string().uuid(),
  }),
);
export type PlaidItemLinked = z.infer<typeof PlaidItemLinkedEvent>;

export const PlaidItemSyncedEvent = defineEvent(
  'plaid.item.synced',
  1,
  z.object({
    itemId: z.string().uuid(),
    accountsUpserted: z.number().int().nonnegative(),
  }),
);
export type PlaidItemSynced = z.infer<typeof PlaidItemSyncedEvent>;

export const PlaidItemStatusChangedEvent = defineEvent(
  'plaid.item.status_changed',
  1,
  z.object({
    itemId: z.string().uuid(),
    status: PlaidItemStatusSchema,
  }),
);
export type PlaidItemStatusChanged = z.infer<typeof PlaidItemStatusChangedEvent>;
