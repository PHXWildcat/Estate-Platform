/**
 * Kafka topic registry. Topic names are versioned; breaking payload changes
 * mean a NEW topic (consumers migrate explicitly), never an in-place change.
 */
export const TOPICS = {
  authEvents: 'estate.auth.events.v1',
  auditEvents: 'estate.audit.events.v1',
  assetEvents: 'estate.asset.events.v1',
  plaidEvents: 'estate.plaid.events.v1',
} as const;

export type TopicName = (typeof TOPICS)[keyof typeof TOPICS];
