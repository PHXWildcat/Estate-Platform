import { Kafka } from 'kafkajs';

/**
 * A topic to provision. Partition and replication counts are explicit rather
 * than defaulted by the broker, because "whatever auto-create gives us" is not
 * a decision anyone reviewed.
 */
export interface TopicSpec {
  topic: string;
  /**
   * Default 1. The audit hash chain does NOT depend on this: `AuditIngestor`
   * serialises chain extension on an `audit_chain_head` row lock, so the chain
   * cannot fork however many partitions deliver out of order. One partition is
   * the local-stack default because it makes delivery order deterministic —
   * which keeps the stack test's assertions simple — and a single-node broker
   * cannot usefully do more anyway.
   */
  numPartitions?: number;
  /** Default 1. A single-node local broker cannot replicate beyond itself. */
  replicationFactor?: number;
}

/** The slice of kafkajs's `Admin` this helper drives, so tests inject a double. */
export interface AdminLike {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  listTopics(): Promise<string[]>;
  createTopics(options: {
    topics: { topic: string; numPartitions: number; replicationFactor: number }[];
    waitForLeaders: boolean;
  }): Promise<boolean>;
}

export interface EnsureTopicsOptions {
  clientId: string;
  brokers: string[];
  topics: readonly TopicSpec[];
  admin?: AdminLike;
}

export interface EnsureTopicsResult {
  created: string[];
  existing: string[];
}

/**
 * Create any of `topics` that do not exist yet, and report what it did.
 *
 * Topics are provisioned EXPLICITLY because nothing else will. Redpanda ships
 * `auto_create_topics_enabled` off by default (unlike Apache Kafka, whose
 * default is on), and no service in this repo has ever called `admin()` — so
 * without this a producer's first send fails and the audit consumer subscribes
 * to a topic that does not exist. Relying on auto-create would also silently
 * pick the broker's partition count and retention rather than the reviewed
 * ones above.
 *
 * Idempotent, and safe to run concurrently with itself: existing topics are
 * skipped, and a topic created by a racing run between the list and the create
 * is re-checked rather than treated as a failure.
 */
export async function ensureTopics(options: EnsureTopicsOptions): Promise<EnsureTopicsResult> {
  const admin =
    options.admin ?? new Kafka({ clientId: options.clientId, brokers: options.brokers }).admin();

  await admin.connect();
  try {
    const before = new Set(await admin.listTopics());
    const missing = options.topics.filter((spec) => !before.has(spec.topic));
    if (missing.length === 0) {
      return { created: [], existing: options.topics.map((spec) => spec.topic) };
    }

    try {
      await admin.createTopics({
        topics: missing.map((spec) => ({
          topic: spec.topic,
          numPartitions: spec.numPartitions ?? 1,
          replicationFactor: spec.replicationFactor ?? 1,
        })),
        waitForLeaders: true,
      });
    } catch (err: unknown) {
      // A concurrent provisioner may have won the race. Re-list: if every
      // topic we wanted now exists, that is success, not a failure.
      const after = new Set(await admin.listTopics());
      const stillMissing = missing.filter((spec) => !after.has(spec.topic));
      if (stillMissing.length > 0) {
        throw err;
      }
    }

    return {
      created: missing.map((spec) => spec.topic),
      existing: options.topics.map((spec) => spec.topic).filter((topic) => before.has(topic)),
    };
  } finally {
    await admin.disconnect();
  }
}
