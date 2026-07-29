import { TOPICS } from '@estate/contracts';
import { ensureTopics } from '@estate/kafka';

/**
 * Create every topic in the registry, then exit.
 *
 *   KAFKA_BROKERS=redpanda:29092 node dist/provision-topics-cli.js
 *
 * Runs as a one-shot before the services start. Redpanda ships
 * `auto_create_topics_enabled` OFF (unlike Apache Kafka, whose default is on)
 * and nothing in the services creates topics, so without this the first
 * produce fails and the audit consumer subscribes to a topic that does not
 * exist.
 *
 * The list comes from `TOPICS` in @estate/contracts rather than being retyped
 * in compose YAML: a hand-maintained copy is a copy that drifts, and the
 * failure mode — one topic silently unprovisioned — is a consumer that reports
 * healthy and receives nothing.
 */
async function main(): Promise<number> {
  const brokers = (process.env['KAFKA_BROKERS'] ?? '')
    .split(',')
    .map((b) => b.trim())
    .filter((b) => b.length > 0);
  if (brokers.length === 0) {
    process.stderr.write('KAFKA_BROKERS is required\n');
    return 1;
  }

  const result = await ensureTopics({
    clientId: 'stack-topic-provisioner',
    brokers,
    topics: Object.values(TOPICS).map((topic) => ({ topic })),
  });
  process.stdout.write(
    `topics created: ${result.created.join(', ') || '(none)'}; already present: ${
      result.existing.join(', ') || '(none)'
    }\n`,
  );
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(
      `topic provisioning failed: ${err instanceof Error ? err.message : 'unknown'}\n`,
    );
    process.exitCode = 1;
  });
