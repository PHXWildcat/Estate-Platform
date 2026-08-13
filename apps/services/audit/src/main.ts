import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { Client } from 'pg';
import type { KafkaAuditProducer } from '@estate/kafka';
import { AppModule, AUDIT_PRODUCER, DETECTOR_PG_CLIENT, PG_CLIENT } from './app.module';
import { AuditConsumer } from './consumer';
import { DecryptRateDetector } from './decrypt-rate-detector';
import { DETECTOR_TICK_MS } from './decrypt-rate-bounds';
import { handleFatal } from './fatal';
import { log } from './logger';

/**
 * Handles this process has already opened, so the fatal path can release them.
 * Set as soon as the context exists — the window that matters is AFTER
 * Postgres is connected and BEFORE the consumer reaches the broker.
 */
let opened: { close: () => Promise<void> } | null = null;

async function bootstrap(): Promise<void> {
  const app = await NestFactory.createApplicationContext(AppModule, {
    // Nest's logger stays off: this service logs through the PII-safe
    // structured logger instead (see logger.ts).
    logger: false,
    // ...but Nest's DEFAULT abortOnError then swallows startup failures
    // entirely: it reports initialization errors through that disabled logger
    // and calls process.exit(1) itself, so a misconfigured or DB-unreachable
    // worker dies with an exit code and NO output — a crash-looping pod with
    // nothing to debug, in the one service whose job is the tamper-evident
    // audit trail (docs/01 §6 treats audit gaps as a paging signal). Rejecting
    // instead routes the failure to the catch below, which emits a structured
    // `audit_service_fatal` line naming the error but never event payloads.
    abortOnError: false,
  });
  const consumer = app.get(AuditConsumer);
  const pgClient = app.get<Client>(PG_CLIENT);
  const detectorClient = app.get<Client>(DETECTOR_PG_CLIENT);
  const producer = app.get<KafkaAuditProducer>(AUDIT_PRODUCER);
  const detector = app.get(DecryptRateDetector);
  let detectorTimer: NodeJS.Timeout | null = null;

  const releaseAll = async (): Promise<void> => {
    if (detectorTimer) {
      clearInterval(detectorTimer);
      detectorTimer = null;
    }
    await producer.disconnect();
    await detectorClient.end();
    await pgClient.end();
    await app.close();
  };

  const shutdown = async (signal: string): Promise<void> => {
    log({ level: 'info', msg: 'audit_service_stopping', signal });
    await consumer.stop();
    await releaseAll();
  };
  opened = { close: releaseAll };
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => {
      shutdown(signal)
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
    });
  }

  // The consumer's own death takes the SAME path a failed startup takes: log,
  // release the handles, exit non-zero so the restart policy fires. Without
  // this the process would keep running with a disconnected consumer.
  await consumer.start((err) => {
    void handleFatal(err, opened);
  });

  // The M18 decrypt-rate detector: STARTED HERE, deliberately not via a Nest
  // lifecycle hook — jest suites construct the classes directly and never run
  // main.ts, so the timer structurally cannot run under test (the
  // settlement-driver rule, achieved by placement instead of an env check,
  // because this service's config deliberately has no NODE_ENV). unref'd:
  // an advisory sweep must never keep the process alive, and its faults are
  // swallowed inside tick() — a detector error must never take the path the
  // consumer's death takes (advisory loss degrades alerting, not safety).
  detectorTimer = setInterval(() => {
    void detector.tick();
  }, DETECTOR_TICK_MS);
  detectorTimer.unref();

  log({ level: 'info', msg: 'audit_service_started', groupId: 'audit-service' });
}

bootstrap().catch((err: unknown) => handleFatal(err, opened));
