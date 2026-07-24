import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { Client } from 'pg';
import { AppModule, PG_CLIENT } from './app.module';
import { AuditConsumer } from './consumer';
import { log } from './logger';

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

  const shutdown = async (signal: string): Promise<void> => {
    log({ level: 'info', msg: 'audit_service_stopping', signal });
    await consumer.stop();
    await pgClient.end();
    await app.close();
  };
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => {
      shutdown(signal)
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
    });
  }

  await consumer.start();
  log({ level: 'info', msg: 'audit_service_started', groupId: 'audit-service' });
}

bootstrap().catch((err: unknown) => {
  // Infrastructure failure detail only — never event payloads (which are the
  // only place PII could appear, and they are handled without throwing).
  log({
    level: 'error',
    msg: 'audit_service_fatal',
    error: err instanceof Error ? `${err.name}: ${err.message}` : 'unknown',
  });
  process.exitCode = 1;
});
