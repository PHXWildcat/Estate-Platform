import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { Client } from 'pg';
import { AppModule, PG_CLIENT } from './app.module';
import { AuditConsumer } from './consumer';
import { log } from './logger';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.createApplicationContext(AppModule, { logger: false });
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
