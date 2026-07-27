import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import { loadConfig } from './config';
import { BODY_LIMIT } from './schemas';

async function bootstrap(): Promise<void> {
  // Fail fast on bad configuration before Nest starts wiring providers.
  const config = loadConfig();
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: ['error', 'warn'],
  });
  // Vault blobs arrive as base64 JSON, capped at 68 KiB decoded by the schema.
  // This is the transport-level ceiling above that; SRP payloads (two 512-byte
  // group elements) are far smaller.
  app.useBodyParser('json', { limit: BODY_LIMIT });
  app.enableShutdownHooks();
  await app.listen(config.port);
}

void bootstrap();
