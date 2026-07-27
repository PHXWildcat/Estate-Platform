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
  // Settlement payloads are ids, enums, and timestamps only.
  app.useBodyParser('json', { limit: BODY_LIMIT });
  app.enableShutdownHooks();
  await app.listen(config.port);
}

void bootstrap();
