import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { loadConfig } from './config';

async function bootstrap(): Promise<void> {
  // Fail fast on bad configuration before Nest starts wiring providers.
  const config = loadConfig();
  // rawBody: webhook signature verification hashes the EXACT request bytes.
  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn'], rawBody: true });
  app.enableShutdownHooks();
  await app.listen(config.port);
}

void bootstrap();
