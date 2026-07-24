import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import { loadConfig } from './config';

async function bootstrap(): Promise<void> {
  // Fail fast on bad configuration before Nest starts wiring providers.
  const config = loadConfig();
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: ['error', 'warn'],
  });
  // Uploads arrive as strict base64 JSON (UPLOAD_MAX_BYTES decoded ⇒ ~14MB
  // encoded); the JSON body limit is the transport-level cap above the
  // schema-level one. Everything else on this service is far smaller.
  app.useBodyParser('json', { limit: '16mb' });
  app.enableShutdownHooks();
  await app.listen(config.port);
}

void bootstrap();
