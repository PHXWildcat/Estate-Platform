import 'reflect-metadata';
import { createBffApp } from './app';
import { loadConfig } from './config';
import { FetchIdentityClient } from './identity-client';

async function bootstrap(): Promise<void> {
  // Fail fast on bad configuration (and a bad/missing persisted-operations
  // manifest in production) before Nest starts wiring providers.
  const config = loadConfig();
  const app = await createBffApp({
    config,
    identity: new FetchIdentityClient(config.identityUrl),
  });
  app.enableShutdownHooks();
  await app.listen(config.port);
}

void bootstrap();
