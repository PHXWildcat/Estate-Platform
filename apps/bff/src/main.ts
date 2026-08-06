import 'reflect-metadata';
import { createBffApp } from './app';
import { FetchAssetsClient } from './assets-client';
import { FetchAssistantClient } from './assistant-client';
import { loadConfig } from './config';
import { FetchDocumentsClient } from './documents-client';
import { FetchIdentityClient } from './identity-client';
import { FetchProfileClient } from './profile-client';

async function bootstrap(): Promise<void> {
  // Fail fast on bad configuration (and a bad/missing persisted-operations
  // manifest in production) before Nest starts wiring providers.
  const config = loadConfig();
  const app = await createBffApp({
    config,
    identity: new FetchIdentityClient(config.identityUrl),
    assets: new FetchAssetsClient(config.assetsUrl),
    assistant: new FetchAssistantClient(config.aiAssistantUrl),
    documents: new FetchDocumentsClient(config.documentsUrl),
    profile: new FetchProfileClient(config.profileUrl),
  });
  app.enableShutdownHooks();
  await app.listen(config.port);
}

void bootstrap();
