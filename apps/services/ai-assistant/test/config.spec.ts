import { credentialEnvVarsFor, credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
import { ConfigError, loadConfig } from '../src/config';

const KMS_HEX = 'a'.repeat(64);

const DEV_BASE: NodeJS.ProcessEnv = {
  DATABASE_URL: 'postgres://estate:estate@localhost:5434/core',
  KMS_MASTER_KEY_HEX: KMS_HEX,
};

const PROD_BASE: NodeJS.ProcessEnv = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://estate:estate@db:5432/core',
  KAFKA_BROKERS: 'broker:9092',
  IDENTITY_URL: 'https://identity.internal',
  ASSETS_URL: 'https://assets.internal',
  DOCUMENTS_URL: 'https://documents.internal',
  PROFILE_URL: 'https://profile.internal',
  KMS_MODE: 'aws',
  AWS_KMS_KEY_ID: 'alias/estate-ai-assistant-kek',
  AWS_REGION: 'us-east-1',
};

describe('loadConfig (dev/test)', () => {
  it('loads dev defaults: port 3009, localhost peers, stub gateway, no Kafka', () => {
    const config = loadConfig(DEV_BASE);
    expect(config.port).toBe(3009);
    expect(config.identityUrl).toBe('http://localhost:3001');
    expect(config.assetsUrl).toBe('http://localhost:3003');
    expect(config.documentsUrl).toBe('http://localhost:3005');
    expect(config.profileUrl).toBe('http://localhost:3002');
    expect(config.llm.mode).toBe('stub');
    expect(config.kafkaBrokers).toBeNull();
  });

  it('rejects a missing DATABASE_URL', () => {
    expect(() => loadConfig({ NODE_ENV: 'development' })).toThrow(ConfigError);
  });

  it('wraps its DEKs under its OWN kek alias, never the core cluster’s', () => {
    // profile, settlement and notifications share this cluster. A shared alias
    // would make the docs/03 §5.3 chokepoint argument false: any co-tenant's
    // KMS grant would unwrap a conversation.
    expect(loadConfig(DEV_BASE).kekAlias).toBe('ai-assistant/kek');
    expect(loadConfig(DEV_BASE).kekAlias).not.toBe('core/kek');
  });

  it('refuses the live provider in EVERY environment until PR2 wires it', () => {
    // Selecting a mode whose adapter does not exist would boot a service whose
    // gateway cannot answer, surfacing per-request instead of at deploy time.
    expect(() => loadConfig({ ...DEV_BASE, LLM_MODE: 'anthropic' })).toThrow(/LLM_MODE/);
    expect(() => loadConfig({ ...PROD_BASE, LLM_MODE: 'anthropic' })).toThrow(/LLM_MODE/);
  });
});

describe('loadConfig (production)', () => {
  it('loads a fully specified production config', () => {
    const config = loadConfig(PROD_BASE);
    expect(config.nodeEnv).toBe('production');
    expect(config.kms.mode).toBe('aws');
    expect(config.kafkaBrokers).toEqual(['broker:9092']);
  });

  it.each(['KAFKA_BROKERS', 'IDENTITY_URL', 'ASSETS_URL', 'DOCUMENTS_URL', 'PROFILE_URL'])(
    'fails fast without %s in production',
    (key) => {
      const env: Record<string, string | undefined> = { ...PROD_BASE };
      delete env[key];
      expect(() => loadConfig(env)).toThrow(ConfigError);
    },
  );

  it.each(['AWS_KMS_KEY_ID', 'AWS_REGION'])(
    'fails fast without %s (LocalKmsProvider is dev-only)',
    (key) => {
      const env: Record<string, string | undefined> = { ...PROD_BASE };
      delete env[key];
      expect(() => loadConfig(env)).toThrow(ConfigError);
    },
  );

  it('refuses the local KMS provider and a plaintext AWS endpoint', () => {
    expect(() => loadConfig({ ...PROD_BASE, KMS_MODE: 'local' })).toThrow(/KMS_MODE/);
    expect(() => loadConfig({ ...PROD_BASE, AWS_ENDPOINT_URL: 'http://localstack:4566' })).toThrow(
      /AWS_ENDPOINT_URL/,
    );
  });
});

describe('configuration errors', () => {
  it('carries the word "configuration" (images.yml smoke grep)', () => {
    try {
      loadConfig({ NODE_ENV: 'development' });
      throw new Error('expected ConfigError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as ConfigError).message).toContain('configuration');
    }
  });

  it('never echoes env values', () => {
    try {
      loadConfig({ ...DEV_BASE, KMS_MASTER_KEY_HEX: 'not-hex-but-secret-looking' });
      throw new Error('expected ConfigError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as Error).message).not.toContain('not-hex-but-secret-looking');
    }
  });
});

describe('service-credential graph (packages/auth-guard/src/credential-graph.ts)', () => {
  it('holds exactly the credentials the graph grants it — no more, no fewer', () => {
    // The AI assistant is granted NONE, and that is the assertion — the audit
    // service's precedent, where the empty set is the whole point. It
    // authenticates callers on their own forwarded bearer (CallerGuard) and
    // presents no service credential to anyone, so the service with the
    // largest prompt-injection surface in the product cannot hold a key that
    // opens another service's internal routes. Every credential in the product
    // is present in this environment; it must absorb none of them.
    //
    // The explicit empty-set assertion matters as much as the equality: without
    // it this test would pass vacuously if the graph ever silently lost the
    // service, which is exactly how a fence stops fencing.
    const config = loadConfig({ ...DEV_BASE, ...credentialSentinelEnv() });
    expect(credentialsHeldIn(config)).toEqual(credentialEnvVarsFor('ai-assistant'));
    expect(credentialEnvVarsFor('ai-assistant')).toEqual([]);
  });
});
