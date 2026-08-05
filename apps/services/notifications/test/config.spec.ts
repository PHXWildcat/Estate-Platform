import { credentialEnvVarsFor, credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
import { ConfigError, loadConfig } from '../src/config';

const KMS_HEX = 'a'.repeat(64);
const STRONG_TOKEN = 'n'.repeat(48);

const DEV_BASE: NodeJS.ProcessEnv = {
  DATABASE_URL: 'postgres://estate:estate@localhost:5432/core',
  KMS_MASTER_KEY_HEX: KMS_HEX,
};

const PROD_BASE: NodeJS.ProcessEnv = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://estate:estate@db:5432/core',
  KAFKA_BROKERS: 'broker:9092',
  NOTIFICATIONS_INTERNAL_TOKEN: STRONG_TOKEN,
  EMAIL_MODE: 'ses',
  SES_FROM_ADDRESS: 'no-reply@estate.example',
  KMS_MODE: 'aws',
  AWS_KMS_KEY_ID: 'alias/notifications-kek',
  AWS_REGION: 'us-east-1',
};

describe('loadConfig (dev/test)', () => {
  it('defaults to the stub carrier, local KMS, port 3008, and an empty inbound credential', () => {
    const config = loadConfig(DEV_BASE);
    expect(config.email).toEqual({ mode: 'stub' });
    expect(config.kms.mode).toBe('local');
    expect(config.port).toBe(3008);
    expect(config.internalApiToken).toBe('');
    expect(config.kekAlias).toBe('notifications/kek');
    expect(config.kafkaBrokers).toBeNull();
  });

  it('requires the SES sender and region as soon as EMAIL_MODE is ses, in any environment', () => {
    expect(() => loadConfig({ ...DEV_BASE, EMAIL_MODE: 'ses' })).toThrow(ConfigError);
    const config = loadConfig({
      ...DEV_BASE,
      EMAIL_MODE: 'ses',
      SES_FROM_ADDRESS: 'no-reply@estate.example',
      AWS_REGION: 'us-east-1',
      AWS_ENDPOINT_URL: 'http://localhost:4566',
    });
    expect(config.email).toEqual({
      mode: 'ses',
      fromAddress: 'no-reply@estate.example',
      region: 'us-east-1',
      endpoint: 'http://localhost:4566',
    });
  });

  it('rejects an unknown carrier', () => {
    expect(() => loadConfig({ ...DEV_BASE, EMAIL_MODE: 'carrier-pigeon' })).toThrow(ConfigError);
  });
});

describe('loadConfig (production)', () => {
  it('accepts the full production shape', () => {
    const config = loadConfig(PROD_BASE);
    expect(config.email.mode).toBe('ses');
    expect(config.kms.mode).toBe('aws');
    expect(config.internalApiToken).toBe(STRONG_TOKEN);
  });

  it.each([
    ['KAFKA_BROKERS', 'audit emission'],
    ['NOTIFICATIONS_INTERNAL_TOKEN', 'the internal surface'],
    ['SES_FROM_ADDRESS', 'the verified sender'],
  ])('requires %s in production', (key) => {
    const env = { ...PROD_BASE };
    delete env[key];
    expect(() => loadConfig(env)).toThrow(ConfigError);
  });

  it('pins the real carrier: the stub cannot run in production', () => {
    expect(() => loadConfig({ ...PROD_BASE, EMAIL_MODE: 'stub' })).toThrow(
      /EMAIL_MODE must be "ses"/,
    );
  });

  it('pins AWS KMS and refuses a plaintext endpoint', () => {
    expect(() => loadConfig({ ...PROD_BASE, KMS_MODE: 'local' })).toThrow(ConfigError);
    expect(() => loadConfig({ ...PROD_BASE, AWS_ENDPOINT_URL: 'http://aws:4566' })).toThrow(
      /must be https in production/,
    );
    expect(loadConfig({ ...PROD_BASE, AWS_ENDPOINT_URL: 'https://aws-tls' }).email).toMatchObject({
      endpoint: 'https://aws-tls',
    });
  });

  it('rejects a weak inbound credential', () => {
    expect(() => loadConfig({ ...PROD_BASE, NOTIFICATIONS_INTERNAL_TOKEN: 'short' })).toThrow(
      ConfigError,
    );
  });
});

describe('service-credential graph (packages/auth-guard/src/credential-graph.ts)', () => {
  it('holds exactly the credentials the graph grants it — no more, no fewer', () => {
    const config = loadConfig({ ...DEV_BASE, ...credentialSentinelEnv() });
    expect(credentialsHeldIn(config)).toEqual(credentialEnvVarsFor('notifications'));
  });
});
