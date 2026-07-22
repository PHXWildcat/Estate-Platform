import { randomBytes } from 'node:crypto';
import { ConfigError, loadConfig } from '../src/config';

const KEY = randomBytes(32).toString('hex');

function baseEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    DATABASE_URL: 'postgres://x/y',
    KMS_MASTER_KEY_HEX: KEY,
    ITEM_INDEX_KEY_HEX: KEY,
    ...overrides,
  } as NodeJS.ProcessEnv;
}

describe('plaid service config (fail-fast posture)', () => {
  it('loads a dev/test config with the stub gateway by default', () => {
    const config = loadConfig(baseEnv());
    expect(config.plaid).toEqual({ mode: 'stub' });
    expect(config.kms.mode).toBe('local');
    expect(config.kekAlias).toBe('plaid/kek');
  });

  it('requires DATABASE_URL and ITEM_INDEX_KEY_HEX', () => {
    expect(() => loadConfig(baseEnv({ DATABASE_URL: undefined }))).toThrow(ConfigError);
    expect(() => loadConfig(baseEnv({ ITEM_INDEX_KEY_HEX: undefined }))).toThrow(ConfigError);
    expect(() => loadConfig(baseEnv({ ITEM_INDEX_KEY_HEX: 'deadbeef' }))).toThrow(ConfigError);
  });

  it('requires KMS_MASTER_KEY_HEX outside production', () => {
    expect(() => loadConfig(baseEnv({ KMS_MASTER_KEY_HEX: undefined }))).toThrow(ConfigError);
  });

  it('live mode requires Plaid credentials', () => {
    expect(() => loadConfig(baseEnv({ PLAID_MODE: 'live' }))).toThrow(ConfigError);
    const config = loadConfig(
      baseEnv({ PLAID_MODE: 'live', PLAID_CLIENT_ID: 'cid', PLAID_SECRET: 's3cr3t' }),
    );
    expect(config.plaid).toEqual({
      mode: 'live',
      env: 'sandbox',
      clientId: 'cid',
      secret: 's3cr3t',
    });
  });

  function prodEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
    return baseEnv({
      NODE_ENV: 'production',
      KMS_MASTER_KEY_HEX: undefined,
      AWS_KMS_KEY_ID: 'alias/plaid-kek',
      AWS_REGION: 'us-east-1',
      KAFKA_BROKERS: 'b-1:9092',
      PLAID_MODE: 'live',
      PLAID_ENV: 'production',
      PLAID_CLIENT_ID: 'cid',
      PLAID_SECRET: 's3cr3t',
      ...overrides,
    });
  }

  it('accepts a complete production config (AWS KMS + Kafka + live Plaid)', () => {
    const config = loadConfig(prodEnv());
    expect(config.kms).toEqual({ mode: 'aws', keyId: 'alias/plaid-kek', region: 'us-east-1' });
    expect(config.kafkaBrokers).toEqual(['b-1:9092']);
  });

  it.each([
    ['KAFKA_BROKERS', { KAFKA_BROKERS: undefined }],
    ['AWS_KMS_KEY_ID', { AWS_KMS_KEY_ID: undefined }],
    ['AWS_REGION', { AWS_REGION: undefined }],
    ['PLAID_CLIENT_ID', { PLAID_CLIENT_ID: undefined }],
  ])('production fails fast without %s', (_key, overrides) => {
    expect(() => loadConfig(prodEnv(overrides))).toThrow(ConfigError);
  });

  it('production can NEVER run the stub gateway', () => {
    expect(() => loadConfig(prodEnv({ PLAID_MODE: 'stub' }))).toThrow(ConfigError);
    expect(() => loadConfig(prodEnv({ PLAID_MODE: undefined }))).toThrow(ConfigError);
  });

  it('never echoes env values in error messages', () => {
    try {
      loadConfig(baseEnv({ ITEM_INDEX_KEY_HEX: 'super-secret-value' }));
      throw new Error('expected ConfigError');
    } catch (err) {
      expect((err as Error).message).not.toContain('super-secret-value');
    }
  });
});
