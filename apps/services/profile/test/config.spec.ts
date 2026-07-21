import { ConfigError, loadConfig } from '../src/config';

const HEX_64 = 'ab'.repeat(32);

function validEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'development',
    DATABASE_URL: 'postgres://localhost:5434/core',
    KMS_MASTER_KEY_HEX: HEX_64,
    EMAIL_INDEX_KEY_HEX: HEX_64,
    ...overrides,
  };
}

describe('config validation', () => {
  it('parses a valid dev environment (no Kafka needed)', () => {
    const config = loadConfig(validEnv());
    expect(config.nodeEnv).toBe('development');
    expect(config.port).toBe(3002);
    expect(config.kms.mode).toBe('local');
    if (config.kms.mode === 'local') {
      expect(config.kms.masterKey).toHaveLength(32);
    }
    expect(config.emailIndexKey).toHaveLength(32);
    expect(config.kafkaBrokers).toBeNull();
    expect(config.kekAlias).toBe('core/kek');
  });

  it('parses a comma-separated broker list', () => {
    const config = loadConfig(validEnv({ KAFKA_BROKERS: 'k1:9092, k2:9092 ,' }));
    expect(config.kafkaBrokers).toEqual(['k1:9092', 'k2:9092']);
  });

  it('rejects a missing DATABASE_URL', () => {
    expect(() => loadConfig(validEnv({ DATABASE_URL: undefined }))).toThrow(ConfigError);
  });

  it('rejects keys that are not 32 bytes of hex', () => {
    expect(() => loadConfig(validEnv({ KMS_MASTER_KEY_HEX: 'abcd' }))).toThrow(ConfigError);
    expect(() => loadConfig(validEnv({ EMAIL_INDEX_KEY_HEX: 'zz'.repeat(32) }))).toThrow(
      ConfigError,
    );
  });

  it('rejects an invalid PORT', () => {
    expect(() => loadConfig(validEnv({ PORT: 'not-a-port' }))).toThrow(ConfigError);
  });

  it('requires KMS_MASTER_KEY_HEX outside production', () => {
    expect(() => loadConfig(validEnv({ KMS_MASTER_KEY_HEX: undefined }))).toThrow(ConfigError);
  });

  const PROD_KMS = {
    AWS_KMS_KEY_ID: 'alias/estate-core-kek',
    AWS_REGION: 'us-east-1',
  };

  it('production REQUIRES Kafka (audit must never silently no-op)', () => {
    expect(() => loadConfig(validEnv({ NODE_ENV: 'production', ...PROD_KMS }))).toThrow(
      ConfigError,
    );
    expect(() =>
      loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: ' , ', ...PROD_KMS })),
    ).toThrow(ConfigError);
  });

  it('production REQUIRES AWS KMS (LocalKmsProvider is dev/test only)', () => {
    expect(() =>
      loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092' })),
    ).toThrow(ConfigError);
  });

  it('production with brokers and AWS KMS is accepted (no in-process master key)', () => {
    const config = loadConfig(
      validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092', ...PROD_KMS }),
    );
    expect(config.kafkaBrokers).toEqual(['k1:9092']);
    expect(config.kms).toEqual({
      mode: 'aws',
      keyId: 'alias/estate-core-kek',
      region: 'us-east-1',
    });
  });

  it('error messages carry issue paths, never env values', () => {
    try {
      loadConfig(validEnv({ KMS_MASTER_KEY_HEX: 'super-secret-value' }));
      throw new Error('expected ConfigError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as ConfigError).message).not.toContain('super-secret-value');
    }
  });
});
