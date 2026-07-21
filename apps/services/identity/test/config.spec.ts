import { ConfigError, loadConfig } from '../src/config';

const HEX_64 = 'ab'.repeat(32);

function validEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'development',
    DATABASE_URL: 'postgres://localhost:5432/auth',
    KMS_MASTER_KEY_HEX: HEX_64,
    EMAIL_INDEX_KEY_HEX: HEX_64,
    ...overrides,
  };
}

describe('config validation', () => {
  it('parses a valid dev environment (no Kafka needed)', () => {
    const config = loadConfig(validEnv());
    expect(config.nodeEnv).toBe('development');
    expect(config.port).toBe(3001);
    expect(config.kmsMasterKey).toHaveLength(32);
    expect(config.emailIndexKey).toHaveLength(32);
    expect(config.kafkaBrokers).toBeNull();
  });

  it('parses a comma-separated broker list', () => {
    const config = loadConfig(validEnv({ KAFKA_BROKERS: 'k1:9092, k2:9092 ,' }));
    expect(config.kafkaBrokers).toEqual(['k1:9092', 'k2:9092']);
  });

  it('rejects a missing DATABASE_URL', () => {
    expect(() => loadConfig(validEnv({ DATABASE_URL: undefined }))).toThrow(ConfigError);
  });

  it('rejects master keys that are not 32 bytes of hex', () => {
    expect(() => loadConfig(validEnv({ KMS_MASTER_KEY_HEX: 'abcd' }))).toThrow(ConfigError);
    expect(() => loadConfig(validEnv({ EMAIL_INDEX_KEY_HEX: 'zz'.repeat(32) }))).toThrow(
      ConfigError,
    );
  });

  it('rejects an invalid PORT', () => {
    expect(() => loadConfig(validEnv({ PORT: 'not-a-port' }))).toThrow(ConfigError);
  });

  it('production REQUIRES Kafka (audit must never silently no-op)', () => {
    expect(() => loadConfig(validEnv({ NODE_ENV: 'production' }))).toThrow(ConfigError);
    expect(() => loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: ' , ' }))).toThrow(
      ConfigError,
    );
  });

  const PROD_WEBAUTHN = {
    RP_ID: 'estate.example.com',
    RP_ORIGIN: 'https://estate.example.com',
    RP_NAME: 'Estate Platform',
  };

  it('production REQUIRES the WebAuthn RP identity (never a localhost default)', () => {
    // Kafka present but RP vars missing ⇒ still rejected.
    expect(() =>
      loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092' })),
    ).toThrow(ConfigError);
  });

  it('production with brokers and RP identity is accepted', () => {
    const config = loadConfig(
      validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092', ...PROD_WEBAUTHN }),
    );
    expect(config.kafkaBrokers).toEqual(['k1:9092']);
    expect(config.rpId).toBe('estate.example.com');
    expect(config.rpOrigin).toBe('https://estate.example.com');
  });

  it('dev falls back to localhost RP defaults', () => {
    const config = loadConfig(validEnv());
    expect(config.rpId).toBe('localhost');
    expect(config.rpOrigin).toBe('http://localhost:3000');
    expect(config.rpName).toBe('Estate Platform');
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
