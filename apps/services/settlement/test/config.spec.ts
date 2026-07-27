import { ConfigError, loadConfig } from '../src/config';

const DEV_BASE = {
  NODE_ENV: 'development',
  DATABASE_URL: 'postgres://localhost:5434/core',
};

const PROD_BASE = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://prod/core',
  KAFKA_BROKERS: 'k1:9092,k2:9092',
  IDENTITY_URL: 'https://identity.internal',
  SETTLEMENT_INTERNAL_TOKEN: 's'.repeat(48),
};

describe('settlement config', () => {
  it('loads dev defaults: port 3007, localhost identity, stub notifier, no Kafka', () => {
    const config = loadConfig(DEV_BASE);
    expect(config.port).toBe(3007);
    expect(config.identityUrl).toBe('http://localhost:3001');
    expect(config.notify).toEqual({ mode: 'stub' });
    expect(config.kafkaBrokers).toBeNull();
    expect(config.driverIntervalMs).toBe(60_000);
    // Unset in dev: identity's guard fails closed until both sides opt in.
    expect(config.settlementInternalToken).toBe('');
  });

  it('rejects a missing DATABASE_URL', () => {
    expect(() => loadConfig({ NODE_ENV: 'development' })).toThrow(ConfigError);
  });

  it('loads a fully specified production config', () => {
    const config = loadConfig(PROD_BASE);
    expect(config.kafkaBrokers).toEqual(['k1:9092', 'k2:9092']);
    expect(config.settlementInternalToken).toBe('s'.repeat(48));
  });

  it.each(['KAFKA_BROKERS', 'IDENTITY_URL', 'SETTLEMENT_INTERNAL_TOKEN'])(
    'production fails fast without %s',
    (key) => {
      const env: Record<string, string> = { ...PROD_BASE };
      delete env[key];
      expect(() => loadConfig(env)).toThrow(ConfigError);
    },
  );

  it('production rejects a weak (short) internal token', () => {
    expect(() => loadConfig({ ...PROD_BASE, SETTLEMENT_INTERNAL_TOKEN: 'short' })).toThrow(
      ConfigError,
    );
  });

  it('production refuses a whitespace-only broker list', () => {
    expect(() => loadConfig({ ...PROD_BASE, KAFKA_BROKERS: ' , ' })).toThrow(ConfigError);
  });

  it('the failure message carries the word "configuration" (images.yml smoke grep)', () => {
    try {
      loadConfig({ NODE_ENV: 'development' });
      throw new Error('expected ConfigError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as ConfigError).message).toContain('configuration');
    }
  });

  it('error messages never echo env values', () => {
    try {
      loadConfig({ ...PROD_BASE, SETTLEMENT_INTERNAL_TOKEN: 'super-secret-but-short' });
      throw new Error('expected ConfigError');
    } catch (err) {
      expect((err as Error).message).not.toContain('super-secret-but-short');
    }
  });
});
