import { ConfigError, loadConfig } from '../src/config';

const BASE = {
  DATABASE_URL: 'postgres://estate:estate@localhost:5437/vault',
};

describe('loadConfig', () => {
  it('defaults to development on the vault service port', () => {
    const config = loadConfig({ ...BASE });
    expect(config).toMatchObject({
      nodeEnv: 'development',
      port: 3006,
      kafkaBrokers: null,
      identityUrl: 'http://localhost:3001',
    });
  });

  it('requires a database url', () => {
    expect(() => loadConfig({})).toThrow(ConfigError);
  });

  it('parses a broker list', () => {
    const config = loadConfig({ ...BASE, KAFKA_BROKERS: ' a:9092 , b:9092 ' });
    expect(config.kafkaBrokers).toEqual(['a:9092', 'b:9092']);
  });

  describe('production posture', () => {
    const PROD = { ...BASE, NODE_ENV: 'production' };

    it('requires Kafka so audit emission cannot be a no-op', () => {
      expect(() => loadConfig({ ...PROD, IDENTITY_URL: 'https://identity.internal' })).toThrow(
        /KAFKA_BROKERS/,
      );
    });

    it('rejects a broker list that parses to nothing', () => {
      expect(() =>
        loadConfig({
          ...PROD,
          IDENTITY_URL: 'https://identity.internal',
          KAFKA_BROKERS: ' , ',
        }),
      ).toThrow(/KAFKA_BROKERS/);
    });

    it('requires an identity url for cross-service session verification', () => {
      expect(() => loadConfig({ ...PROD, KAFKA_BROKERS: 'a:9092' })).toThrow(/IDENTITY_URL/);
    });

    it('accepts a complete production environment', () => {
      const config = loadConfig({
        ...PROD,
        KAFKA_BROKERS: 'a:9092',
        IDENTITY_URL: 'https://identity.internal',
      });
      expect(config).toMatchObject({
        nodeEnv: 'production',
        kafkaBrokers: ['a:9092'],
        identityUrl: 'https://identity.internal',
      });
    });
  });

  it('error messages never echo env values', () => {
    const secret = 'postgres://user:hunter2@db.internal:5432/vault';
    try {
      loadConfig({ DATABASE_URL: secret, PORT: 'not-a-port' });
      throw new Error('expected a ConfigError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      const message = (err as ConfigError).message;
      expect(message).not.toContain('hunter2');
      expect(message).not.toContain(secret);
      expect(message).toContain('PORT');
    }
  });

  it('carries no key material at all', () => {
    // Zone A means this service holds nothing it could decrypt with. If a key
    // ever appears in this config, a trust boundary moved.
    const config = loadConfig({ ...BASE });
    expect(Object.keys(config).sort()).toEqual([
      'databaseUrl',
      'identityUrl',
      'kafkaBrokers',
      'nodeEnv',
      'port',
    ]);
  });
});
