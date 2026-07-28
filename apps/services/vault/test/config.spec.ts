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
    // The settlement gate (docs/03 §6a) is production-required too: without a
    // reachable settlement and a credential, every emergency release blocks.
    const PROD = {
      ...BASE,
      NODE_ENV: 'production',
      SETTLEMENT_URL: 'https://settlement.internal',
      SETTLEMENT_INTERNAL_TOKEN: 's'.repeat(48),
    };

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
        settlementUrl: 'https://settlement.internal',
      });
    });

    it.each(['SETTLEMENT_URL', 'SETTLEMENT_INTERNAL_TOKEN'])(
      'requires %s so the §6a emergency-access gate is reachable',
      (key) => {
        const env: Record<string, string> = {
          ...PROD,
          KAFKA_BROKERS: 'a:9092',
          IDENTITY_URL: 'https://identity.internal',
        };
        delete env[key];
        expect(() => loadConfig(env)).toThrow(new RegExp(key));
      },
    );

    it('rejects a weak settlement credential', () => {
      expect(() =>
        loadConfig({
          ...PROD,
          KAFKA_BROKERS: 'a:9092',
          IDENTITY_URL: 'https://identity.internal',
          SETTLEMENT_INTERNAL_TOKEN: 'short',
        }),
      ).toThrow(/SETTLEMENT_INTERNAL_TOKEN/);
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
    //
    // `settlementInternalToken` (M7 PR2) is an AUTHENTICATION credential for
    // the docs/03 §6a gate, not key material: it proves who is asking about an
    // owner's settlement state and opens no ciphertext whatsoever. The
    // invariant this test guards — no KMS key, no master key, no index key —
    // is unchanged.
    const config = loadConfig({ ...BASE });
    expect(Object.keys(config).sort()).toEqual([
      'databaseUrl',
      'identityUrl',
      'kafkaBrokers',
      'nodeEnv',
      'notify',
      'port',
      'settlementInternalToken',
      'settlementUrl',
    ]);
    // Belt and braces: nothing in this config can decrypt anything.
    for (const forbidden of ['kms', 'masterKey', 'searchIndexKey', 'kekAlias']) {
      expect(Object.keys(config)).not.toContain(forbidden);
    }
  });

  it('defaults the notification channel to the stub', () => {
    // Only the stub exists today. Deliberately not a boot-time production
    // requirement: the refusal is scoped to the emergency-access routes, whose
    // safety depends on reaching the owner, rather than taking the whole vault
    // down for a feature most users never arm.
    expect(loadConfig({ ...BASE }).notify).toEqual({ mode: 'stub' });
    expect(
      loadConfig({
        ...BASE,
        NODE_ENV: 'production',
        KAFKA_BROKERS: 'a:9092',
        IDENTITY_URL: 'https://identity.internal',
        SETTLEMENT_URL: 'https://settlement.internal',
        SETTLEMENT_INTERNAL_TOKEN: 's'.repeat(48),
      }).notify,
    ).toEqual({ mode: 'stub' });
  });

  it('rejects an unknown notification channel', () => {
    expect(() => loadConfig({ ...BASE, NOTIFY_MODE: 'carrier-pigeon' })).toThrow(ConfigError);
  });
});
