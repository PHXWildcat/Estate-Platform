import { ConfigError, loadConfig } from '../src/config';

const DEV_BASE = {
  NODE_ENV: 'development',
  DATABASE_URL: 'postgres://localhost:5434/core',
  // PR2 encrypts distribution amounts, so the dev KMS master key is required
  // outside production exactly as in every other Zone B service.
  KMS_MASTER_KEY_HEX: 'ab'.repeat(32),
};

const PROD_BASE = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://prod/core',
  KAFKA_BROKERS: 'k1:9092,k2:9092',
  IDENTITY_URL: 'https://identity.internal',
  // TWO credentials, in opposite directions and never equal: the inbound one
  // callers present to THIS service's gate route, the outbound one this
  // service presents to identity's account-lock API.
  SETTLEMENT_INTERNAL_TOKEN: 's'.repeat(48),
  IDENTITY_INTERNAL_TOKEN: 'i'.repeat(48),
  AWS_KMS_KEY_ID: 'alias/estate-settlement-kek',
  AWS_REGION: 'us-east-1',
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
    expect(config.internalApiToken).toBe('');
    expect(config.identityInternalToken).toBe('');
  });

  it('rejects a missing DATABASE_URL', () => {
    expect(() => loadConfig({ NODE_ENV: 'development' })).toThrow(ConfigError);
  });

  it('wraps its DEKs under its OWN kek alias, never profile’s core/kek', () => {
    // Both services co-tenant the core cluster; the KMS grant is what keeps a
    // distribution amount unreadable by profile (docs/03 §5.3).
    expect(loadConfig(DEV_BASE).kekAlias).toBe('settlement/kek');
  });

  it.each(['KMS_MASTER_KEY_HEX'])('dev fails fast without %s', (key) => {
    const env: Record<string, string> = { ...DEV_BASE };
    delete env[key];
    expect(() => loadConfig(env)).toThrow(ConfigError);
  });

  it.each(['AWS_KMS_KEY_ID', 'AWS_REGION'])(
    'production fails fast without %s (LocalKmsProvider is dev-only)',
    (key) => {
      const env: Record<string, string> = { ...PROD_BASE };
      delete env[key];
      expect(() => loadConfig(env)).toThrow(ConfigError);
    },
  );

  it('loads a fully specified production config', () => {
    const config = loadConfig(PROD_BASE);
    expect(config.kafkaBrokers).toEqual(['k1:9092', 'k2:9092']);
    expect(config.internalApiToken).toBe('s'.repeat(48));
    expect(config.identityInternalToken).toBe('i'.repeat(48));
  });

  it.each([
    'KAFKA_BROKERS',
    'IDENTITY_URL',
    'SETTLEMENT_INTERNAL_TOKEN',
    'IDENTITY_INTERNAL_TOKEN',
  ])('production fails fast without %s', (key) => {
    const env: Record<string, string> = { ...PROD_BASE };
    delete env[key];
    expect(() => loadConfig(env)).toThrow(ConfigError);
  });

  it.each(['SETTLEMENT_INTERNAL_TOKEN', 'IDENTITY_INTERNAL_TOKEN'])(
    'production rejects a weak (short) %s',
    (key) => {
      expect(() => loadConfig({ ...PROD_BASE, [key]: 'short' })).toThrow(ConfigError);
    },
  );

  it('production REFUSES to boot when the two credentials are the same value', () => {
    // The M7 security review's load-bearing finding. One field used to serve
    // both directions, so the deployment that made settlement's gate work also
    // gave vault (and documents) a credential identity would accept on
    // PUT /internal/v1/settlement-lock/:userId — enough to entomb any living
    // user with no case, no operator and no waiting period (docs/03 §5.1's
    // Critical outcome). Splitting the field is only half the fix: an operator
    // pasting one secret into both slots recreates it exactly. Config refuses.
    const shared = 'x'.repeat(48);
    expect(() =>
      loadConfig({
        ...PROD_BASE,
        SETTLEMENT_INTERNAL_TOKEN: shared,
        IDENTITY_INTERNAL_TOKEN: shared,
      }),
    ).toThrow(ConfigError);
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
