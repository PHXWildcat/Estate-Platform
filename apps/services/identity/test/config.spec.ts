import { credentialEnvVarsFor, credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
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
    expect(config.kms.mode).toBe('local');
    if (config.kms.mode === 'local') {
      expect(config.kms.masterKey).toHaveLength(32);
    }
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

  const PROD_EXTRAS = {
    RP_ID: 'estate.example.com',
    RP_ORIGIN: 'https://estate.example.com',
    RP_NAME: 'Estate Platform',
    KMS_MODE: 'aws',
    AWS_KMS_KEY_ID: 'alias/estate-auth-kek',
    AWS_REGION: 'us-east-1',
    IDENTITY_INTERNAL_TOKEN: 'i'.repeat(48),
    NOTIFICATIONS_URL: 'https://notifications.internal',
    NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN: 'n'.repeat(48),
  };

  it('production REQUIRES the notifications feed (M9) and refuses credential aliasing', () => {
    const { NOTIFICATIONS_URL: _u, ...withoutUrl } = PROD_EXTRAS;
    expect(() =>
      loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092', ...withoutUrl })),
    ).toThrow(ConfigError);
    const { NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN: _t, ...withoutToken } = PROD_EXTRAS;
    expect(() =>
      loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092', ...withoutToken })),
    ).toThrow(ConfigError);
    // The M7 collapse as a value: one string in both slots must refuse to boot.
    expect(() =>
      loadConfig(
        validEnv({
          NODE_ENV: 'production',
          KAFKA_BROKERS: 'k1:9092',
          ...PROD_EXTRAS,
          NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN: PROD_EXTRAS.IDENTITY_INTERNAL_TOKEN,
        }),
      ),
    ).toThrow(/must differ from IDENTITY_INTERNAL_TOKEN/);
  });

  it('production REQUIRES the WebAuthn RP identity (never a localhost default)', () => {
    // Kafka + AWS KMS present but RP vars missing ⇒ still rejected.
    const { RP_ID: _r, RP_ORIGIN: _o, RP_NAME: _n, ...kmsOnly } = PROD_EXTRAS;
    expect(() =>
      loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092', ...kmsOnly })),
    ).toThrow(ConfigError);
  });

  it('production REQUIRES AWS KMS (LocalKmsProvider is dev/test only)', () => {
    const { AWS_KMS_KEY_ID: _k, AWS_REGION: _reg, ...rpOnly } = PROD_EXTRAS;
    expect(() =>
      loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092', ...rpOnly })),
    ).toThrow(ConfigError);
    // The mode is now explicit, so the guarantee is stated directly rather
    // than inferred from NODE_ENV: production refuses the local provider
    // however it is asked for.
    expect(() =>
      loadConfig(
        validEnv({
          NODE_ENV: 'production',
          KAFKA_BROKERS: 'k1:9092',
          ...PROD_EXTRAS,
          KMS_MODE: 'local',
        }),
      ),
    ).toThrow(/KMS_MODE/);
  });

  it('the AWS provider is selectable outside production, and never the default', () => {
    // The local stack exercises the real adapter against an emulator. Dev must
    // be able to opt in; it must never happen by accident.
    expect(loadConfig(validEnv()).kms.mode).toBe('local');
    const config = loadConfig(
      validEnv({
        KMS_MODE: 'aws',
        AWS_KMS_KEY_ID: 'alias/estate-auth-kek',
        AWS_REGION: 'us-east-1',
        AWS_ENDPOINT_URL: 'http://localstack:4566',
      }),
    );
    expect(config.kms).toEqual({
      mode: 'aws',
      keyId: 'alias/estate-auth-kek',
      region: 'us-east-1',
      endpoint: 'http://localstack:4566',
    });
  });

  it('KMS_MODE=aws requires the key material in every environment', () => {
    expect(() => loadConfig(validEnv({ KMS_MODE: 'aws', AWS_REGION: 'us-east-1' }))).toThrow(
      /AWS_KMS_KEY_ID/,
    );
    expect(() => loadConfig(validEnv({ KMS_MODE: 'aws', AWS_KMS_KEY_ID: 'alias/k' }))).toThrow(
      /AWS_REGION/,
    );
  });

  it('production refuses a plaintext AWS endpoint', () => {
    // A local emulator over http is exactly the value that must not survive a
    // copy-paste into a production environment; the SDK itself checks nothing.
    expect(() =>
      loadConfig(
        validEnv({
          NODE_ENV: 'production',
          KAFKA_BROKERS: 'k1:9092',
          ...PROD_EXTRAS,
          AWS_ENDPOINT_URL: 'http://localstack:4566',
        }),
      ),
    ).toThrow(/AWS_ENDPOINT_URL/);
    const ok = loadConfig(
      validEnv({
        NODE_ENV: 'production',
        KAFKA_BROKERS: 'k1:9092',
        ...PROD_EXTRAS,
        AWS_ENDPOINT_URL: 'https://kms.private.internal',
      }),
    );
    expect(ok.kms).toMatchObject({ endpoint: 'https://kms.private.internal' });
  });

  it('production with brokers, RP identity, and AWS KMS is accepted', () => {
    const config = loadConfig(
      validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092', ...PROD_EXTRAS }),
    );
    expect(config.kafkaBrokers).toEqual(['k1:9092']);
    expect(config.rpId).toBe('estate.example.com');
    expect(config.kms).toEqual({
      mode: 'aws',
      keyId: 'alias/estate-auth-kek',
      region: 'us-east-1',
      endpoint: null,
    });
  });

  it('production REQUIRES a non-trivial internal API token (M7 account lock)', () => {
    const { IDENTITY_INTERNAL_TOKEN: _t, ...withoutToken } = PROD_EXTRAS;
    expect(() =>
      loadConfig(validEnv({ NODE_ENV: 'production', KAFKA_BROKERS: 'k1:9092', ...withoutToken })),
    ).toThrow(ConfigError);
    // Present but weak (< 32 chars) is also rejected.
    expect(() =>
      loadConfig(
        validEnv({
          NODE_ENV: 'production',
          KAFKA_BROKERS: 'k1:9092',
          ...withoutToken,
          IDENTITY_INTERNAL_TOKEN: 'short',
        }),
      ),
    ).toThrow(ConfigError);
  });

  it('dev leaves the internal API token empty (guard fails closed)', () => {
    expect(loadConfig(validEnv()).internalApiToken).toBe('');
  });

  it('the internal token names THIS service, not its one known caller', () => {
    // The M7 security review's load-bearing finding: the variable used to be
    // SETTLEMENT_INTERNAL_TOKEN, which read as "the settlement credential" and
    // invited operators to reuse one value everywhere — transitively giving
    // vault and documents a key to the irreversible account-lock API. The name
    // is the control: one secret per CALLEE. A config that only sets the old
    // name must NOT satisfy production.
    const { IDENTITY_INTERNAL_TOKEN: token, ...withoutToken } = PROD_EXTRAS;
    expect(() =>
      loadConfig(
        validEnv({
          NODE_ENV: 'production',
          KAFKA_BROKERS: 'k1:9092',
          ...withoutToken,
          SETTLEMENT_INTERNAL_TOKEN: token,
        }),
      ),
    ).toThrow(ConfigError);
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

describe('service-credential graph (packages/auth-guard/src/credential-graph.ts)', () => {
  it('holds exactly the credentials the graph grants it — no more, no fewer', () => {
    // Every credential in the product is present in this environment. What the
    // service ABSORBS from it is the security property: the M7 review found one
    // config field serving as both settlement's inbound and outbound credential,
    // which transitively handed vault and documents a working key to identity's
    // irreversible account-lock API. Equality in BOTH directions matters — extra
    // means an over-grant, missing means a gate silently unwired.
    const config = loadConfig(validEnv({ ...credentialSentinelEnv() }));
    expect(credentialsHeldIn(config)).toEqual(credentialEnvVarsFor('identity'));
  });
});
