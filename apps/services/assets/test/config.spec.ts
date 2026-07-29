import { credentialEnvVarsFor, credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
import { randomBytes } from 'node:crypto';
import { ConfigError, loadConfig } from '../src/config';

const HEX = randomBytes(32).toString('hex');

function baseEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    DATABASE_URL: 'postgres://localhost/financial',
    KMS_MASTER_KEY_HEX: HEX,
    ...overrides,
  };
}

describe('assets service config', () => {
  it('loads a dev/test config with the local KMS backend', () => {
    const config = loadConfig(baseEnv());
    expect(config.kms.mode).toBe('local');
    expect(config.kekAlias).toBe('financial/kek');
    expect(config.port).toBe(3003);
    expect(config.kafkaBrokers).toBeNull();
  });

  it('fails fast without a database url', () => {
    expect(() => loadConfig(baseEnv({ DATABASE_URL: undefined }))).toThrow(ConfigError);
  });

  it('requires the local master key outside production', () => {
    expect(() => loadConfig(baseEnv({ KMS_MASTER_KEY_HEX: undefined }))).toThrow(ConfigError);
    expect(() => loadConfig(baseEnv({ KMS_MASTER_KEY_HEX: 'deadbeef' }))).toThrow(ConfigError);
  });

  it('production requires AWS KMS, Kafka, and IDENTITY_URL (LocalKmsProvider is dev-only)', () => {
    const prod = {
      NODE_ENV: 'production',
      DATABASE_URL: 'postgres://prod/financial',
    } as NodeJS.ProcessEnv;
    expect(() => loadConfig(prod)).toThrow(ConfigError);
    expect(() =>
      loadConfig({
        ...prod,
        KMS_MODE: 'aws',
        AWS_KMS_KEY_ID: 'alias/financial',
        AWS_REGION: 'us-east-1',
      }),
    ).toThrow(ConfigError); // still no brokers
    expect(() =>
      loadConfig({
        ...prod,
        KMS_MODE: 'aws',
        AWS_KMS_KEY_ID: 'alias/financial',
        AWS_REGION: 'us-east-1',
        KAFKA_BROKERS: 'b-1:9092',
      }),
    ).toThrow(ConfigError); // still no IDENTITY_URL (cross-service verification)
    expect(() =>
      loadConfig({
        ...prod,
        KMS_MODE: 'aws',
        AWS_KMS_KEY_ID: 'alias/financial',
        AWS_REGION: 'us-east-1',
        KAFKA_BROKERS: 'b-1:9092',
        IDENTITY_URL: 'https://identity.internal',
      }),
    ).toThrow(ConfigError); // still no SETTLEMENT_URL (executor staged access)
    const ok = loadConfig({
      ...prod,
      KMS_MODE: 'aws',
      AWS_KMS_KEY_ID: 'alias/financial',
      AWS_REGION: 'us-east-1',
      KAFKA_BROKERS: 'b-1:9092, b-2:9092',
      IDENTITY_URL: 'https://identity.internal',
      SETTLEMENT_URL: 'https://settlement.internal',
    });
    expect(ok.kms).toEqual({
      mode: 'aws',
      keyId: 'alias/financial',
      region: 'us-east-1',
      endpoint: null,
    });
    expect(ok.kafkaBrokers).toEqual(['b-1:9092', 'b-2:9092']);
    expect(ok.identityUrl).toBe('https://identity.internal');
  });

  it('production refuses the local KMS provider however it is asked for', () => {
    const prodOk = {
      NODE_ENV: 'production',
      DATABASE_URL: 'postgres://prod/financial',
      KMS_MODE: 'aws',
      AWS_KMS_KEY_ID: 'alias/financial',
      AWS_REGION: 'us-east-1',
      KAFKA_BROKERS: 'b-1:9092',
      IDENTITY_URL: 'https://identity.internal',
      SETTLEMENT_URL: 'https://settlement.internal',
    } as NodeJS.ProcessEnv;
    expect(() => loadConfig({ ...prodOk, KMS_MODE: 'local' })).toThrow(/KMS_MODE/);
    expect(() => loadConfig({ ...prodOk, AWS_ENDPOINT_URL: 'http://localstack:4566' })).toThrow(
      /AWS_ENDPOINT_URL/,
    );
  });

  it('the AWS provider is selectable outside production, and never the default', () => {
    expect(loadConfig(baseEnv()).kms.mode).toBe('local');
    expect(
      loadConfig(
        baseEnv({
          KMS_MODE: 'aws',
          AWS_KMS_KEY_ID: 'alias/financial',
          AWS_REGION: 'us-east-1',
          AWS_ENDPOINT_URL: 'http://localstack:4566',
        }),
      ).kms,
    ).toEqual({
      mode: 'aws',
      keyId: 'alias/financial',
      region: 'us-east-1',
      endpoint: 'http://localstack:4566',
    });
  });

  it('defaults IDENTITY_URL to localhost outside production', () => {
    expect(loadConfig(baseEnv()).identityUrl).toBe('http://localhost:3001');
  });

  it('never echoes env values in config errors', () => {
    try {
      loadConfig(baseEnv({ DATABASE_URL: undefined, SECRETY: 'hunter2' }));
      fail('expected ConfigError');
    } catch (err) {
      expect((err as Error).message).not.toContain('hunter2');
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
    const config = loadConfig(baseEnv({ ...credentialSentinelEnv() }));
    expect(credentialsHeldIn(config)).toEqual(credentialEnvVarsFor('assets'));
  });
});
