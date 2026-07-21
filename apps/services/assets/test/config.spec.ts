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

  it('production requires AWS KMS and Kafka (LocalKmsProvider is dev-only)', () => {
    const prod = {
      NODE_ENV: 'production',
      DATABASE_URL: 'postgres://prod/financial',
    } as NodeJS.ProcessEnv;
    expect(() => loadConfig(prod)).toThrow(ConfigError);
    expect(() =>
      loadConfig({ ...prod, AWS_KMS_KEY_ID: 'alias/financial', AWS_REGION: 'us-east-1' }),
    ).toThrow(ConfigError); // still no brokers
    const ok = loadConfig({
      ...prod,
      AWS_KMS_KEY_ID: 'alias/financial',
      AWS_REGION: 'us-east-1',
      KAFKA_BROKERS: 'b-1:9092, b-2:9092',
    });
    expect(ok.kms).toEqual({ mode: 'aws', keyId: 'alias/financial', region: 'us-east-1' });
    expect(ok.kafkaBrokers).toEqual(['b-1:9092', 'b-2:9092']);
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
