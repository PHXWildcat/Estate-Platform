import { ConfigError, loadConfig } from '../src/config';

const KEY = 'a'.repeat(64);

const DEV_BASE = {
  NODE_ENV: 'development',
  DATABASE_URL: 'postgres://localhost/documents',
  KMS_MASTER_KEY_HEX: KEY,
};

const PROD_BASE = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://prod/documents',
  KAFKA_BROKERS: 'k1:9092,k2:9092',
  AWS_KMS_KEY_ID: 'alias/documents-kek',
  AWS_REGION: 'us-east-1',
  IDENTITY_URL: 'https://identity.internal',
  OBJECT_STORE_MODE: 's3',
  OBJECT_STORE_BUCKET: 'estate-documents',
};

describe('documents config', () => {
  it('loads dev defaults: fs object store, local KMS, no Kafka', () => {
    const config = loadConfig(DEV_BASE);
    expect(config.port).toBe(3005);
    expect(config.kms).toEqual({ mode: 'local', masterKey: Buffer.from(KEY, 'hex') });
    expect(config.objectStore).toEqual({ mode: 'fs', dir: '.object-store' });
    expect(config.kafkaBrokers).toBeNull();
    expect(config.kekAlias).toBe('documents/kek');
    expect(config.identityUrl).toBe('http://localhost:3001');
  });

  it('honors OBJECT_STORE_DIR in fs mode', () => {
    const config = loadConfig({ ...DEV_BASE, OBJECT_STORE_DIR: 'C:/tmp/objects' });
    expect(config.objectStore).toEqual({ mode: 'fs', dir: 'C:/tmp/objects' });
  });

  it('s3 mode requires bucket and region in any environment', () => {
    expect(() => loadConfig({ ...DEV_BASE, OBJECT_STORE_MODE: 's3' })).toThrow(ConfigError);
    const config = loadConfig({
      ...DEV_BASE,
      OBJECT_STORE_MODE: 's3',
      OBJECT_STORE_BUCKET: 'b',
      AWS_REGION: 'us-east-1',
    });
    expect(config.objectStore).toEqual({ mode: 's3', bucket: 'b', region: 'us-east-1' });
  });

  it('loads a fully specified production config', () => {
    const config = loadConfig(PROD_BASE);
    expect(config.kms).toEqual({
      mode: 'aws',
      keyId: 'alias/documents-kek',
      region: 'us-east-1',
    });
    expect(config.objectStore).toEqual({
      mode: 's3',
      bucket: 'estate-documents',
      region: 'us-east-1',
    });
    expect(config.kafkaBrokers).toEqual(['k1:9092', 'k2:9092']);
  });

  it.each(['KAFKA_BROKERS', 'AWS_KMS_KEY_ID', 'AWS_REGION', 'IDENTITY_URL'])(
    'production fails fast without %s',
    (key) => {
      const env: Record<string, string> = { ...PROD_BASE };
      delete env[key];
      expect(() => loadConfig(env)).toThrow(ConfigError);
    },
  );

  it('production refuses the filesystem object store', () => {
    expect(() => loadConfig({ ...PROD_BASE, OBJECT_STORE_MODE: 'fs' })).toThrow(
      /OBJECT_STORE_MODE/,
    );
  });

  it('production refuses a whitespace-only broker list', () => {
    expect(() => loadConfig({ ...PROD_BASE, KAFKA_BROKERS: ' , ' })).toThrow(ConfigError);
  });

  it('dev fails fast without the local KMS master key', () => {
    expect(() => loadConfig({ NODE_ENV: 'development', DATABASE_URL: 'postgres://x/y' })).toThrow(
      /KMS_MASTER_KEY_HEX/,
    );
    expect(() => loadConfig({ ...DEV_BASE, KMS_MASTER_KEY_HEX: 'nothex' })).toThrow(ConfigError);
  });

  it('error messages never echo env values', () => {
    try {
      loadConfig({ ...DEV_BASE, KMS_MASTER_KEY_HEX: 'super-secret-value' });
      throw new Error('expected ConfigError');
    } catch (err) {
      expect((err as Error).message).not.toContain('super-secret-value');
    }
  });
});
