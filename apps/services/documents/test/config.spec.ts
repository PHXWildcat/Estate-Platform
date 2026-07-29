import { credentialEnvVarsFor, credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
import { ConfigError, loadConfig } from '../src/config';

const KEY = 'a'.repeat(64);

const DEV_BASE = {
  NODE_ENV: 'development',
  DATABASE_URL: 'postgres://localhost/documents',
  KMS_MASTER_KEY_HEX: KEY,
  SEARCH_INDEX_KEY_HEX: 'b'.repeat(64),
};

const PROD_BASE = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://prod/documents',
  KAFKA_BROKERS: 'k1:9092,k2:9092',
  KMS_MODE: 'aws',
  AWS_KMS_KEY_ID: 'alias/documents-kek',
  AWS_REGION: 'us-east-1',
  IDENTITY_URL: 'https://identity.internal',
  SETTLEMENT_URL: 'https://settlement.internal',
  OBJECT_STORE_MODE: 's3',
  OBJECT_STORE_BUCKET: 'estate-documents',
  SEARCH_INDEX_KEY_HEX: 'b'.repeat(64),
  SCANNER_MODE: 'clamd',
  CLAMD_HOST: 'clamav.internal',
  OCR_MODE: 'textract',
};

describe('documents config', () => {
  it('loads dev defaults: fs object store, local KMS, stub scanner/OCR, no Kafka', () => {
    const config = loadConfig(DEV_BASE);
    expect(config.port).toBe(3005);
    expect(config.kms).toEqual({ mode: 'local', masterKey: Buffer.from(KEY, 'hex') });
    expect(config.objectStore).toEqual({ mode: 'fs', dir: '.object-store' });
    expect(config.scanner).toEqual({ mode: 'stub' });
    expect(config.ocr).toEqual({ mode: 'stub' });
    expect(config.searchIndexKey).toEqual(Buffer.from('b'.repeat(64), 'hex'));
    expect(config.kafkaBrokers).toBeNull();
    expect(config.kekAlias).toBe('documents/kek');
    expect(config.identityUrl).toBe('http://localhost:3001');
    expect(config.settlementUrl).toBe('http://localhost:3007');
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
    expect(config.objectStore).toEqual({
      mode: 's3',
      bucket: 'b',
      region: 'us-east-1',
      endpoint: null,
    });
  });

  it('loads a fully specified production config', () => {
    const config = loadConfig(PROD_BASE);
    expect(config.kms).toEqual({
      mode: 'aws',
      keyId: 'alias/documents-kek',
      region: 'us-east-1',
      endpoint: null,
    });
    expect(config.objectStore).toEqual({
      mode: 's3',
      bucket: 'estate-documents',
      region: 'us-east-1',
      endpoint: null,
    });
    expect(config.kafkaBrokers).toEqual(['k1:9092', 'k2:9092']);
  });

  it('production refuses the local KMS provider and a plaintext AWS endpoint', () => {
    expect(() => loadConfig({ ...PROD_BASE, KMS_MODE: 'local' })).toThrow(/KMS_MODE/);
    expect(() => loadConfig({ ...PROD_BASE, AWS_ENDPOINT_URL: 'http://localstack:4566' })).toThrow(
      /AWS_ENDPOINT_URL/,
    );
  });

  it('one endpoint override reaches KMS, S3 and Textract alike', () => {
    // All three clients address the same emulator in the local stack; a
    // partial override would leave one of them talking to real AWS.
    const config = loadConfig({
      ...DEV_BASE,
      KMS_MODE: 'aws',
      AWS_KMS_KEY_ID: 'alias/documents-kek',
      AWS_REGION: 'us-east-1',
      OBJECT_STORE_MODE: 's3',
      OBJECT_STORE_BUCKET: 'estate-documents',
      OCR_MODE: 'textract',
      AWS_ENDPOINT_URL: 'http://localstack:4566',
    });
    expect(config.kms).toMatchObject({ endpoint: 'http://localstack:4566' });
    expect(config.objectStore).toMatchObject({ endpoint: 'http://localstack:4566' });
    expect(config.ocr).toEqual({
      mode: 'textract',
      region: 'us-east-1',
      endpoint: 'http://localstack:4566',
    });
  });

  it('tesseract is a real engine: production accepts it, and it needs a URL', () => {
    // The production guard names the STUB rather than one permitted engine —
    // which is what its message has always meant, and what stops it rejecting
    // real adapters that simply are not Textract.
    expect(() => loadConfig({ ...DEV_BASE, OCR_MODE: 'tesseract' })).toThrow(/OCR_URL/);
    expect(
      loadConfig({ ...DEV_BASE, OCR_MODE: 'tesseract', OCR_URL: 'http://ocr:8884' }).ocr,
    ).toEqual({ mode: 'tesseract', endpoint: 'http://ocr:8884' });
    const prod = loadConfig({
      ...PROD_BASE,
      OCR_MODE: 'tesseract',
      OCR_URL: 'https://ocr.internal',
    });
    expect(prod.ocr).toEqual({ mode: 'tesseract', endpoint: 'https://ocr.internal' });
  });

  it.each(['KAFKA_BROKERS', 'AWS_KMS_KEY_ID', 'AWS_REGION', 'IDENTITY_URL', 'SETTLEMENT_URL'])(
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

  it('production refuses the stub scanner and stub OCR', () => {
    expect(() => loadConfig({ ...PROD_BASE, SCANNER_MODE: 'stub' })).toThrow(/SCANNER_MODE/);
    expect(() => loadConfig({ ...PROD_BASE, OCR_MODE: 'stub' })).toThrow(/OCR_MODE/);
  });

  it('clamd mode requires a host in any environment; port defaults to 3310', () => {
    expect(() => loadConfig({ ...DEV_BASE, SCANNER_MODE: 'clamd' })).toThrow(/CLAMD_HOST/);
    const config = loadConfig({ ...DEV_BASE, SCANNER_MODE: 'clamd', CLAMD_HOST: 'localhost' });
    expect(config.scanner).toEqual({ mode: 'clamd', host: 'localhost', port: 3310 });
    expect(loadConfig(PROD_BASE).scanner).toEqual({
      mode: 'clamd',
      host: 'clamav.internal',
      port: 3310,
    });
  });

  it('textract mode requires a region; SEARCH_INDEX_KEY_HEX is always required', () => {
    expect(() => loadConfig({ ...DEV_BASE, OCR_MODE: 'textract' })).toThrow(/AWS_REGION/);
    expect(loadConfig({ ...DEV_BASE, OCR_MODE: 'textract', AWS_REGION: 'us-east-1' }).ocr).toEqual({
      mode: 'textract',
      region: 'us-east-1',
      endpoint: null,
    });
    const { SEARCH_INDEX_KEY_HEX: _omit, ...withoutKey } = DEV_BASE;
    expect(() => loadConfig(withoutKey)).toThrow(/SEARCH_INDEX_KEY_HEX/);
  });

  it('production refuses a whitespace-only broker list', () => {
    expect(() => loadConfig({ ...PROD_BASE, KAFKA_BROKERS: ' , ' })).toThrow(ConfigError);
  });

  it('dev fails fast without the local KMS master key', () => {
    const { KMS_MASTER_KEY_HEX: _omit, ...withoutKms } = DEV_BASE;
    expect(() => loadConfig(withoutKms)).toThrow(/KMS_MASTER_KEY_HEX/);
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

describe('service-credential graph (packages/auth-guard/src/credential-graph.ts)', () => {
  it('holds exactly the credentials the graph grants it — no more, no fewer', () => {
    // Every credential in the product is present in this environment. What the
    // service ABSORBS from it is the security property: the M7 review found one
    // config field serving as both settlement's inbound and outbound credential,
    // which transitively handed vault and documents a working key to identity's
    // irreversible account-lock API. Equality in BOTH directions matters — extra
    // means an over-grant, missing means a gate silently unwired.
    const config = loadConfig({ ...DEV_BASE, ...credentialSentinelEnv() });
    expect(credentialsHeldIn(config)).toEqual(credentialEnvVarsFor('documents'));
  });
});
