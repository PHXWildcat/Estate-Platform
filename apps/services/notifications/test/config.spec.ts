import { credentialEnvVarsFor, credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
import { ConfigError, loadConfig } from '../src/config';

const KMS_HEX = 'a'.repeat(64);
const STRONG_TOKEN = 'n'.repeat(48);

const DEV_BASE: NodeJS.ProcessEnv = {
  DATABASE_URL: 'postgres://estate:estate@localhost:5432/core',
  KMS_MASTER_KEY_HEX: KMS_HEX,
};

const PROD_BASE: NodeJS.ProcessEnv = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://estate:estate@db:5432/core',
  KAFKA_BROKERS: 'broker:9092',
  NOTIFICATIONS_INTERNAL_TOKEN: STRONG_TOKEN,
  // The second inbound credential (M9 review): the recipient-upsert surface
  // is identity's alone and must never share a value with the send surface.
  NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN: `${STRONG_TOKEN}-recipients`,
  // M14's two further surfaces, each with its own holder set and therefore its
  // own secret: mailing a verification code, and reading the verified bit.
  NOTIFICATIONS_VERIFY_INTERNAL_TOKEN: `${STRONG_TOKEN}-verify`,
  NOTIFICATIONS_STATUS_INTERNAL_TOKEN: `${STRONG_TOKEN}-status`,
  NOTIFICATIONS_SECURITY_INTERNAL_TOKEN: `${STRONG_TOKEN}-security`,
  NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN: 'echange-token-0123456789abcdef-echange',
  NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN: `${STRONG_TOKEN}-recovery`,
  EMAIL_MODE: 'ses',
  SES_FROM_ADDRESS: 'no-reply@estate.example',
  KMS_MODE: 'aws',
  AWS_KMS_KEY_ID: 'alias/notifications-kek',
  AWS_REGION: 'us-east-1',
};

describe('loadConfig (dev/test)', () => {
  it('defaults to the stub carrier, local KMS, port 3008, and an empty inbound credential', () => {
    const config = loadConfig(DEV_BASE);
    expect(config.email).toEqual({ mode: 'stub' });
    expect(config.kms.mode).toBe('local');
    expect(config.port).toBe(3008);
    expect(config.internalApiToken).toBe('');
    expect(config.kekAlias).toBe('notifications/kek');
    expect(config.kafkaBrokers).toBeNull();
  });

  it('requires the SES sender and region as soon as EMAIL_MODE is ses, in any environment', () => {
    expect(() => loadConfig({ ...DEV_BASE, EMAIL_MODE: 'ses' })).toThrow(ConfigError);
    const config = loadConfig({
      ...DEV_BASE,
      EMAIL_MODE: 'ses',
      SES_FROM_ADDRESS: 'no-reply@estate.example',
      AWS_REGION: 'us-east-1',
      AWS_ENDPOINT_URL: 'http://localhost:4566',
    });
    expect(config.email).toEqual({
      mode: 'ses',
      fromAddress: 'no-reply@estate.example',
      region: 'us-east-1',
      endpoint: 'http://localhost:4566',
    });
  });

  it('rejects an unknown carrier', () => {
    expect(() => loadConfig({ ...DEV_BASE, EMAIL_MODE: 'carrier-pigeon' })).toThrow(ConfigError);
  });
});

/**
 * This service's four inbound surfaces, in one place, so the production
 * requirement, the weak-value check and the full pairwise aliasing check are
 * all derived from the same list rather than restated three times.
 */
const INBOUND_CREDENTIALS = [
  'NOTIFICATIONS_INTERNAL_TOKEN',
  'NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN',
  'NOTIFICATIONS_VERIFY_INTERNAL_TOKEN',
  'NOTIFICATIONS_STATUS_INTERNAL_TOKEN',
  'NOTIFICATIONS_SECURITY_INTERNAL_TOKEN',
  'NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN',
] as const;

describe('loadConfig (production)', () => {
  it('accepts the full production shape', () => {
    const config = loadConfig(PROD_BASE);
    expect(config.email.mode).toBe('ses');
    expect(config.kms.mode).toBe('aws');
    expect(config.internalApiToken).toBe(STRONG_TOKEN);
  });

  it.each([
    ['KAFKA_BROKERS', 'audit emission'],
    ['NOTIFICATIONS_INTERNAL_TOKEN', 'the send surface'],
    ['NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN', 'the recipient surface'],
    ['NOTIFICATIONS_VERIFY_INTERNAL_TOKEN', 'the verification-send surface'],
    ['NOTIFICATIONS_STATUS_INTERNAL_TOKEN', 'the recipient-status surface'],
    ['NOTIFICATIONS_SECURITY_INTERNAL_TOKEN', 'the account-security send surface'],
    ['NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN', 'the password-reset send surface'],
    ['SES_FROM_ADDRESS', 'the verified sender'],
  ])('requires %s in production', (key) => {
    const env = { ...PROD_BASE };
    delete env[key];
    expect(() => loadConfig(env)).toThrow(ConfigError);
  });

  it('pins the real carrier: the stub cannot run in production', () => {
    expect(() => loadConfig({ ...PROD_BASE, EMAIL_MODE: 'stub' })).toThrow(
      /EMAIL_MODE must be "ses"/,
    );
  });

  it('pins AWS KMS and refuses a plaintext endpoint', () => {
    expect(() => loadConfig({ ...PROD_BASE, KMS_MODE: 'local' })).toThrow(ConfigError);
    expect(() => loadConfig({ ...PROD_BASE, AWS_ENDPOINT_URL: 'http://aws:4566' })).toThrow(
      /must be https in production/,
    );
    expect(loadConfig({ ...PROD_BASE, AWS_ENDPOINT_URL: 'https://aws-tls' }).email).toMatchObject({
      endpoint: 'https://aws-tls',
    });
  });

  it.each(INBOUND_CREDENTIALS)('rejects a weak %s', (key) => {
    expect(() => loadConfig({ ...PROD_BASE, [key]: 'short' })).toThrow(ConfigError);
  });

  /**
   * EVERY PAIR, not the one pair that existed when this was written (M9 review,
   * extended by M14). Splitting the surfaces buys nothing if the operator
   * provisions one secret twice — vault and settlement would again hold a
   * working key to the recipient route and could silently repoint any owner's
   * alerts — and a hand-written comparison per pair stays correct only until
   * the next credential lands. Derived from the list, so a fifth surface is
   * covered by adding it there.
   */
  it.each(
    INBOUND_CREDENTIALS.flatMap((a, i) =>
      INBOUND_CREDENTIALS.slice(i + 1).map((b) => [a, b] as const),
    ),
  )('refuses one value pasted into both %s and %s', (a, b) => {
    expect(() => loadConfig({ ...PROD_BASE, [b]: PROD_BASE[a] })).toThrow(/must differ from/);
  });

  it('absorbs each inbound credential into its OWN field', () => {
    const config = loadConfig(PROD_BASE);
    expect(config.internalApiToken).toBe(STRONG_TOKEN);
    expect(config.recipientsApiToken).toBe(`${STRONG_TOKEN}-recipients`);
    expect(config.verificationApiToken).toBe(`${STRONG_TOKEN}-verify`);
    expect(config.recipientStatusApiToken).toBe(`${STRONG_TOKEN}-status`);
    // Four DISTINCT values landing in four distinct fields is the property; a
    // crossed pair of factories would otherwise pass every check above.
    expect(
      new Set([
        config.internalApiToken,
        config.recipientsApiToken,
        config.verificationApiToken,
        config.recipientStatusApiToken,
      ]).size,
    ).toBe(4);
  });
});

describe('service-credential graph (packages/auth-guard/src/credential-graph.ts)', () => {
  it('holds exactly the credentials the graph grants it — no more, no fewer', () => {
    const config = loadConfig({ ...DEV_BASE, ...credentialSentinelEnv() });
    expect(credentialsHeldIn(config)).toEqual(credentialEnvVarsFor('notifications'));
  });
});
