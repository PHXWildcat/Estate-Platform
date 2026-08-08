import { credentialEnvVarsFor, credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
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
      NOTIFY_MODE: 'http',
      NOTIFICATIONS_URL: 'https://notifications.internal',
      NOTIFICATIONS_INTERNAL_TOKEN: 'n'.repeat(48),
      // M14: the STATUS edge, a distinct secret — vault reads whether the owner
      // proved their address before arming an escrow.
      NOTIFICATIONS_STATUS_INTERNAL_TOKEN: 'v'.repeat(48),
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

    it('pins the real notifier (M9): the stub cannot run in production', () => {
      expect(() =>
        loadConfig({
          ...PROD,
          KAFKA_BROKERS: 'a:9092',
          IDENTITY_URL: 'https://identity.internal',
          NOTIFY_MODE: 'stub',
        }),
      ).toThrow(/NOTIFY_MODE must be "http"/);
    });

    it('refuses aliasing the notifications credential onto the settlement one', () => {
      expect(() =>
        loadConfig({
          ...PROD,
          KAFKA_BROKERS: 'a:9092',
          IDENTITY_URL: 'https://identity.internal',
          NOTIFICATIONS_INTERNAL_TOKEN: PROD.SETTLEMENT_INTERNAL_TOKEN,
        }),
      ).toThrow(/must differ from SETTLEMENT_INTERNAL_TOKEN/);
    });
  });

  it('requires the notifications url as soon as NOTIFY_MODE is http, in any environment', () => {
    expect(() => loadConfig({ ...BASE, NOTIFY_MODE: 'http' })).toThrow(/NOTIFICATIONS_URL/);
    const config = loadConfig({
      ...BASE,
      NOTIFY_MODE: 'http',
      NOTIFICATIONS_URL: 'http://localhost:3008',
    });
    expect(config.notify).toEqual({ mode: 'http' });
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
    //
    // It is also scoped to exactly that one CALLEE. The M7 security review
    // found the credential shared with identity's account-lock API, which
    // would have made this config — the one in the product's most exposed
    // service — a key to irreversibly marking a living user deceased. The
    // exact key list below is what keeps that regression loud.
    const config = loadConfig({ ...BASE });
    // `notificationsInternalToken` (M9) is the same class as
    // `settlementInternalToken`: an authentication credential for one callee's
    // notification-domain routes — not key material, and not identity's
    // account-lock value (config refuses that aliasing in production).
    expect(Object.keys(config).sort()).toEqual([
      'databaseUrl',
      'identityUrl',
      'kafkaBrokers',
      'nodeEnv',
      'notificationsInternalToken',
      'notificationsStatusToken',
      'notificationsUrl',
      'notify',
      'port',
      'settlementInternalToken',
      'settlementUrl',
    ]);
    // Belt and braces: nothing in this config can decrypt anything, and
    // nothing in it authenticates against identity's internal (account-lock)
    // surface — vault's only service-to-service reach is settlement's gate.
    for (const forbidden of [
      'kms',
      'masterKey',
      'searchIndexKey',
      'kekAlias',
      'identityInternalToken',
      'internalApiToken',
    ]) {
      expect(Object.keys(config)).not.toContain(forbidden);
    }
  });

  it('defaults the notification channel to the stub in dev — and ONLY in dev', () => {
    // The pre-M9 stance ("not a boot-time production requirement") is
    // deliberately reversed now a real adapter exists: production pins 'http',
    // asserted in the production-posture suite above. Dev keeps the stub.
    expect(loadConfig({ ...BASE }).notify).toEqual({ mode: 'stub' });
    expect(() =>
      loadConfig({
        ...BASE,
        NODE_ENV: 'production',
        KAFKA_BROKERS: 'a:9092',
        IDENTITY_URL: 'https://identity.internal',
        SETTLEMENT_URL: 'https://settlement.internal',
        SETTLEMENT_INTERNAL_TOKEN: 's'.repeat(48),
      }),
    ).toThrow(/NOTIFY_MODE must be "http"/);
  });

  it('rejects an unknown notification channel', () => {
    expect(() => loadConfig({ ...BASE, NOTIFY_MODE: 'carrier-pigeon' })).toThrow(ConfigError);
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
    const config = loadConfig({ ...BASE, ...credentialSentinelEnv() });
    expect(credentialsHeldIn(config)).toEqual(credentialEnvVarsFor('vault'));
  });
});
