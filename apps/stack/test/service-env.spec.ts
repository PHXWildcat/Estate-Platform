import { parseEnvFile } from '../src/doctor';
import { generateEnv, renderEnvFile } from '../src/generate-env';
import {
  bffProcessEnv,
  plannedServices,
  scrubbedBaseEnv,
  serviceProcessEnv,
} from '../src/service-env';
import { databaseUrl, HOST_NETWORK, SERVICES, serviceUrl } from '../src/topology';

function generated(
  mode: 'development' | 'production' = 'development',
  addressing: 'compose' | 'host' = 'host',
): Map<string, string> {
  return parseEnvFile(renderEnvFile(generateEnv({ mode, addressing }), { mode }));
}

const HOST = { addressing: 'host' as const };

function svc(name: string): (typeof SERVICES)[number] {
  const found = SERVICES.find((s) => s.name === name);
  if (!found) {
    throw new Error(`no service ${name}`);
  }
  return found;
}

describe('topology addressing', () => {
  it('host mode reaches infra via published ports, compose via container names', () => {
    expect(databaseUrl('core', 'host')).toContain('@localhost:5434/core');
    expect(databaseUrl('core', 'compose')).toContain('@pg-core:5432/core');
    expect(serviceUrl('identity', 'host')).toBe('http://localhost:3001');
    expect(serviceUrl('identity', 'compose')).toBe('http://identity:3001');
    expect(HOST_NETWORK.kafkaBrokers).toBe('localhost:9092');
  });

  it('refuses a URL for the headless audit service', () => {
    expect(() => serviceUrl('audit', 'host')).toThrow(/no addressable service/);
  });
});

describe('serviceProcessEnv', () => {
  it('gives identity exactly its variables — one peer (notifications) since M9', () => {
    const env = serviceProcessEnv(svc('identity'), generated(), HOST);
    expect(Object.keys(env).sort()).toEqual([
      'AWS_ACCESS_KEY_ID',
      'AWS_ENDPOINT_URL',
      'AWS_KMS_KEY_ID',
      'AWS_REGION',
      'AWS_SECRET_ACCESS_KEY',
      'DATABASE_URL',
      'EMAIL_INDEX_KEY_HEX',
      'IDENTITY_INTERNAL_TOKEN',
      'KAFKA_BROKERS',
      'KMS_MASTER_KEY_HEX',
      'KMS_MODE',
      'NODE_ENV',
      'NODE_EXTRA_CA_CERTS',
      'NOTIFICATIONS_INTERNAL_TOKEN',
      'NOTIFICATIONS_URL',
      'PORT',
      'RP_ID',
      'RP_NAME',
      'RP_ORIGIN',
    ]);
    expect(env['DATABASE_URL']).toContain('@localhost:5433/auth');
    expect(env['NOTIFICATIONS_URL']).toBe('http://localhost:3008');
  });

  it('maps prefixed credentials to the bare names the services read', () => {
    const file = generated();
    const vault = serviceProcessEnv(svc('vault'), file, HOST);
    expect(vault['SETTLEMENT_INTERNAL_TOKEN']).toBe(file.get('VAULT_SETTLEMENT_INTERNAL_TOKEN'));
    const settlement = serviceProcessEnv(svc('settlement'), file, HOST);
    expect(settlement['SETTLEMENT_INTERNAL_TOKEN']).toBe(
      file.get('SETTLEMENT_SETTLEMENT_INTERNAL_TOKEN'),
    );
    expect(settlement['IDENTITY_INTERNAL_TOKEN']).toBe(
      file.get('SETTLEMENT_IDENTITY_INTERNAL_TOKEN'),
    );
    // The equality the generator promises, restated at the process boundary.
    const identity = serviceProcessEnv(svc('identity'), file, HOST);
    expect(settlement['IDENTITY_INTERNAL_TOKEN']).toBe(identity['IDENTITY_INTERNAL_TOKEN']);
  });

  it('gives vault NO key material and NO AWS variables (Zone A)', () => {
    const vault = serviceProcessEnv(svc('vault'), generated(), HOST);
    for (const key of Object.keys(vault)) {
      expect(key).not.toMatch(/^AWS_|^KMS_/);
    }
  });

  it('audit is headless: exactly DATABASE_URL and KAFKA_BROKERS', () => {
    expect(Object.keys(serviceProcessEnv(svc('audit'), generated(), HOST)).sort()).toEqual([
      'DATABASE_URL',
      'KAFKA_BROKERS',
    ]);
  });

  it("documents' inbound credential is real, and settlement holds the same value (M9 PR2)", () => {
    const file = generated();
    const documents = serviceProcessEnv(svc('documents'), file, HOST);
    const settlement = serviceProcessEnv(svc('settlement'), file, HOST);
    expect(documents['DOCUMENTS_INTERNAL_TOKEN']).toBeTruthy();
    expect(settlement['DOCUMENTS_INTERNAL_TOKEN']).toBe(documents['DOCUMENTS_INTERNAL_TOKEN']);
    expect(settlement['DOCUMENTS_URL']).toBe('http://localhost:3005');
    expect(documents['OCR_URL']).toBe('http://localhost:8884');
    expect(documents['CLAMD_HOST']).toBe('localhost');
  });

  it('throws by NAME on a missing variable rather than booting a half-configured child', () => {
    const file = generated();
    file.delete('IDENTITY_EMAIL_INDEX_KEY_HEX');
    expect(() => serviceProcessEnv(svc('identity'), file, HOST)).toThrow(
      /IDENTITY_EMAIL_INDEX_KEY_HEX/,
    );
  });
});

describe('plannedServices', () => {
  it('runs everything in development', () => {
    expect(plannedServices(generated('development')).map((s) => s.name)).toEqual(
      SERVICES.map((s) => s.name),
    );
  });

  it('drops plaid from a production run — live mode has no credentials to boot with', () => {
    const names = plannedServices(generated('production')).map((s) => s.name);
    expect(names).not.toContain('plaid');
    expect(names).toContain('identity');
  });
});

describe('scrubbedBaseEnv', () => {
  it('strips everything credential-shaped and keeps the platform basics', () => {
    const scrubbed = scrubbedBaseEnv({
      PATH: '/usr/bin',
      SystemRoot: 'C:\\Windows',
      AWS_PROFILE: 'prod-admin',
      AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
      aws_secret_access_key: 'shh',
      IDENTITY_INTERNAL_TOKEN: 'stolen',
      KMS_MASTER_KEY_HEX: 'ff',
      UNDEFINED_ONE: undefined,
    });
    expect(scrubbed).toEqual({ PATH: '/usr/bin', SystemRoot: 'C:\\Windows' });
  });

  it('strips the TLS escape hatches, which the env-file doctor cannot see', () => {
    // The doctor refuses an env FILE that disables TLS verification, because
    // that turns production mode's https requirement into decoration. Both of
    // these reach a child from the developer's shell without ever appearing in
    // the file the doctor read.
    expect(
      scrubbedBaseEnv({
        PATH: '/usr/bin',
        NODE_TLS_REJECT_UNAUTHORIZED: '0',
        NODE_OPTIONS: '--use-openssl-ca --require ./evil.js',
        NODE_EXTRA_CA_CERTS: '/home/dev/some-other-ca.pem',
      }),
    ).toEqual({ PATH: '/usr/bin' });
  });
});

describe('bffProcessEnv', () => {
  it('maps the BFF with a host manifest path', () => {
    const env = bffProcessEnv(generated(), { addressing: 'host', manifestPath: '/repo/m.json' });
    expect(env).toEqual({
      NODE_ENV: 'development',
      PORT: '4000',
      IDENTITY_URL: 'http://localhost:3001',
      ASSETS_URL: 'http://localhost:3003',
      PERSISTED_MANIFEST_PATH: '/repo/m.json',
    });
  });
});
