import { diagnose, parseEnvFile } from '../src/doctor';
import { generateEnv, renderEnvFile, writeStackEnv } from '../src/generate-env';
import {
  databaseUrl,
  networkFor,
  TLS_AWS_ENDPOINT,
  TLS_CA_PATH,
  TLS_CA_PATH_HOST,
  tlsCaPathFor,
} from '../src/topology';

function generated(
  mode: 'development' | 'production',
  addressing: 'compose' | 'host' = 'compose',
): Map<string, string> {
  return parseEnvFile(renderEnvFile(generateEnv({ mode, addressing }), { mode }));
}

const codesOf = (env: Map<string, string>): string[] =>
  diagnose(env)
    .filter((f) => f.severity === 'error')
    .map((f) => f.code);

describe('production reaches AWS over TLS', () => {
  it('routes production through the TLS proxy and trusts its CA', () => {
    // The PR1 guard refuses a plaintext endpoint in production — so the
    // production profile terminates TLS in front of LocalStack rather than
    // having that guard relaxed.
    const prod = generated('production');
    expect(prod.get('AWS_ENDPOINT_URL')).toBe(TLS_AWS_ENDPOINT);
    expect(prod.get('NODE_EXTRA_CA_CERTS')).toBe(TLS_CA_PATH);
    expect(diagnose(prod)).toEqual([]);
  });

  it('development stays on plain http with no trust anchor', () => {
    const dev = generated('development');
    expect(dev.get('AWS_ENDPOINT_URL')).toBe('http://localstack:4566');
    expect(dev.get('NODE_EXTRA_CA_CERTS')).toBe('');
  });

  it('host-mode production trusts the bind-mounted CA, not the container path', () => {
    const prod = generated('production', 'host');
    expect(prod.get('AWS_ENDPOINT_URL')).toBe('https://localhost:8443');
    expect(prod.get('NODE_EXTRA_CA_CERTS')).toBe(TLS_CA_PATH_HOST);
    expect(diagnose(prod)).toEqual([]);
  });

  it('maps the CA path per addressing', () => {
    expect(tlsCaPathFor('compose')).toBe(TLS_CA_PATH);
    expect(tlsCaPathFor('host')).toBe(TLS_CA_PATH_HOST);
  });

  it('defaults to development addressing when mode is omitted', () => {
    expect(networkFor('compose').awsEndpoint).toBe('http://localstack:4566');
    expect(databaseUrl('core')).toContain('@pg-core:5432/core');
  });
});

describe('the doctor refuses every shortcut around production TLS', () => {
  it('refuses production on a plaintext endpoint', () => {
    const env = generated('production');
    env.set('AWS_ENDPOINT_URL', 'http://localstack:4566');
    expect(codesOf(env)).toContain('production_endpoint_not_tls');
  });

  it('refuses production with an untrusted CA', () => {
    const env = generated('production');
    env.set('NODE_EXTRA_CA_CERTS', '');
    expect(codesOf(env)).toContain('tls_ca_not_trusted');
  });

  it('refuses TLS verification being switched off entirely', () => {
    // The shortest path from "production mode will not connect" to a green
    // stack that proves nothing about transport security.
    const env = generated('production');
    env.set('NODE_TLS_REJECT_UNAUTHORIZED', '0');
    expect(codesOf(env)).toContain('tls_verification_disabled');
  });

  it('accepts the proxy hostname as local', () => {
    const env = generated('production');
    expect(codesOf(env)).not.toContain('aws_endpoint_not_local');
  });
});

describe('writeStackEnv addressing passthrough', () => {
  it('carries the addressing choice into the written file', () => {
    const written = new Map<string, string>();
    writeStackEnv(
      { mode: 'production', addressing: 'host', target: '.env.x', force: false },
      {
        exists: () => false,
        read: () => {
          throw new Error('not expected');
        },
        write: (path, contents) => written.set(path, contents),
      },
    );
    expect(written.get('.env.x')).toContain('STACK_ADDRESSING=host');
    expect(written.get('.env.x')).toContain('https://localhost:8443');
  });
});
