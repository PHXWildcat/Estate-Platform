import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseEnvFile } from '../src/doctor';
import { generateEnv, renderEnvFile } from '../src/generate-env';
import { bffProcessEnv, serviceProcessEnv } from '../src/service-env';
import { SERVICES } from '../src/topology';

/**
 * THE TWO MAPPINGS MUST AGREE. docker-compose.stack.yml maps the flat
 * generated environment onto each container; `serviceProcessEnv` performs the
 * same mapping for host-mode processes. They are written in different
 * languages in different files, which is exactly how one of them gains a
 * variable the other lacks — and the symptom would be a service that behaves
 * differently in CI's fast gate than in the composed stack.
 *
 * This spec parses the compose file's environment blocks (scoped to this
 * repo's formatting conventions — two-space service indent, six-space
 * environment keys) and asserts key-for-key, value-for-value agreement after
 * substituting a generated env file into the YAML's ${VAR} references.
 *
 * The vault-crypto/credential-graph precedent: a source-scanning spec, not a
 * runtime dependency on a YAML parser.
 */

const COMPOSE_PATH = join(__dirname, '..', '..', '..', 'docker-compose.stack.yml');

function composeEnvironmentBlock(compose: string, service: string): Map<string, string> {
  const lines = compose.split(/\r?\n/);
  const start = lines.findIndex((line) => line === `  ${service}:`);
  if (start === -1) {
    throw new Error(`compose file has no service "${service}"`);
  }
  const env = new Map<string, string>();
  let inEnvironment = false;
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i] as string;
    if (/^ {2}\S/.test(line)) {
      break; // next service
    }
    // Two YAML spellings are in use: a block mapping, and the one-line flow
    // mapping the terse migrate jobs use. Both must be read, or a job written
    // in the other style silently escapes this fence.
    const flow = /^ {4}environment:\s*\{(.*)\}\s*$/.exec(line);
    if (flow) {
      for (const pair of (flow[1] as string).split(',')) {
        const entry = /^\s*([A-Z][A-Z0-9_]*):\s*(.*?)\s*$/.exec(pair);
        if (entry) {
          env.set(entry[1] as string, (entry[2] as string).replace(/^['"]|['"]$/g, ''));
        }
      }
      continue;
    }
    if (/^ {4}environment:/.test(line)) {
      inEnvironment = true;
      continue;
    }
    if (inEnvironment) {
      const entry = /^ {6}([A-Z][A-Z0-9_]*):\s*(.*)$/.exec(line);
      if (!entry) {
        if (/^ {4}\S/.test(line)) {
          inEnvironment = false;
        }
        continue;
      }
      const [, key, rawValue] = entry;
      env.set(key as string, (rawValue as string).replace(/^['"]|['"]$/g, ''));
    }
  }
  return env;
}

/** Resolve compose ${VAR} interpolation against a generated env file. */
function resolve(value: string, file: ReadonlyMap<string, string>): string {
  return value.replace(/\$\{([A-Z0-9_]+)\}/g, (_, name: string) => {
    const found = file.get(name);
    if (found === undefined) {
      throw new Error(`compose references ${name}, which the generator never writes`);
    }
    return found;
  });
}

describe('compose/supervisor mapping parity', () => {
  const compose = readFileSync(COMPOSE_PATH, 'utf8');
  const file = parseEnvFile(
    renderEnvFile(generateEnv({ mode: 'development', addressing: 'compose' }), {
      mode: 'development',
    }),
  );

  it.each(SERVICES.map((s) => [s.name] as const))(
    '%s: the compose block and serviceProcessEnv agree, key for key and value for value',
    (name) => {
      const service = SERVICES.find((s) => s.name === name)!;
      const composeEnv = composeEnvironmentBlock(compose, name);
      const resolved = new Map([...composeEnv].map(([key, value]) => [key, resolve(value, file)]));
      const mapped = serviceProcessEnv(service, file, { addressing: 'compose' });
      expect(Object.fromEntries([...resolved].sort())).toEqual(
        Object.fromEntries(Object.entries(mapped).sort()),
      );
    },
  );

  it('bff: same keys; the manifest path differs by design (mount vs repo file)', () => {
    const composeEnv = composeEnvironmentBlock(compose, 'bff');
    const mapped = bffProcessEnv(file, {
      addressing: 'compose',
      manifestPath: '/app/persisted-manifest.json',
    });
    expect([...composeEnv.keys()].sort()).toEqual(Object.keys(mapped).sort());
    expect(resolve(composeEnv.get('IDENTITY_URL') ?? '', file)).toBe(mapped['IDENTITY_URL']);
  });

  // THE BOOTSTRAP JOBS. They are the other half of the mapping and they were
  // outside this fence until the M8 security review: they run the same code
  // against the same clusters and buckets, but their environment blocks are
  // hand-written per job, so a migrator pointed at the wrong cluster or a
  // publish CLI addressing the bucket differently from the service would both
  // "succeed" and leave the stack subtly wrong.
  it.each(SERVICES.map((s) => [s.name] as const))(
    'migrate-%s migrates the very cluster the service reads',
    (name) => {
      const service = SERVICES.find((s) => s.name === name)!;
      const job = composeEnvironmentBlock(compose, `migrate-${name}`);
      const mapped = serviceProcessEnv(service, file, { addressing: 'compose' });
      expect([...job.keys()]).toEqual(['DATABASE_URL']);
      expect(resolve(job.get('DATABASE_URL') ?? '', file)).toBe(mapped['DATABASE_URL']);
    },
  );

  it('seed-templates addresses the object store exactly as documents does', () => {
    // The publish CLI's own comment: "templates and content share one bucket,
    // so a CLI that reached it differently would publish blobs the service
    // could not read back."
    const job = composeEnvironmentBlock(compose, 'seed-templates');
    const documents = serviceProcessEnv(
      SERVICES.find((s) => s.name === 'documents')!,
      file,
      {
        addressing: 'compose',
      },
    );
    for (const key of [
      'DATABASE_URL',
      'OBJECT_STORE_MODE',
      'OBJECT_STORE_BUCKET',
      'AWS_REGION',
      'AWS_ENDPOINT_URL',
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'NODE_EXTRA_CA_CERTS',
      'KAFKA_BROKERS',
    ]) {
      expect(`${key}=${resolve(job.get(key) ?? '(absent)', file)}`).toBe(
        `${key}=${documents[key] ?? '(absent)'}`,
      );
    }
    // NODE_ENV is the one deliberate divergence: the M4 guard refuses
    // placeholder legalReview in production and the exemplars ARE
    // placeholders, so seeding runs as development even in the production
    // profile. docs/05 says loudly that generation working there is therefore
    // not evidence of the legal gate.
    expect(job.get('NODE_ENV')).toBe('development');
  });

  it('provision-topics reaches the same broker the services produce to', () => {
    const job = composeEnvironmentBlock(compose, 'provision-topics');
    expect([...job.keys()]).toEqual(['KAFKA_BROKERS']);
    expect(resolve(job.get('KAFKA_BROKERS') ?? '', file)).toBe(file.get('KAFKA_BROKERS'));
  });

  it('every ${VAR} the compose file references is one the generator writes', () => {
    // Comments describe variables generically; only real YAML values count.
    const withoutComments = compose
      .split(/\r?\n/)
      .filter((line) => !line.trimStart().startsWith('#'))
      .join('\n');
    for (const reference of withoutComments.matchAll(/\$\{([A-Z0-9_]+)\}/g)) {
      expect(`${reference[1] as string}: ${String(file.has(reference[1] as string))}`).toBe(
        `${reference[1] as string}: true`,
      );
    }
  });
});
