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
