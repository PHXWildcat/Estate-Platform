import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseEnvFile } from '../src/doctor';
import { generateEnv, renderEnvFile } from '../src/generate-env';
import { bffProcessEnv, serviceProcessEnv, vaultWebProcessEnv } from '../src/service-env';
import { SERVICES, VAULT_ORIGIN } from '../src/topology';

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

  /**
   * The vault origin (M15). Held to the STRICTER standard the BFF is not: key
   * for key AND value for value, because its whole environment is four URLs
   * that decide which upstreams it may reach — there is no manifest-path
   * divergence to make room for.
   */
  it('vault-web: the compose block and vaultWebProcessEnv agree exactly', () => {
    const composeEnv = composeEnvironmentBlock(compose, 'vault-web');
    const resolved = new Map([...composeEnv].map(([key, value]) => [key, resolve(value, file)]));
    const mapped = vaultWebProcessEnv(file, { addressing: 'compose' });
    expect(Object.fromEntries([...resolved].sort())).toEqual(
      Object.fromEntries(Object.entries(mapped).sort()),
    );
  });

  it('vault-web carries NO credential of any kind, in either direction', () => {
    // The source and runtime halves live in apps/vault-web; this is the
    // DEPLOYMENT half. A credential cannot be held by a container that is never
    // handed one, and the compose block is where it would be handed one.
    const composeEnv = composeEnvironmentBlock(compose, 'vault-web');
    for (const key of composeEnv.keys()) {
      expect({ key, credentialShaped: /_INTERNAL_TOKEN$|KEY|SECRET/.test(key) }).toEqual({
        key,
        credentialShaped: false,
      });
    }
  });

  it('the BFF hands the browser the same vault origin the vault container serves', () => {
    // Two places name this origin — the BFF's runtime response and the web
    // image's build-time CSP — and a disagreement between them is a form POST
    // the browser refuses, which is exactly the class of defect the M8 PR5
    // BFF_URL bug was. Both are checked against the one constant.
    const bff = composeEnvironmentBlock(compose, 'bff');
    expect(bff.get('VAULT_ORIGIN')).toBe(VAULT_ORIGIN);
    const webBuildArg = /VAULT_ORIGIN:\s*'([^']+)'/.exec(compose);
    expect(webBuildArg?.[1]).toBe(VAULT_ORIGIN);
  });

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

  describe('scripts a container executes directly carry the git executable bit', () => {
    // THE BIT ONLY EXISTS IN GIT. Windows has no execute permission, so Docker
    // Desktop's bind mounts surface every file as executable and a Windows
    // BuildKit context tars everything 0755 — which is why a missing bit is
    // INVISIBLE on the machine that commits it and fatal on the Linux runner,
    // where checkout materializes git's real mode. That is exactly how the
    // first-ever CI run of stack.yml died: LocalStack's init runner hit
    // "[Errno 13] Permission denied" on 01-provision.sh (mode 100644), the
    // health marker never appeared, and the whole gate failed before one test
    // ran. aws-tls's ENTRYPOINT script had the same latent defect one
    // dependency further down.
    const REPO_ROOT = join(__dirname, '..', '..', '..');
    const gitMode = (path: string): string =>
      execFileSync('git', ['ls-files', '-s', '--', path], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
      }).split(' ')[0] ?? '(untracked)';

    it('every LocalStack ready.d hook is executable — the runner execs each file', () => {
      const dir = join(REPO_ROOT, 'infra', 'localstack', 'init');
      const hooks = readdirSync(dir);
      expect(hooks.length).toBeGreaterThan(0);
      for (const hook of hooks) {
        expect(`${hook}: ${gitMode(`infra/localstack/init/${hook}`)}`).toBe(`${hook}: 100755`);
      }
    });

    it('every exec-form ENTRYPOINT script copied from the repo is executable', () => {
      // COPY preserves the context file's mode, and exec-form ENTRYPOINT
      // execs the path directly — no shell to forgive a missing bit.
      const dockerDir = join(REPO_ROOT, 'infra', 'docker');
      const checked: string[] = [];
      for (const name of readdirSync(dockerDir).filter((n) => n.endsWith('.Dockerfile'))) {
        const dockerfile = readFileSync(join(dockerDir, name), 'utf8');
        const copies = new Map<string, string>();
        for (const copy of dockerfile.matchAll(/^COPY\s+(\S+)\s+(\S+)\s*$/gm)) {
          copies.set(copy[2] as string, copy[1] as string);
        }
        for (const entry of dockerfile.matchAll(/^ENTRYPOINT\s+\[\s*"([^"]+)"/gm)) {
          const source = copies.get(entry[1] as string);
          if (source !== undefined) {
            checked.push(source);
            expect(`${name} -> ${source}: ${gitMode(source)}`).toBe(`${name} -> ${source}: 100755`);
          }
        }
      }
      // The fence must be fencing something: aws-tls's entrypoint is the known
      // instance, and this assertion fails if a refactor stops the parser
      // seeing it (silent vacuity is how the anti-drop check almost shipped).
      expect(checked).toContain('infra/docker/aws-tls/entrypoint.sh');
    });
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
