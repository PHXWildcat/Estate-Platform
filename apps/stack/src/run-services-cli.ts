import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { join } from 'node:path';
import { parseEnvFile } from './doctor';
import { OPERATOR_WEB_PORT, VAULT_WEB_PORT } from './topology';
import {
  bffProcessEnv,
  plannedServices,
  scrubbedBaseEnv,
  serviceProcessEnv,
  operatorWebProcessEnv,
  vaultWebProcessEnv,
} from './service-env';

/**
 * Host-mode supervisor: run the stack's node processes from their built dist,
 * against infra containers reached through their published ports.
 *
 *   node dist/run-services-cli.js [envFile] [--repo-root <dir>] [--no-bff]
 *
 * This is CI's fast gate (no image builds) and the local inner loop. It
 * REFUSES a compose-addressed env file: those URLs name container hosts that
 * do not resolve from the host, and every service would boot and then fail
 * per request — the slowest possible way to discover the mistake.
 *
 * Exits non-zero the moment any child dies. There is deliberately no restart:
 * a service that cannot stay up is a finding, not a nuisance.
 */

const PORT_DEADLINE_MS = 90_000;
const PORT_POLL_MS = 500;

function waitForPort(port: number, deadlineMs: number): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  return new Promise((resolve, reject) => {
    const attempt = (): void => {
      const socket = connect(port, '127.0.0.1');
      socket.once('connect', () => {
        socket.destroy();
        resolve();
      });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) {
          reject(new Error(`port ${port} not listening after ${deadlineMs}ms`));
          return;
        }
        setTimeout(attempt, PORT_POLL_MS);
      });
    };
    attempt();
  });
}

function prefixed(name: string, child: ChildProcess): void {
  for (const stream of [child.stdout, child.stderr] as const) {
    let buffer = '';
    stream?.setEncoding('utf8');
    stream?.on('data', (chunk: string) => {
      buffer += chunk;
      let index = buffer.indexOf('\n');
      while (index !== -1) {
        process.stdout.write(`[${name}] ${buffer.slice(0, index)}\n`);
        buffer = buffer.slice(index + 1);
        index = buffer.indexOf('\n');
      }
    });
  }
}

async function main(argv: readonly string[]): Promise<number> {
  const positional = argv.filter((a) => !a.startsWith('--'));
  const envFile = positional[0] ?? process.env['STACK_ENV_FILE'] ?? '.env.stack';
  const rootArg = argv.indexOf('--repo-root');
  const repoRoot = rootArg === -1 ? process.cwd() : (argv[rootArg + 1] ?? process.cwd());
  const withBff = !argv.includes('--no-bff');

  if (!existsSync(envFile)) {
    process.stderr.write(`${envFile} not found — run \`pnpm stack:env -- --addressing host\`\n`);
    return 1;
  }
  const env = parseEnvFile(readFileSync(envFile, 'utf8'));
  if (env.get('STACK_ADDRESSING') !== 'host') {
    process.stderr.write(
      `${envFile} is addressed for '${env.get('STACK_ADDRESSING') ?? 'compose'}', not 'host'. ` +
        'Container hostnames do not resolve from the host; every service would boot and then fail per request. ' +
        'Regenerate with --addressing host.\n',
    );
    return 1;
  }

  const base = scrubbedBaseEnv(process.env);
  const children = new Map<string, ChildProcess>();
  let shuttingDown = false;
  let failure: string | null = null;

  const stopAll = (): void => {
    shuttingDown = true;
    for (const child of children.values()) {
      child.kill('SIGTERM');
    }
  };
  process.once('SIGINT', stopAll);
  process.once('SIGTERM', stopAll);

  const launch = (name: string, entry: string, processEnv: Record<string, string>): void => {
    const child = spawn(process.execPath, [join(repoRoot, entry)], {
      env: { ...base, ...processEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    prefixed(name, child);
    child.once('exit', (code) => {
      children.delete(name);
      if (!shuttingDown) {
        failure = `${name} exited with code ${String(code)} before shutdown`;
        process.stderr.write(`${failure}\n`);
        stopAll();
      }
    });
    children.set(name, child);
  };

  const options = {
    addressing: 'host' as const,
    manifestPath: join(repoRoot, 'apps', 'web', 'persisted-manifest.json'),
  };
  const services = plannedServices(env);
  for (const service of services) {
    launch(
      service.name,
      `apps/services/${service.name}/dist/main.js`,
      serviceProcessEnv(service, env, options),
    );
  }
  if (withBff) {
    launch('bff', 'apps/bff/dist/main.js', bffProcessEnv(env, options));
    // The ISOLATED VAULT ORIGIN (M15) is edge tier like the BFF — no cluster,
    // no migration, no credential — so it rides the same flag. Started here
    // rather than in `plannedServices` because that list is derived from
    // `apps/services/*`, which the vault origin is deliberately NOT: keeping it
    // out of that directory is what keeps it out of `SERVICE_NAMES` and the
    // credential graph, where a service is presumed to hold a secret.
    launch('vault-web', 'apps/vault-web/dist/main.js', vaultWebProcessEnv(env, options));
    // The ISOLATED OPERATOR ORIGIN (M21 PR3a) rides the same flag for the same
    // reasons: edge tier, no cluster, no migration, no credential, and
    // deliberately outside `apps/services/` so `SERVICE_NAMES` and the
    // credential graph never absorb it.
    launch('operator-web', 'apps/operator-web/dist/main.js', operatorWebProcessEnv(env, options));
  }

  const ports = [
    ...services.filter((s) => s.port !== null).map((s) => s.port as number),
    ...(withBff ? [4000, VAULT_WEB_PORT, OPERATOR_WEB_PORT] : []),
  ];
  try {
    await Promise.all(ports.map((port) => waitForPort(port, PORT_DEADLINE_MS)));
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : 'startup failed'}\n`);
    stopAll();
    return 1;
  }
  if (failure) {
    return 1;
  }
  process.stdout.write(
    `stack up: ${services.map((s) => s.name).join(', ')}${withBff ? ', bff, vault-web, operator-web' : ''}\n`,
  );

  // Stay resident until a signal or a child death.
  return new Promise<number>((resolve) => {
    const poll = setInterval(() => {
      if (failure) {
        clearInterval(poll);
        resolve(1);
      } else if (shuttingDown && children.size === 0) {
        clearInterval(poll);
        resolve(0);
      }
    }, 250);
    poll.unref();
    process.once('exit', () => clearInterval(poll));
  });
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : 'supervisor failed'}\n`);
    process.exitCode = 1;
  });
