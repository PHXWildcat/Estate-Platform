/**
 * THE SESSION-AUDIENCE FENCE (M15).
 *
 * `CallerGuard` enforces "this service admits these audiences". It cannot say
 * which services SHOULD, and that is the security property — the whole point of
 * the audience is that a leaked vault handoff reaches the vault service and
 * nothing else, which is false the moment a second service quietly binds
 * `ALLOWED_SESSION_AUDIENCES`. So the table in `session.ts` is checked against
 * the source rather than believed, in BOTH directions.
 *
 * The mechanism is `credential-graph.spec.ts`'s, for its reason: every service
 * depends on this package, so a suite here can never import services back
 * (workspace cycle). `readFileSync` creates no package edge — the
 * vault-crypto zero-dependency-fence precedent.
 *
 * Anchored on the DI TOKEN NAME, not on a service name or a comment, because a
 * binding is the only thing that actually widens the guard.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { AUDIENCE_ADMITTERS, SESSION_AUDIENCES } from '../src/session';

const SERVICES_DIR = join(__dirname, '..', '..', '..', 'apps', 'services');
const TOKEN = 'ALLOWED_SESSION_AUDIENCES';

function serviceNames(): string[] {
  return readdirSync(SERVICES_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => existsSync(join(SERVICES_DIR, name, 'src', 'config.ts')))
    .sort();
}

/** Every .ts file under a service's src/, recursively. */
function sourceFiles(service: string): string[] {
  const root = join(SERVICES_DIR, service, 'src');
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.name.endsWith('.ts')) out.push(path);
    }
  };
  walk(root);
  return out;
}

/** Comments discuss the token by name; only a real `provide:` binding counts. */
function bindsToken(service: string): boolean {
  return sourceFiles(service).some((file) =>
    new RegExp(`provide:\\s*${TOKEN}\\b`).test(readFileSync(file, 'utf8')),
  );
}

/** The audience list a service binds, read out of its `useValue`. */
function boundAudiences(service: string): string[] {
  for (const file of sourceFiles(service)) {
    const match = new RegExp(`provide:\\s*${TOKEN}\\s*,\\s*useValue:\\s*\\[([^\\]]*)\\]`, 's').exec(
      readFileSync(file, 'utf8'),
    );
    if (match) {
      return [...(match[1] ?? '').matchAll(/'([^']+)'/g)].map((m) => m[1] ?? '').sort();
    }
  }
  return [];
}

describe('session-audience grants match the declaration', () => {
  const services = serviceNames();

  it('finds the services it is meant to be checking', () => {
    // Guards against the scan silently matching nothing and passing vacuously
    // — the failure mode the credential-graph anti-drop check was caught in.
    expect(services.length).toBeGreaterThan(5);
    expect(services).toContain('vault');
  });

  it('declares admitters only for real, non-default audiences', () => {
    for (const audience of Object.keys(AUDIENCE_ADMITTERS)) {
      expect(SESSION_AUDIENCES).toContain(audience);
      expect(audience).not.toBe('account');
    }
  });

  it('every declared admitter actually binds the token', () => {
    for (const [audience, admitters] of Object.entries(AUDIENCE_ADMITTERS)) {
      for (const service of admitters) {
        expect(services).toContain(service);
        expect(boundAudiences(service)).toContain(audience);
      }
    }
  });

  it('NO UNDECLARED SERVICE binds the token', () => {
    const declared = new Set(Object.values(AUDIENCE_ADMITTERS).flat());
    for (const service of services) {
      if (declared.has(service)) continue;
      expect({ service, binds: bindsToken(service) }).toEqual({ service, binds: false });
    }
  });

  it('an admitter binds no audience beyond what it is granted, plus account', () => {
    // The reverse direction: vault may not quietly widen its own useValue to a
    // third audience while the table still reads `{ vault: ['vault'] }`.
    for (const service of new Set(Object.values(AUDIENCE_ADMITTERS).flat())) {
      const granted = Object.entries(AUDIENCE_ADMITTERS)
        .filter(([, admitters]) => admitters.includes(service))
        .map(([audience]) => audience);
      expect(boundAudiences(service).sort()).toEqual(['account', ...granted].sort());
    }
  });

  it('vault is the only service admitting the vault audience', () => {
    // Stated explicitly as well as derived: this one sentence is the milestone's
    // claim, and a table edit that broke it should fail a test that NAMES it.
    expect(AUDIENCE_ADMITTERS.vault).toEqual(['vault']);
  });
});
