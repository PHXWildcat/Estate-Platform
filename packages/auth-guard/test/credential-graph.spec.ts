/**
 * THE CREDENTIAL GRAPH, ENFORCED.
 *
 * `credential-graph.ts` declares which service may hold which service-to-service
 * secret. This spec is what makes that declaration binding: it reads the repo's
 * source and fails the build when the code and the table disagree.
 *
 * It scans files rather than importing them, exactly like
 * `packages/vault-crypto/test/zero-dependency.spec.ts`. A `readFileSync` creates
 * no package.json edge, no import, no build ordering — which matters here
 * because every service depends on `@estate/auth-guard`, so this package can
 * never depend on them back. The complementary RUNTIME half (does a service
 * actually absorb only its granted credentials?) therefore lives in each
 * service's own `test/config.spec.ts`; the last check below proves those have
 * not been quietly deleted.
 *
 * Every scan carries an anti-vacuity assertion. A fence that silently matches
 * nothing is worse than no fence, because the decision log then records that
 * the graph is machine-checked when it is not — which is the same
 * prose-vs-reality failure the graph exists to prevent.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

import { routeDecorator } from './nest-routes';
import { stripComments } from './source-text';

import {
  credentialEnvVarsFor,
  credentialSentinel,
  envVarPrefixFor,
  inboundCredentialsFor,
  outboundCredentialsFor,
  SERVICE_CREDENTIAL_GRAPH,
  SERVICE_NAMES,
  type ServiceName,
} from '../src/credential-graph';

const REPO_ROOT = join(__dirname, '..', '..', '..');
const SERVICES_DIR = join(REPO_ROOT, 'apps', 'services');

/** Repo-relative, forward-slashed, so expectations read the same on Windows. */
function repoPath(absolute: string): string {
  return relative(REPO_ROOT, absolute).split(sep).join('/');
}

function walk(dir: string): string[] {
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      // dist is build output: scanning it would double-count and go stale.
      return entry === 'dist' || entry === 'node_modules' ? [] : walk(full);
    }
    return full.endsWith('.ts') ? [full] : [];
  });
}

/** Every first-party `src` TypeScript file: the whole surface a credential could hide in. */
function allSourceFiles(): string[] {
  const roots = [join(REPO_ROOT, 'apps'), join(REPO_ROOT, 'packages')];
  return roots
    .flatMap((root) =>
      existsSync(root)
        ? readdirSync(root).flatMap((entry) => {
            const pkg = join(root, entry);
            if (!statSync(pkg).isDirectory()) {
              return [];
            }
            // apps/services/* nests one level deeper than apps/bff, apps/web.
            return entry === 'services'
              ? readdirSync(pkg).flatMap((svc) => walk(join(pkg, svc, 'src')))
              : walk(join(pkg, 'src'));
          })
        : [],
    )
    .sort();
}

function read(file: string): string {
  return stripComments(readFileSync(file, 'utf8'));
}

const SOURCE_FILES = allSourceFiles();
const GRAPH_ENV_VARS = SERVICE_CREDENTIAL_GRAPH.map((edge) => edge.envVar);

/** This module is the declaration itself, so it names every variable by design. */
const GRAPH_MODULE = 'packages/auth-guard/src/credential-graph.ts';

function serviceSrc(service: ServiceName, file: string): string {
  return join(SERVICES_DIR, service, 'src', file);
}

/** `internalApiToken: e.IDENTITY_INTERNAL_TOKEN ?? ''` → { internalApiToken: 'IDENTITY_…' }. */
function configFieldToEnvVar(service: ServiceName): Record<string, string> {
  const source = read(serviceSrc(service, 'config.ts'));
  const mapping: Record<string, string> = {};
  for (const match of source.matchAll(/(\w+)\s*:\s*e\.([A-Z][A-Z0-9_]*)\s*\?\?/g)) {
    const [, field, envVar] = match;
    if (field && envVar) {
      mapping[field] = envVar;
    }
  }
  return mapping;
}

describe('the credential graph is internally coherent', () => {
  it('declares credentials to check', () => {
    // Vacuity guard: an emptied table would satisfy every other test here.
    expect(SERVICE_CREDENTIAL_GRAPH.length).toBeGreaterThanOrEqual(3);
  });

  it.each(SERVICE_CREDENTIAL_GRAPH)('$envVar is named for its callee', (edge) => {
    // Rule 1. The name is the control: a credential named for its CALLER is
    // how M7 ended up with one secret opening four services. A callee with
    // more than one internal surface qualifies the middle of the name, so the
    // rule is prefix + suffix rather than exact equality.
    expect(edge.envVar.startsWith(envVarPrefixFor(edge.callee))).toBe(true);
    expect(edge.envVar.endsWith('_INTERNAL_TOKEN')).toBe(true);
  });

  it('never declares the same env var twice', () => {
    // Two edges sharing a variable would be the split-in-name-only failure:
    // separate holders on paper, one secret in every deployment.
    const vars = SERVICE_CREDENTIAL_GRAPH.map((edge) => edge.envVar);
    expect(new Set(vars).size).toBe(vars.length);
  });

  it.each(SERVICE_NAMES)('%s has at most one credential per guard token', (service) => {
    // A guard binds exactly ONE token, so two edges on one callee are only
    // really separate if they are enforced by different guards. Same token on
    // two edges would mean one guard admitting both credentials' holders —
    // the over-grant this split exists to remove, wearing a disguise.
    const tokens = inboundCredentialsFor(service).map((edge) => edge.guard.token);
    expect(new Set(tokens).size).toBe(tokens.length);
    const classes = inboundCredentialsFor(service).map((edge) => edge.guard.className);
    expect(new Set(classes).size).toBe(classes.length);
  });

  it.each(SERVICE_CREDENTIAL_GRAPH)('$envVar is not held by its own callee', (edge) => {
    expect(edge.holders).not.toContain(edge.callee);
  });

  it.each(SERVICE_CREDENTIAL_GRAPH)('$envVar names only real services', (edge) => {
    expect(SERVICE_NAMES).toContain(edge.callee);
    for (const holder of edge.holders) {
      expect(SERVICE_NAMES).toContain(holder);
    }
  });

  it('gives every credential a distinct variable and a stated surface', () => {
    expect(new Set(GRAPH_ENV_VARS).size).toBe(GRAPH_ENV_VARS.length);
    for (const edge of SERVICE_CREDENTIAL_GRAPH) {
      expect(edge.opens.length).toBeGreaterThan(0);
      expect(edge.grants.length).toBeGreaterThan(40);
    }
  });

  it('uses sentinels that cannot be confused with one another', () => {
    // credentialsHeldIn matches by substring, which is only sound if no
    // sentinel contains another — otherwise a service holding one credential
    // would report holding two, and the equality assertions would be nonsense.
    const sentinels = GRAPH_ENV_VARS.map(credentialSentinel);
    for (const outer of sentinels) {
      expect(outer.length).toBeGreaterThanOrEqual(32);
      for (const inner of sentinels) {
        if (outer !== inner) {
          expect(outer).not.toContain(inner);
        }
      }
    }
  });
});

describe('the graph covers every service that exists', () => {
  it('lists exactly the services on disk', () => {
    // The highest-value check here. Everything else is scoped to SERVICE_NAMES,
    // so a hand-maintained list that misses a new service would quietly narrow
    // the whole fence — a ninth service could hold identity's account-lock key
    // and every test below would still pass.
    const onDisk = readdirSync(SERVICES_DIR)
      .filter((entry) => existsSync(join(SERVICES_DIR, entry, 'src', 'config.ts')))
      .sort();
    expect(onDisk.length).toBeGreaterThanOrEqual(8);
    expect([...SERVICE_NAMES].sort()).toEqual(onDisk);
  });
});

describe('no credential is mentioned anywhere the graph does not allow', () => {
  it('scans the real source tree', () => {
    expect(SOURCE_FILES.length).toBeGreaterThan(50);
  });

  it.each(SERVICE_CREDENTIAL_GRAPH)('$envVar appears only where it belongs', (edge) => {
    // A credential env var may be named by exactly three kinds of file: the
    // graph module itself, the callee's config (which expects it), and each
    // holder's config (which presents it). Anything else — an app.module
    // reading process.env directly, a client with a fallback default, a second
    // service quietly adding the variable — is a graph change in disguise.
    const allowed = [
      GRAPH_MODULE,
      repoPath(serviceSrc(edge.callee, 'config.ts')),
      ...edge.holders.map((holder) => repoPath(serviceSrc(holder, 'config.ts'))),
    ].sort();

    const actual = SOURCE_FILES.filter((file) =>
      new RegExp(`\\b${edge.envVar}\\b`).test(read(file)),
    )
      .map(repoPath)
      .sort();

    expect(actual).toEqual(allowed);
  });

  it('finds no *_INTERNAL_TOKEN variable that the graph does not declare', () => {
    const discovered = new Set<string>();
    for (const file of SOURCE_FILES) {
      for (const match of read(file).matchAll(/\b([A-Z][A-Z0-9_]*_INTERNAL_TOKEN)\b/g)) {
        if (match[1]) {
          discovered.add(match[1]);
        }
      }
    }
    expect(discovered.size).toBeGreaterThanOrEqual(3);
    expect([...discovered].sort()).toEqual([...GRAPH_ENV_VARS].sort());
  });
});

describe('the guard mechanism agrees with the graph', () => {
  /** Every credential DI token any edge names, e.g. SERVICE_CREDENTIAL. */
  const GUARD_TOKENS = [...new Set(SERVICE_CREDENTIAL_GRAPH.map((e) => e.guard.token))];

  /** Services whose app.module binds ANY credential token. */
  const providers = SERVICE_NAMES.filter((service) =>
    GUARD_TOKENS.some((token) =>
      new RegExp(`provide:\\s*${token}\\b`).test(read(serviceSrc(service, 'app.module.ts'))),
    ),
  );

  it('is anchored on something that exists', () => {
    expect(providers.length).toBeGreaterThanOrEqual(3);
    expect(GUARD_TOKENS).toContain('SERVICE_CREDENTIAL');
  });

  it('lets exactly the callees expect a credential', () => {
    // Anchored on the MECHANISM, not on variable names: a new internal route
    // authenticated by a differently-named secret still has to bind one of
    // these tokens, and is caught here even though no *_INTERNAL_TOKEN
    // variable was ever added.
    const callees = [...new Set(SERVICE_CREDENTIAL_GRAPH.map((edge) => edge.callee))].sort();
    expect([...providers].sort()).toEqual(callees);
  });

  it.each(SERVICE_CREDENTIAL_GRAPH)(
    '$callee binds $envVar exactly once, under its own guard token',
    (edge) => {
      const module = read(serviceSrc(edge.callee, 'app.module.ts'));
      // A second binding of the SAME token would be a second inbound
      // credential hiding behind the first — the M7 aliasing shape, one level
      // down. (Two bindings of DIFFERENT tokens is the legitimate split, and
      // the per-service token-uniqueness check above keeps it honest.)
      const binding = new RegExp(`provide:\\s*${edge.guard.token}\\b`, 'g');
      expect(module.match(binding)).toHaveLength(1);

      const factory = new RegExp(
        `provide:\\s*${edge.guard.token}\\b[\\s\\S]{0,400}?config\\.(\\w+)`,
      ).exec(module);
      expect(factory).not.toBeNull();
      const field = (factory as RegExpExecArray)[1] as string;
      expect(configFieldToEnvVar(edge.callee)[field]).toBe(edge.envVar);
    },
  );

  it.each(SERVICE_CREDENTIAL_GRAPH)('$callee provides the guard class $envVar names', (edge) => {
    // The class must actually be a provider, or Nest cannot construct it and
    // the route would fail closed at runtime rather than at build time.
    const module = read(serviceSrc(edge.callee, 'app.module.ts'));
    expect(new RegExp(`\\b${edge.guard.className}\\b`).test(module)).toBe(true);
  });

  it.each(SERVICE_NAMES)('%s presents only credentials the graph grants it', (service) => {
    // Outbound side: every credential a service hands to a peer client must
    // draw on a config field whose env var this service is allowed to hold —
    // and never on its own inbound one. That last clause is rule 2, and it is
    // the exact line the M7 collapse crossed.
    //
    // THE PATTERN COVERS BOTH WIRING SHAPES, and the second one is why the M14
    // review flagged this loop. It used to match only
    // `(?:serviceCredential|credential)\s*:\s*config\.X` — then M14 changed every
    // notifications client to the per-capability object
    // `credentials: { send: config.X, status: config.Y }`. `credentials:` does
    // not match `credential:` (an `s` sits in between) and the inner keys are
    // `send`/`recipients`/`verification`/`status`, so the scan silently fell to
    // ZERO matches for identity, profile and notifications and covered none of
    // the seven notifications presentations. A fence that stops matching is
    // worse than one that never existed, because the decision log goes on
    // citing it.
    const module = read(serviceSrc(service, 'app.module.ts'));
    const fieldToEnv = configFieldToEnvVar(service);
    const granted = credentialEnvVarsFor(service);
    const inboundVars = inboundCredentialsFor(service).map((edge) => edge.envVar);

    // Any `<key>: config.<field>` whose field is a known credential field. This
    // is deliberately keyed on the CONFIG FIELD rather than on the property
    // name: a property name is a caller's choice and can be renamed into
    // invisibility (which is exactly what happened), whereas the set of config
    // fields that hold credentials is derived from the graph.
    // Only CREDENTIAL env vars: `configFieldToEnvVar` maps every config field,
    // and a service legitimately wires plenty of non-secrets (base URLs, modes)
    // into the same client factories.
    const credentialVars = new Set(SERVICE_CREDENTIAL_GRAPH.map((edge) => edge.envVar));
    const wired = [...module.matchAll(/[A-Za-z_$][\w$]*\s*:\s*config\.(\w+)/g)]
      .map((match) => fieldToEnv[match[1] as string])
      .filter((envVar): envVar is string => envVar !== undefined && credentialVars.has(envVar));

    for (const envVar of wired) {
      expect(granted).toContain(envVar);
      expect(inboundVars).not.toContain(envVar);
    }

    // ANTI-VACUITY. The file header claims every scan carries one; this loop
    // did not, which is why its fall to zero matches was silent. A service the
    // graph grants an outbound credential MUST be observed wiring one.
    if (outboundCredentialsFor(service).length > 0) {
      expect(wired.length).toBeGreaterThan(0);
    }
  });
});

describe('every guarded route is declared in the graph', () => {
  /**
   * Routes of controller classes carrying a class-level
   * `@UseGuards(<guardClass>)`. Split per `@Controller(...)` because one file
   * can hold both a bearer-guarded and a credential-guarded controller —
   * settlement's admin.controller.ts does exactly that, and since the M9
   * review notifications' internal.controller.ts holds two controllers under
   * two DIFFERENT credential guards.
   *
   * `guardClass` is a parameter rather than a constant because the guard class
   * is what partitions a callee's routes between its credentials: attributing
   * every guarded route to one edge would let the recipient route be
   * re-merged under the send credential without any check firing.
   */
  function guardedRoutes(service: ServiceName, guardClass: string): string[] {
    const dir = join(SERVICES_DIR, service, 'src');
    const routes: string[] = [];
    const guarded = new RegExp(`@UseGuards\\([^)]*\\b${guardClass}\\b`);
    for (const file of walk(dir)) {
      const source = read(file);
      const chunks = source.split(/(?=@Controller\()/).slice(1);
      for (const chunk of chunks) {
        const header = chunk.slice(0, chunk.indexOf('export class'));
        if (!guarded.test(header)) {
          continue;
        }
        const prefix = /@Controller\(\s*'([^']*)'/.exec(chunk)?.[1] ?? '';
        // DERIVED from Nest, not hand-listed. This alternation used to name
        // five verbs; a handler on any of the other eleven derived no route at
        // all, so `guardedRoutes` under-collected AND `edge.opens` never
        // demanded it — invisible in both directions, with no refusal.
        for (const m of chunk.matchAll(routeDecorator())) {
          const segment = m[2] ? `${prefix}/${m[2]}` : prefix;
          routes.push(`${(m[1] as string).toUpperCase()} /${segment}`);
        }
      }
    }
    return routes.sort();
  }

  /** Every credential-guarded route of a service, whichever guard carries it. */
  function allGuardedRoutes(service: ServiceName): string[] {
    const classes = [...new Set(SERVICE_CREDENTIAL_GRAPH.map((e) => e.guard.className))];
    return [...new Set(classes.flatMap((cls) => guardedRoutes(service, cls)))].sort();
  }

  it('finds the guarded controllers it is meant to be checking', () => {
    const total = SERVICE_NAMES.flatMap(allGuardedRoutes);
    expect(total.length).toBeGreaterThanOrEqual(4);
  });

  it.each(SERVICE_CREDENTIAL_GRAPH)('$callee opens exactly what $envVar says', (edge) => {
    // Keeps `opens` — and so the `grants` sentence a reviewer judges `holders`
    // by — from going stale the moment someone adds a route to an existing
    // internal controller. Scoped to THIS edge's guard, so moving a route
    // between a callee's two credentials is a visible change to both lists.
    expect(guardedRoutes(edge.callee, edge.guard.className)).toEqual([...edge.opens].sort());
  });

  it('declares every credential-guarded route in the repo exactly once', () => {
    // Cross-check against the per-edge assertion above: a route guarded by a
    // class no edge names would be invisible to it, and a route claimed by two
    // edges would mean two credentials opening one capability.
    const declared = SERVICE_CREDENTIAL_GRAPH.flatMap((edge) => [...edge.opens]).sort();
    const found = SERVICE_NAMES.flatMap(allGuardedRoutes).sort();
    expect(found).toEqual([...new Set(declared)].sort());
    expect(declared.length).toBe(new Set(declared).size);
  });

  it.each(SERVICE_NAMES)('%s has no guarded route unless the graph says so', (service) => {
    if (inboundCredentialsFor(service).length === 0) {
      expect(allGuardedRoutes(service)).toEqual([]);
    }
  });
});

describe('the runtime half has not been dropped', () => {
  it.each(SERVICE_NAMES)('%s asserts its own credential holdings', (service) => {
    // This spec can prove what the source SAYS; only the service's own suite
    // can prove what its config DOES, because a package every service depends
    // on cannot import them back. If that assertion disappears, half the fence
    // disappears silently — so its absence fails here.
    //
    // Imports are stripped before matching, and the service's own name is
    // required inside the call. Mutation-testing this fence caught the naive
    // version passing after the whole assertion was deleted, because the import
    // line still mentioned the identifiers — a fence that survives the deletion
    // of what it guards is the vacuity failure this file exists to avoid. The
    // name check additionally rejects a block copy-pasted from another service,
    // which would assert the wrong grant against the right config.
    const spec = join(SERVICES_DIR, service, 'test', 'config.spec.ts');
    expect(existsSync(spec)).toBe(true);
    const body = readFileSync(spec, 'utf8').replace(/^import[\s\S]*?from\s*'[^']*';/gm, '');
    expect(body).toContain('credentialsHeldIn(config)');
    expect(body).toContain(`credentialEnvVarsFor('${service}')`);
  });
});
