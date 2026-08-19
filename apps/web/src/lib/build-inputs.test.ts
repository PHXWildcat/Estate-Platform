/**
 * EVERY BUILD-TIME INPUT `next.config.ts` READS ACTUALLY REACHES THE BUILD.
 *
 * `csp.test.ts` already pins that the config READS `VAULT_ORIGIN` and
 * `OPERATOR_ORIGIN`, and its comment says the values are build-time "like
 * BFF_URL, and for the same reason". Both halves of that sentence were true and
 * the plumbing under it was not: the value never arrived, at either of the two
 * layers that carry it.
 *
 *   * `infra/docker/web.Dockerfile` declared `ARG BFF_URL` and no ARG for
 *     either origin, while `docker-compose.stack.yml` has passed both as build
 *     args since M15 and M21 PR3a. Docker warns about an unconsumed build arg
 *     and carries on.
 *   * `turbo.json`'s build task declared `env: ["BFF_URL", "NEXT_STANDALONE"]`,
 *     and Turbo 2 runs tasks in STRICT env mode, so even with an ARG the
 *     variable is stripped before `next build` sees it.
 *
 * MEASURED, WITH A CONTROL, before any of it was changed: one `turbo run build
 * --filter=@estate/web --force` with `VAULT_ORIGIN`/`OPERATOR_ORIGIN` set to
 * probe values left ZERO files under `.next` containing either, while the same
 * command with `BFF_URL=http://probe-bff.example:9999` — the one variable that
 * WAS declared — put it straight into `routes-manifest.json`. Same build, same
 * mechanism, and the difference is only the declaration.
 *
 * What that cost: `form-action 'self' ${vaultOrigin} ${operatorOrigin}` is the
 * only directive permitting the top-level form POST that opens the vault origin
 * and the operator console, so any deployment whose origins are not literally
 * the localhost defaults would have shipped an app whose own browser refuses
 * both handoffs. Latent only because nothing is deployed and the compose values
 * happen to equal the fallbacks.
 *
 * So this fence is DERIVED, not a list: the names come out of `next.config.ts`
 * itself, and each must carry an explicit classification saying how it is meant
 * to reach the build. A new build-time input arrives classified and wired, or
 * this goes red. `apps/vault-extension/test/turbo-env.spec.ts` is the same idea
 * for the package that hit this first; the app, where the defect actually was,
 * had nothing.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const WEB_ROOT = join(__dirname, '..', '..');
const REPO_ROOT = join(WEB_ROOT, '..', '..');

const nextConfig = readFileSync(join(WEB_ROOT, 'next.config.ts'), 'utf8');
const dockerfile = readFileSync(join(REPO_ROOT, 'infra', 'docker', 'web.Dockerfile'), 'utf8');
const compose = readFileSync(join(REPO_ROOT, 'docker-compose.stack.yml'), 'utf8');

/**
 * How a variable is meant to reach `next build`, as DATA with a reason each.
 *
 *   deployment — varies per environment, so the image must be able to receive
 *                it: declared to turbo, and an ARG in the Dockerfile.
 *   fixed      — the image decides it and no deployment may vary it: declared
 *                to turbo, set as ENV, and deliberately NOT an ARG.
 *   ambient    — the toolchain sets it; neither declared nor received.
 *
 * The distinction is the point. A `deployment` variable with no ARG is the
 * defect this file exists for; a `fixed` one that grows an ARG has quietly
 * become deployment-varying and wants an argument rather than a commit.
 */
const BUILD_INPUTS: ReadonlyArray<{
  name: string;
  kind: 'deployment' | 'fixed' | 'ambient';
  because: string;
}> = [
  {
    name: 'BFF_URL',
    kind: 'deployment',
    because:
      'serialised into the routes manifest as the /graphql rewrite target; ' +
      'M8 PR5 found the image proxying to itself when it was undeclared',
  },
  {
    name: 'VAULT_ORIGIN',
    kind: 'deployment',
    because: "named in form-action so the browser permits the M15 vault handoff's form POST",
  },
  {
    name: 'OPERATOR_ORIGIN',
    kind: 'deployment',
    because: 'named in form-action so the browser permits the M21 PR3a operator handoff',
  },
  {
    name: 'NEXT_STANDALONE',
    kind: 'fixed',
    because:
      'the image always wants the traced server bundle; it is a flag only ' +
      'because emitting it needs symlinks, which Windows workstations refuse',
  },
  {
    name: 'NODE_ENV',
    kind: 'ambient',
    because:
      'set by next build itself, and turbo passes it through outside strict ' +
      'env mode; an ARG would let a deployment build a development CSP',
  },
];

/** Environment variables a source file reads, in either access form. */
function envReadsIn(source: string): string[] {
  const out: string[] = [];
  for (const pattern of [/process\.env\.([A-Z0-9_]+)/g, /process\.env\[['"]([A-Z0-9_]+)['"]\]/g]) {
    for (const match of source.matchAll(pattern)) {
      const value = match[1];
      if (value !== undefined) out.push(value);
    }
  }
  return out;
}

/**
 * Strip `//` and block comments while tracking string state, so the
 * `"https://turbo.build/schema.json"` on line two survives. A naive strip
 * corrupts it into invalid JSON and this fence then fails for a reason that has
 * nothing to do with what it checks.
 */
function stripJsonComments(text: string): string {
  let out = '';
  let inString = false;
  let inLine = false;
  let inBlock = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];
    if (inLine) {
      if (ch === '\n') {
        inLine = false;
        out += ch;
      }
      continue;
    }
    if (inBlock) {
      if (ch === '*' && next === '/') {
        inBlock = false;
        i += 1;
      }
      continue;
    }
    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += next ?? '';
        i += 1;
      } else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === '/' && next === '/') {
      inLine = true;
      i += 1;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlock = true;
      i += 1;
      continue;
    }
    out += ch;
  }
  return out;
}

/** The `ENV` block of the builder stage, as one string. */
function builderEnvBlock(): string {
  // Line continuations make the block multi-line; join them so a single
  // `includes` can ask whether a name is set there.
  const joined = dockerfile.replace(/\\\n\s*/g, ' ');
  const line = joined.split('\n').find((l) => l.startsWith('ENV NEXT_TELEMETRY_DISABLED'));
  return line ?? '';
}

describe('every build-time input reaches the build', () => {
  const pkgName = (
    JSON.parse(readFileSync(join(WEB_ROOT, 'package.json'), 'utf8')) as { name: string }
  ).name;
  const turbo = JSON.parse(
    stripJsonComments(readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8')),
  ) as { tasks: Record<string, { env?: string[] }> };

  /**
   * READ THE PACKAGE'S REAL NAME, and resolve which task actually applies.
   *
   * A `pkg#task` entry OVERRIDES the base entry rather than merging with it, so
   * asking the wrong key is how a fence stays green over an artifact built with
   * the wrong values — which is exactly the failure mode below.
   */
  const taskKey = `${pkgName}#build` in turbo.tasks ? `${pkgName}#build` : 'build';
  const declared = new Set(turbo.tasks[taskKey]?.env ?? []);
  const reads = [...new Set(envReadsIn(nextConfig))].sort();
  const envBlock = builderEnvBlock();

  it('reads the config, the Dockerfile and turbo, so nothing below is vacuous', () => {
    // Two regexes that quietly match nothing agree perfectly.
    expect(reads.length).toBeGreaterThanOrEqual(4);
    expect(declared.size).toBeGreaterThanOrEqual(2);
    expect(envBlock).toContain('NEXT_TELEMETRY_DISABLED');
    expect(dockerfile).toContain('ARG BFF_URL');
    expect(compose).toContain('web.Dockerfile');
  });

  it('classifies exactly the variables next.config.ts reads — no more, no fewer', () => {
    // BOTH directions. An unclassified read is an input nobody decided how to
    // deliver; a classified name the config no longer reads is dead prose that
    // makes the table look more complete than it is.
    expect(BUILD_INPUTS.map((i) => i.name).sort()).toEqual(reads);
  });

  it('gives every entry a reason', () => {
    // A classification with no argument behind it is a line somebody will
    // change without noticing they took a decision.
    expect(BUILD_INPUTS.filter((i) => i.because.trim().length < 20)).toEqual([]);
  });

  const declarable = BUILD_INPUTS.filter((i) => i.kind !== 'ambient');

  it.each(declarable)('turbo is told about $name', ({ name }) => {
    // Strict env mode strips anything not named here, and the build then falls
    // through to its default and exits 0.
    expect({ name, taskKey, declared: declared.has(name) }).toEqual({
      name,
      taskKey,
      declared: true,
    });
  });

  const deployment = BUILD_INPUTS.filter((i) => i.kind === 'deployment');

  it.each(deployment)('the image can RECEIVE $name', ({ name }) => {
    // The half that was missing. Without an ARG, a build arg passed by compose
    // or by CI is silently discarded.
    expect({ name, arg: new RegExp(`^ARG ${name}=`, 'm').test(dockerfile) }).toEqual({
      name,
      arg: true,
    });
    expect({ name, env: envBlock.includes(`${name}=\${${name}}`) }).toEqual({ name, env: true });
  });

  it.each(deployment)('the stack actually passes $name to the web build', ({ name }) => {
    // Closes the third link. `apps/stack/test/compose-parity.spec.ts` checks
    // that the VALUE compose passes equals topology's constant; nothing checked
    // that it is passed at all, and nothing on either side checked that the
    // Dockerfile could receive it.
    const webBuild = compose.slice(compose.indexOf('dockerfile: infra/docker/web.Dockerfile'));
    const args = webBuild.slice(0, webBuild.indexOf('\n    profiles:'));
    expect({ name, passed: new RegExp(`^\\s+${name}:`, 'm').test(args) }).toEqual({
      name,
      passed: true,
    });
  });

  const fixed = BUILD_INPUTS.filter((i) => i.kind === 'fixed');

  it.each(fixed)('$name is fixed by the image and NOT deployment-varying', ({ name }) => {
    // An ARG appearing here means it has quietly become deployment-varying,
    // which is a decision rather than a wiring detail.
    expect({ name, arg: new RegExp(`^ARG ${name}=`, 'm').test(dockerfile) }).toEqual({
      name,
      arg: false,
    });
    expect({ name, env: new RegExp(`${name}=`).test(envBlock) }).toEqual({ name, env: true });
  });
});
