/**
 * EVERY BUILD-TIME INPUT IS DECLARED TO TURBO, DERIVED RATHER THAN LISTED.
 *
 * Turbo 2 runs tasks in strict env mode: a variable not named in the task's
 * `env` is stripped, and the build script then falls through to its default and
 * exits 0. The artifact is wrong and nothing anywhere is red.
 *
 * That is not hypothetical here. `build-package.mjs` reads `VAULT_ORIGIN` to
 * bake the one origin the extension may address into both the manifest and
 * `origin.ts`, and it was undeclared: measured with
 * `VAULT_ORIGIN=https://vault.example.test pnpm build --filter=@estate/
 * vault-extension --force`, the package came out saying
 * `http://vault.localhost:3010`. The script VALIDATES the value it reads and
 * throws on a malformed one, so its own guard could not help — it never
 * received the variable. Identical in shape to the M8 PR5 defect where the web
 * image baked a rewrite to `localhost:4000` because `BFF_URL` was undeclared,
 * one milestone later and in the same `turbo.json`.
 *
 * So the check is not "is VAULT_ORIGIN declared" — that pins the instance and
 * misses the next one. It reads the build command out of `package.json`,
 * follows it to the scripts it actually runs, scans those for `process.env`
 * reads, and requires each to be declared. A new build-time input arrives
 * declared, or the build goes red.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const PKG_ROOT = join(__dirname, '..');
const REPO_ROOT = join(PKG_ROOT, '..', '..');

/**
 * READ THE PACKAGE'S REAL NAME, never a literal.
 *
 * turbo matches a `pkg#task` key against the name in `package.json`. A literal
 * here would keep validating a turbo entry that no longer applies the moment
 * the package is renamed: turbo silently falls back to the base `build` task,
 * whose `env` does not list `VAULT_ORIGIN`, and the artifact goes back to being
 * built with the wrong origin — with this fence green, because it would still
 * be reading the orphaned key it was told to read.
 */
const PKG_NAME = (
  JSON.parse(readFileSync(join(PKG_ROOT, 'package.json'), 'utf8')) as { name: string }
).name;

/**
 * Strip `//` and block comments from JSONC, tracking string state so the
 * `"https://turbo.build/schema.json"` on line two survives. A naive strip
 * corrupts it into invalid JSON, which would make this fence fail for a reason
 * that has nothing to do with what it checks.
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

/** Every first capture group of `pattern` in `source`. */
function captures(source: string, pattern: RegExp): string[] {
  const out: string[] = [];
  for (const match of source.matchAll(pattern)) {
    const value = match[1];
    if (value !== undefined) out.push(value);
  }
  return out;
}

/** The `.mjs` scripts the package's `build` command actually invokes. */
function buildScripts(): string[] {
  const pkg = JSON.parse(readFileSync(join(PKG_ROOT, 'package.json'), 'utf8')) as {
    scripts: { build: string };
  };
  return captures(pkg.scripts.build, /node\s+(\S+\.mjs)/g);
}

/** Environment variables a source file reads, in either access form. */
function envReadsIn(source: string): string[] {
  return [
    ...captures(source, /process\.env\.([A-Z0-9_]+)/g),
    ...captures(source, /process\.env\[['"]([A-Z0-9_]+)['"]\]/g),
  ];
}

describe('turbo is told about every build-time input', () => {
  const turbo = JSON.parse(
    stripJsonComments(readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8')),
  ) as {
    tasks: Record<string, { env?: string[] }>;
  };
  const scripts = buildScripts();

  it('finds the build scripts and their inputs, so the scan is not vacuous', () => {
    // Without this, a `build` script that stopped matching the `node …mjs`
    // pattern would leave every assertion below quantified over nothing.
    expect(scripts.length).toBeGreaterThanOrEqual(2);
    const reads = scripts.flatMap((s) => envReadsIn(readFileSync(join(PKG_ROOT, s), 'utf8')));
    expect(new Set(reads).size).toBeGreaterThanOrEqual(2);
    expect(reads).toContain('VAULT_ORIGIN');
  });

  it('declares a package-specific build task at all', () => {
    // The base `build` task's `env` does not apply: a `pkg#task` entry
    // OVERRIDES the base entry rather than merging with it, so the declaration
    // has to live on this key.
    expect(Object.keys(turbo.tasks)).toContain(`${PKG_NAME}#build`);
  });

  it.each(scripts)('declares every variable %s reads', (script) => {
    const declared = new Set(turbo.tasks[`${PKG_NAME}#build`]?.env ?? []);
    const reads = [...new Set(envReadsIn(readFileSync(join(PKG_ROOT, script), 'utf8')))].sort();
    const undeclared = reads.filter((name) => !declared.has(name));
    // Named in the failure, because "some variable is missing" sends the next
    // person back to this file rather than to turbo.json.
    expect({ script, undeclared }).toEqual({ script, undeclared: [] });
  });
});
