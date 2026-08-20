/**
 * EVERY PATHS-FILTERED WORKFLOW MUST BE TRIGGERED BY EVERYTHING THAT DECIDES
 * WHAT IT PRODUCES.
 *
 * A `paths:` filter is the only gate in this repo that can turn a whole
 * workflow off without anything going red. A path missing from one is a commit
 * that changes what the workflow would have checked, with the check simply not
 * happening — and for `extension.yml` that means the reproducibility
 * comparison, the browser smoke and the SLSA attestation all skipped, so the
 * last attestation on `main` silently stops describing `main`.
 *
 * That is not hypothetical. `extension.yml` listed three paths and missed
 * three inputs, and the sharpest of them was measured rather than reasoned
 * about: deleting `VAULT_ORIGIN` from `turbo.json`'s task `env` makes Turbo 2's
 * strict env mode strip the variable, `build-package.mjs` falls through to its
 * localhost default, the build exits 0 and the packed digest moves — with
 * `turbo.json` outside the filter, so the workflow that would have caught it
 * did not run. `packages/config/**` was missed too, and nobody had noticed it
 * at all; it was found by asking turbo for the task graph instead of listing
 * what seemed relevant.
 *
 * SO THE ANSWER IS A REGISTRY, NOT A SECOND HAND-WRITTEN LIST. `WORKFLOW_INPUTS`
 * says, as data, how each filtered workflow's inputs are derived — the
 * credential-graph shape. Where a build graph can answer it, turbo answers it;
 * where it cannot, the entry is DECLARED with a reason, so a reader can tell a
 * derived fact from a judgement. A new filtered workflow arrives with an entry
 * or this goes red naming it, which is the property the first version of this
 * fence did not have: it lived in `apps/vault-extension` and knew about exactly
 * one workflow, so the next `paths:` filter anywhere in the repo would have
 * inherited the defect with nothing watching.
 *
 * WHAT THIS DELIBERATELY REFUSES RATHER THAN GUESSES. GitHub's glob dialect is
 * richer than the two forms used here (a literal path, and a `**` suffix), and
 * a filter written in YAML flow style or behind an anchor is not something this
 * parser can read. Both are REFUSED by name rather than silently treated as
 * absent — a filter this fence cannot see would otherwise read as "no filter",
 * which is the permissive answer, and a fence that stops matching goes green.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(__dirname, '..', '..', '..');
const WORKFLOW_DIR = join(REPO_ROOT, '.github', 'workflows');

/**
 * How each paths-filtered workflow's inputs are derived.
 *
 * `turbo` entries are answered by the build graph — add a dependency and the
 * required set grows on its own. `declared` entries are judgements about what
 * else moves the output, and each states why, because "which packages feed a
 * build" and "what else decides the bytes" are different kinds of claim and the
 * next reader has to be able to tell them apart.
 */
type InputSource =
  | { kind: 'turbo'; package: string; because: string }
  | { kind: 'declared'; path: string; because: string };

export const WORKFLOW_INPUTS: Readonly<Record<string, readonly InputSource[]>> = {
  'extension.yml': [
    {
      kind: 'turbo',
      package: '@estate/vault-extension',
      because:
        'the workflow builds, packs, attests and browser-drives this package, so every ' +
        'package in its build graph decides the signed bytes',
    },
    {
      kind: 'declared',
      path: 'turbo.json',
      because:
        "declares the build task's `env`; under Turbo 2's strict env mode an undeclared " +
        'variable is stripped and the build bakes its default instead — measured to move the digest',
    },
    {
      kind: 'declared',
      path: 'pnpm-lock.yaml',
      because: 'pins TypeScript, and the compiler decides the compiled bytes the packer stores',
    },
    {
      kind: 'declared',
      path: 'pnpm-workspace.yaml',
      because:
        'holds the catalog entries the lockfile resolves, including `typescript`; it always ' +
        'co-changes with the lockfile, and covering it costs nothing if that ever stops being true',
    },
    {
      kind: 'declared',
      path: '.gitattributes',
      because:
        'normalises line endings on checkout, which changes the bytes tsc reads; turbo names ' +
        'it a global cache input for the same reason',
    },
    {
      kind: 'declared',
      path: '.github/workflows/extension.yml',
      because:
        'chooses the Node major, the build command and every check in the job — it decides ' +
        'the artifact as surely as the sources do',
    },
  ],
};

/** A workflow's filters, per event. `null` = that event has no filter. */
interface Filters {
  paths: Record<string, string[] | null>;
  ignore: Record<string, string[] | null>;
  /** Shapes the parser will not guess at, e.g. flow style or an alias. */
  unreadable: string[];
}

/** The lines of a workflow's top-level `on:` block. */
function onBlock(source: string): string[] {
  const lines = source.split('\n');
  const start = lines.findIndex((l) => /^on:\s*$/.test(l));
  if (start < 0) {
    // `on: push` one-liners carry no filter and are not an error; a file with
    // no `on:` at all is not a workflow this fence has anything to say about.
    return [];
  }
  const body: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    body.push(line);
  }
  return body;
}

function parseFilters(source: string): Filters {
  const out: Filters = { paths: {}, ignore: {}, unreadable: [] };
  let event: string | null = null;
  let collecting: { key: 'paths' | 'ignore' } | null = null;

  for (const line of onBlock(source)) {
    const eventMatch = /^ {2}([a-z_]+):/.exec(line);
    if (eventMatch?.[1]) {
      event = eventMatch[1];
      out.paths[event] ??= null;
      out.ignore[event] ??= null;
      collecting = null;
      continue;
    }
    const filterMatch = /^ {4}(paths|paths-ignore):(.*)$/.exec(line);
    if (filterMatch && event) {
      const key = filterMatch[1] === 'paths' ? 'paths' : 'ignore';
      const trailing = (filterMatch[2] ?? '').trim();
      if (trailing !== '') {
        // Flow style (`paths: [a, b]`), an alias (`paths: *x`) or an anchor.
        // Refused by name: read as "no filter" it would be the permissive
        // answer, and this fence would go green on a workflow it cannot see.
        out.unreadable.push(`${event}.${filterMatch[1]}: ${trailing}`);
        collecting = null;
        continue;
      }
      out[key][event] = [];
      collecting = { key };
      continue;
    }
    if (/^ {4}\S/.test(line)) {
      collecting = null;
      continue;
    }
    const item = /^ {6}- '?([^'\s]+)'?\s*$/.exec(line);
    if (collecting && item?.[1] && event) out[collecting.key][event]?.push(item[1]);
  }
  return out;
}

/** turbo's own answer for which workspace directories a package's build reads. */
const turboCache = new Map<string, { dirs: string[]; globalFiles: string[] }>();
function turboInputs(pkg: string): { dirs: string[]; globalFiles: string[] } {
  const cached = turboCache.get(pkg);
  if (cached) return cached;
  const raw = execFileSync(
    join(REPO_ROOT, 'node_modules', '.bin', 'turbo'),
    ['run', 'build', `--filter=${pkg}`, '--dry=json'],
    { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  // Anything unparseable is a hard failure rather than an empty result: a
  // derivation that silently yields nothing makes every check below vacuous.
  const parsed = JSON.parse(raw.slice(raw.indexOf('{'))) as {
    tasks?: { directory?: string }[];
    globalCacheInputs?: { files?: Record<string, unknown> };
  };
  const value = {
    dirs: (parsed.tasks ?? [])
      .map((t) => t.directory)
      .filter((d): d is string => typeof d === 'string' && d.length > 0),
    globalFiles: Object.keys(parsed.globalCacheInputs?.files ?? {}),
  };
  turboCache.set(pkg, value);
  return value;
}

/** Every input a workflow's entry requires, as repo-relative paths. */
function requiredInputs(sources: readonly InputSource[]): string[] {
  const out = new Set<string>();
  for (const s of sources) {
    if (s.kind === 'declared') {
      out.add(s.path);
      continue;
    }
    const { dirs, globalFiles } = turboInputs(s.package);
    for (const d of dirs) out.add(`${d}/`);
    for (const f of globalFiles) out.add(f);
  }
  return [...out].sort();
}

/** Does an allowlist cover everything under `input`? `null` = no filter. */
function allowCovers(patterns: string[] | null, input: string): boolean {
  if (patterns === null) return true;
  return patterns.some((p) => (p.endsWith('/**') ? input.startsWith(p.slice(0, -2)) : p === input));
}

/** An ignore list covers an input only by NOT matching it. */
function ignoreCovers(patterns: string[] | null, input: string): boolean {
  if (patterns === null) return true;
  return !patterns.some((p) =>
    p.endsWith('/**') ? input.startsWith(p.slice(0, -2)) : p === input,
  );
}

const workflowFiles = readdirSync(WORKFLOW_DIR).filter((f) => /\.ya?ml$/.test(f));
const parsed = new Map(
  workflowFiles.map((f) => [f, parseFilters(readFileSync(join(WORKFLOW_DIR, f), 'utf8'))]),
);
const filtered = workflowFiles.filter((f) => {
  const p = parsed.get(f);
  if (!p) return false;
  return [...Object.values(p.paths), ...Object.values(p.ignore)].some((v) => v !== null);
});

/**
 * `it.each([])` is a jest ERROR rather than zero tests, so an empty registry —
 * which is what removing the last `paths:` filter in the repo legitimately
 * produces — would make this fence red for a mechanical reason having nothing
 * to do with what it checks. The placeholder keeps the suite well-formed and
 * every per-workflow case returns on it. That is a vacuous pass by
 * construction, and it is sound only because the registry-vs-reality equality
 * above is what carries the property when both sides are empty: there are no
 * filtered workflows, so there is nothing per-workflow left to say.
 */
const NO_FILTERED_WORKFLOWS = '(none — no workflow carries a paths filter)';
const REGISTERED = Object.keys(WORKFLOW_INPUTS);
const CASES = REGISTERED.length > 0 ? REGISTERED : [NO_FILTERED_WORKFLOWS];

describe('every paths-filtered workflow declares what triggers it', () => {
  it('reads the workflow directory at all', () => {
    // Without this, a moved directory or a changed extension would leave every
    // check below quantified over nothing and passing.
    expect(workflowFiles.length).toBeGreaterThanOrEqual(5);
    expect(workflowFiles).toContain('extension.yml');
  });

  it('refuses a filter shape it cannot read, rather than reading it as absent', () => {
    // Flow style, an anchor or an alias. Treated as "no filter" these would be
    // the permissive answer.
    //
    // THIS IS DEFENCE IN DEPTH, NOT THE CONTROL, and the difference was
    // measured rather than assumed: with this refusal disabled AND a flow-style
    // filter planted, the suite still goes red — the parser-reach comparison
    // below sees it, because the permissive read counts a `paths:` key that the
    // parser did not collect. What this buys is a failure that NAMES the
    // unreadable shape instead of one reporting a key/item count mismatch, and
    // saying which half is load-bearing is the point of writing it down.
    const unreadable = workflowFiles.flatMap((f) =>
      (parsed.get(f)?.unreadable ?? []).map((u) => `${f} -> ${u}`),
    );
    expect(unreadable).toEqual([]);
  });

  it('has an entry for every filtered workflow, and no entry for anything else', () => {
    // The generalization. A new `paths:` filter anywhere in the repo arrives
    // with a declared derivation or this names it.
    expect([...filtered].sort()).toEqual(Object.keys(WORKFLOW_INPUTS).sort());
  });

  it.each(CASES)('%s derives a non-empty input set', (file) => {
    if (file === NO_FILTERED_WORKFLOWS) return;
    const sources = WORKFLOW_INPUTS[file] ?? [];
    expect(sources.length).toBeGreaterThan(0);
    for (const s of sources) {
      expect(s.because.length).toBeGreaterThan(30);
      if (s.kind === 'turbo') {
        const { dirs } = turboInputs(s.package);
        // A filter whose package no longer exists derives nothing and would
        // otherwise leave the coverage check below trivially satisfied. Shaped
        // so the failure names WHICH package derived nothing, rather than
        // reporting that some number was not at least one.
        expect({ pkg: s.package, derivedNothing: dirs.length === 0 }).toEqual({
          pkg: s.package,
          derivedNothing: false,
        });
      }
    }
    expect(requiredInputs(sources).length).toBeGreaterThanOrEqual(2);
  });

  it.each(CASES)('%s parses every filter it actually contains', (file) => {
    // THE PARSER'S REACH, COMPARED AS A SET RATHER THAN ASSUMED — this fence's
    // own mutation run is why. Breaking the `paths:` regex left every check
    // green, because a missing filter reads as "covers everything" and the
    // anti-vacuity case checked only that the event keys were found, which a
    // broken paths regex does not disturb. A count could not see it either:
    // mis-attribution preserves totals.
    if (file === NO_FILTERED_WORKFLOWS) return;
    const body = onBlock(readFileSync(join(WORKFLOW_DIR, file), 'utf8'));
    const keysInFile = body.filter((l) => /^ {4}paths(-ignore)?:/.test(l)).length;
    const itemsInFile = body.filter((l) => /^ {6}- /.test(l)).length;
    const p = parsed.get(file)!;
    const lists = [...Object.values(p.paths), ...Object.values(p.ignore)];
    expect({
      keys: lists.filter((v) => v !== null).length,
      items: lists.reduce((n, v) => n + (v?.length ?? 0), 0),
    }).toEqual({ keys: keysInFile, items: itemsInFile });
  });

  it.each(CASES)('%s is triggered by every one of its inputs', (file) => {
    if (file === NO_FILTERED_WORKFLOWS) return;
    const required = requiredInputs(WORKFLOW_INPUTS[file] ?? []);
    const p = parsed.get(file)!;
    const uncovered: string[] = [];
    for (const event of Object.keys(p.paths)) {
      for (const input of required) {
        if (!allowCovers(p.paths[event] ?? null, input)) uncovered.push(`${event}: ${input}`);
        if (!ignoreCovers(p.ignore[event] ?? null, input))
          uncovered.push(`${event}: ${input} (excluded by paths-ignore)`);
      }
    }
    // Named in the failure, because "something is missing" sends the next
    // person back to this file rather than to the workflow.
    expect({ file, uncovered }).toEqual({ file, uncovered: [] });
  });

  it.each(CASES)('%s filters every event the same way', (file) => {
    // IDENTICAL, not merely "push is no narrower". A `push` filter narrower
    // than the `pull_request` one leaves the branch verified and `main` not,
    // and "no narrower" needs a reader to work out which way a difference cuts.
    // Deleting every filter still satisfies this (all `null`), so the
    // legitimate widening stays available.
    if (file === NO_FILTERED_WORKFLOWS) return;
    const p = parsed.get(file)!;
    const lists = Object.keys(p.paths)
      .filter((e) => p.paths[e] !== null || p.ignore[e] !== null)
      .map((e) => JSON.stringify({ paths: p.paths[e], ignore: p.ignore[e] }));
    expect(new Set(lists).size).toBeLessThanOrEqual(1);
  });

  it.each(CASES)('%s carries no path that is not an input', (file) => {
    // The reverse direction. A stale entry is not dangerous, but it is a claim
    // about what matters, and a wrong one sends a reader looking for a
    // dependency that no longer exists.
    if (file === NO_FILTERED_WORKFLOWS) return;
    const required = requiredInputs(WORKFLOW_INPUTS[file] ?? []);
    const p = parsed.get(file)!;
    const stale = Object.values(p.paths)
      .flatMap((v) => v ?? [])
      .filter((pattern) => {
        const target = pattern.endsWith('/**') ? `${pattern.slice(0, -3)}/` : pattern;
        return !required.includes(target);
      });
    expect([...new Set(stale)]).toEqual([]);
  });
});
