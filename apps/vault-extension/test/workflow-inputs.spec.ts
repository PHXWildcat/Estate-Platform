/**
 * THE SIGNING WORKFLOW'S TRIGGER MUST COVER EVERY INPUT THAT DECIDES THE BYTES.
 *
 * `.github/workflows/extension.yml` is the only paths-filtered workflow in this
 * repo, and its filter decides three things at once: whether the two-build
 * reproducibility comparison runs, whether the artifact is driven in a real
 * browser, and whether an attestation is minted. A path missing from it is a
 * commit that changes the signed bytes with none of that happening — and the
 * failure is silent in the worst direction, because the last attestation on
 * `main` simply stops describing `main` while every other gate stays green.
 *
 * It was hand-written and it had drifted in three places at once. Measured, not
 * reasoned about: deleting `VAULT_ORIGIN` from `turbo.json`'s task `env` makes
 * Turbo 2's strict env mode strip the variable, `build-package.mjs` falls
 * through to its localhost `DEFAULT_ORIGIN`, the build exits 0, and the packed
 * digest moves — with `turbo.json` outside the filter, so the workflow that
 * would have caught it does not run. `pnpm-lock.yaml` pins the compiler.
 * `packages/config/**` holds the `tsconfig.base.json` that
 * `tsconfig.build.json` extends transitively, and nobody had noticed it at all.
 *
 * SO THE LIST IS DERIVED FROM THE PROJECT, NOT MAINTAINED BY MEMORY — the
 * remedy this repo has applied every time this shape appeared (stack.yml's
 * hand-copied migrate list, `web.Dockerfile`'s asserted-absent `public/`,
 * images.yml's hand-listed diagnostics containers). turbo is asked for the
 * build's own task graph; the handful of inputs turbo does not model are
 * DECLARED with a reason each, so a reader can tell a derived entry from a
 * judgement call.
 *
 * WHAT THIS DOES NOT CHECK, stated rather than implied: that a path in the
 * filter is spelled the way GitHub matches it. The patterns are literal
 * prefixes and `**` suffixes, which the coverage check models directly, but
 * GitHub's own glob dialect is richer and this fence does not implement it. A
 * pattern doing something clever would be covered here and behave differently
 * there.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const PKG_ROOT = join(__dirname, '..');
const REPO_ROOT = join(PKG_ROOT, '..', '..');
const WORKFLOW = join(REPO_ROOT, '.github', 'workflows', 'extension.yml');

/**
 * Inputs that decide the artifact and that turbo's task graph does not name.
 *
 * A reason per entry, because "which packages feed the build" is answerable
 * from the graph while "what else moves the bytes" is a judgement, and the next
 * reader needs to be able to tell which kind of claim they are looking at.
 */
const DECLARED_INPUTS: ReadonlyArray<{ path: string; because: string }> = [
  {
    path: 'turbo.json',
    because:
      "declares the build task's `env`; under Turbo 2's strict env mode an undeclared " +
      'variable is stripped and the build bakes its default instead — measured to move the digest',
  },
  {
    path: 'pnpm-lock.yaml',
    because: 'pins TypeScript, and the compiler decides the compiled bytes the packer stores',
  },
  {
    path: 'pnpm-workspace.yaml',
    because:
      'holds the catalog entries the lockfile resolves, including `typescript`; it always ' +
      'co-changes with the lockfile, and covering it costs nothing if that ever stops being true',
  },
  {
    path: '.github/workflows/extension.yml',
    because:
      'chooses the Node major, the build command and every check above — it decides the ' +
      'artifact as surely as the sources do',
  },
];

/** The workspace-relative directories turbo builds to produce the extension. */
function turboInputPackages(): { dirs: string[]; globalFiles: string[] } {
  const raw = execFileSync(
    join(REPO_ROOT, 'node_modules', '.bin', 'turbo'),
    ['run', 'build', '--filter=@estate/vault-extension', '--dry=json'],
    { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  // turbo prints a banner line before the JSON on some versions; take from the
  // first `{`. Anything that is not parseable is a hard failure rather than an
  // empty result — a fence that silently derives nothing goes green.
  const parsed = JSON.parse(raw.slice(raw.indexOf('{'))) as {
    tasks?: { directory?: string }[];
    globalCacheInputs?: { files?: Record<string, unknown> };
  };
  const dirs = (parsed.tasks ?? [])
    .map((t) => t.directory)
    .filter((d): d is string => typeof d === 'string' && d.length > 0);
  return { dirs, globalFiles: Object.keys(parsed.globalCacheInputs?.files ?? {}) };
}

/**
 * The `paths:` list under each event, read out of the workflow.
 *
 * A missing key means NO filter, which is a strictly wider trigger than any
 * list and therefore always covering — modelled as `null` rather than as an
 * empty list, because an empty list would read as "covers nothing".
 */
function workflowPaths(): Record<string, string[] | null> {
  const lines = readFileSync(WORKFLOW, 'utf8').split('\n');
  const onIndex = lines.findIndex((l) => /^on:\s*$/.test(l));
  if (onIndex < 0) throw new Error('extension.yml has no top-level `on:` block');

  const out: Record<string, string[] | null> = {};
  let event: string | null = null;
  let collecting = false;
  for (const line of lines.slice(onIndex + 1)) {
    if (/^\S/.test(line)) break; // dedented out of `on:` entirely
    const eventMatch = /^ {2}([a-z_]+):/.exec(line);
    if (eventMatch?.[1]) {
      event = eventMatch[1];
      if (!(event in out)) out[event] = null;
      collecting = false;
      continue;
    }
    if (/^ {4}paths(-ignore)?:\s*$/.test(line) && event) {
      out[event] = [];
      collecting = true;
      continue;
    }
    if (/^ {4}\S/.test(line)) {
      collecting = false;
      continue;
    }
    const item = /^ {6}- '?([^'\s]+)'?\s*$/.exec(line);
    if (collecting && item?.[1] && event) out[event]?.push(item[1]);
  }
  return out;
}

/** Does any pattern in `patterns` cover everything under `input`? */
function covers(patterns: string[] | null, input: string): boolean {
  if (patterns === null) return true; // no filter at all: the widest trigger
  return patterns.some((p) => (p.endsWith('/**') ? input.startsWith(p.slice(0, -2)) : p === input));
}

describe('the extension workflow is triggered by everything that decides its artifact', () => {
  const { dirs, globalFiles } = turboInputPackages();
  const derived = [...dirs.map((d) => `${d}/`), ...globalFiles];
  const required = [...derived, ...DECLARED_INPUTS.map((d) => d.path)];
  const events = workflowPaths();

  it('derives a real input set from turbo, so the checks below are not vacuous', () => {
    // Without this, a turbo whose `--dry=json` shape has moved would yield an
    // empty task list and every coverage assertion would quantify over nothing.
    expect(dirs).toEqual(expect.arrayContaining(['apps/vault-extension']));
    expect(dirs.length).toBeGreaterThanOrEqual(3);
    expect(globalFiles.length).toBeGreaterThanOrEqual(1);
  });

  it('parses every filter the file actually contains', () => {
    // THE PARSER'S REACH, COMPARED AS A SET RATHER THAN ASSUMED — this fence's
    // own mutation run is why. Breaking the `paths:` regex left all seven
    // checks GREEN: `workflowPaths` returned `null` for every event, `covers`
    // reads `null` as "no filter, therefore covering", and the whole suite
    // passed over a file it had not read. An earlier version of this case
    // asserted only that the event KEYS were found, which a broken paths regex
    // does not disturb.
    //
    // So the parse is checked against a deliberately permissive second read of
    // the same block: how many `paths:` keys are in there, and how many list
    // items under them. Equality means the parser saw what is written. It is a
    // comparison and not a floor on purpose — deleting both filters is a
    // legitimate (and strictly wider) change, and then both reads are zero and
    // this still holds.
    const block = readFileSync(WORKFLOW, 'utf8').split('\n');
    const onIndex = block.findIndex((l) => /^on:\s*$/.test(l));
    const body: string[] = [];
    for (const line of block.slice(onIndex + 1)) {
      if (/^\S/.test(line)) break;
      body.push(line);
    }
    const keysInFile = body.filter((l) => /^ {4}paths(-ignore)?:/.test(l)).length;
    const itemsInFile = body.filter((l) => /^ {6}- /.test(l)).length;

    const parsedKeys = Object.values(events).filter((v) => v !== null).length;
    const parsedItems = Object.values(events).reduce((n, v) => n + (v?.length ?? 0), 0);

    expect({ keys: parsedKeys, items: parsedItems }).toEqual({
      keys: keysInFile,
      items: itemsInFile,
    });
  });

  it.each(['push', 'pull_request'])('%s is triggered by every build input', (event) => {
    const uncovered = required.filter((input) => !covers(events[event] ?? null, input));
    // Named in the failure: "something is missing" sends the next person back
    // to this file rather than to the workflow.
    expect({ event, uncovered }).toEqual({ event, uncovered: [] });
  });

  it('checks the same inputs on main as on the pull request that produced it', () => {
    // IDENTICAL, not merely "push is no narrower". The property worth having is
    // that a `push` filter narrower than the `pull_request` one leaves the
    // branch verified and `main` not — but "no narrower" needs a reader to work
    // out which way a difference cuts, and equality does not. Deleting both
    // filters still satisfies this (both `null`), so the legitimate widening
    // stays available.
    expect(events['push']).toEqual(events['pull_request']);
  });

  it('carries no path that is not a build input', () => {
    // The reverse direction. A stale entry is not dangerous, but it is a claim
    // about what matters, and a wrong one sends a reader looking for a
    // dependency that no longer exists.
    const stale = (events['push'] ?? []).filter((p) => {
      const target = p.endsWith('/**') ? `${p.slice(0, -3)}/` : p;
      return !required.includes(target);
    });
    expect(stale).toEqual([]);
  });

  it('states why each non-derived input is an input', () => {
    for (const entry of DECLARED_INPUTS) expect(entry.because.length).toBeGreaterThan(30);
  });
});
