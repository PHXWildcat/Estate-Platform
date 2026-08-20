/**
 * THE ENTRY-POINT GUARD FIRES HOWEVER THE PATH IS SPELLED.
 *
 * Two scripts here do their work only when they ARE the entry point, so that a
 * test can import their functions without writing an archive or regenerating a
 * module. A guard that fails to fire is the worst shape a build step can take:
 * node exits 0, prints nothing and produces nothing, so every downstream check
 * reads it as a step that simply had nothing to do.
 *
 * BOTH FORMS WERE MEASURED BROKEN, on these two files, before this file existed:
 *
 *   · `file://${process.argv[1]}` — build-psl's form — is broken by a SPACE
 *     anywhere in the path (`import.meta.url` percent-encodes it and the
 *     template does not) AND by a SYMLINK anywhere in the path.
 *   · `pathToFileURL(process.argv[1]).href` — the packer's form, which is M16
 *     PR4b's fix for the space — is still broken by the SYMLINK: node reports
 *     the RESOLVED REAL path in `import.meta.url` and the literal path as typed
 *     in `process.argv[1]`, so the two disagree.
 *
 * WHICH SYMLINKS REACH THIS, measured rather than assumed, because the
 * distinction is why the defect outlived the fix that was meant to cover it.
 * `process.argv[1]` is resolved against the PHYSICAL cwd, so a symlink ABOVE
 * the working directory collapses and can never be seen — which is why M16
 * PR4b's own check, running the packer from `/tmp/has space/probe`, passed on a
 * macOS whose `/tmp` IS a symlink, and exercised only the space. A symlink AT
 * OR BELOW the working directory does NOT collapse, and that is the shape
 * VERIFYING.md prescribes: `node apps/vault-extension/scripts/pack-extension.mjs`
 * from the repo root, where any of those segments may be a link, plus any
 * absolute-path invocation through one.
 *
 * AND IT FAILS IN THE REASSURING DIRECTION. The line after that one in
 * VERIFYING.md is `sha256sum` on the archive; with the guard unfired the packer
 * writes nothing, so the hash is of the archive left by an EARLIER run — a
 * digest MATCH reported for a build that never happened, in the one procedure
 * whose entire purpose is to detect that the bytes are not what they claim to
 * be. That is what makes this worth a test rather than a note.
 *
 * TWO LAYERS, because neither is sufficient. The BEHAVIOURAL half invokes each
 * script through each distortion and requires it to do its work; it is the
 * layer that catches the defect as a user meets it. The STRUCTURAL half
 * requires every guard under `scripts/` to be DECLARED here and written in the
 * resolved-both-sides form, so a third script arrives covered rather than
 * silently exempt — a behavioural case can only ever test the scripts somebody
 * remembered to write one for.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PKG = join(__dirname, '..');
const SCRIPTS = join(PKG, 'scripts');

/**
 * Every script that decides for itself whether it is the entry point, with a
 * recipe for invoking it and for telling whether it did its work.
 *
 * A silent exit 0 IS the regression, so each `assertWorked` requires an
 * artifact AND non-empty output: a guard that never fires produces neither, and
 * asserting only on the exit status would pass over exactly this defect.
 */
interface GuardedScript {
  /** File under `scripts/`. */
  readonly file: string;
  /** Why this one has a guard rather than running unconditionally. */
  readonly why: string;
  /** Invoke it against a staged package root; return what it printed. */
  run(pkgRoot: string, scratch: string): string;
  /** Fail unless the invocation really did the work. */
  assertWorked(scratch: string, stdout: string): void;
}

const GUARDED: readonly GuardedScript[] = [
  {
    file: 'pack-extension.mjs',
    why: '`pack.spec.ts` imports `packDirectory`, which must not write an archive as a side effect of being imported.',
    run(pkgRoot, scratch) {
      const fixture = join(scratch, 'fixture');
      mkdirSync(fixture, { recursive: true });
      writeFileSync(join(fixture, 'a.txt'), 'alpha\n');
      return execFileSync(process.execPath, [join(pkgRoot, 'scripts', 'pack-extension.mjs')], {
        cwd: PKG,
        encoding: 'utf8',
        env: { ...process.env, PACK_DIR: fixture, PACK_OUT: join(scratch, 'out.zip') },
        stdio: 'pipe',
      });
    },
    assertWorked(scratch, stdout) {
      const zip = join(scratch, 'out.zip');
      // The archive exists at all — a guard that did not fire writes nothing.
      const bytes = readFileSync(zip);
      expect(bytes.length).toBeGreaterThan(0);
      // And the digest it PRINTED describes the bytes it WROTE, so a partial
      // run cannot satisfy this by leaving a file behind.
      const printed = stdout.trim().split(/\s+/)[0];
      expect(printed).toBe(createHash('sha256').update(bytes).digest('hex'));
    },
  },
  {
    file: 'build-psl.mjs',
    why: '`psl.spec.ts` imports `toALabels` and `moduleFor` to probe them directly, which must not rewrite `src/psl-data.ts`.',
    run(pkgRoot, scratch) {
      return execFileSync(process.execPath, [join(pkgRoot, 'scripts', 'build-psl.mjs')], {
        cwd: PKG,
        encoding: 'utf8',
        env: { ...process.env, OUT_FILE: join(scratch, 'psl-data.ts') },
        stdio: 'pipe',
      });
    },
    assertWorked(scratch, stdout) {
      const generated = readFileSync(join(scratch, 'psl-data.ts'), 'utf8');
      expect(generated).toContain('export const PUBLIC_SUFFIX_RULES');
      expect(stdout).toMatch(/psl-data\.ts: \d+ rules from /);
    },
  },
];

/* ------------------------------------------------------------------ *
 * Staging. Each distortion is applied ALONE, and each is asserted to be
 * the distortion it claims — see the anti-vacuity block below. That is
 * not pedantry here: `os.tmpdir()` is ITSELF symlinked on macOS, so the
 * obvious staging for the space case would have silently been a second
 * symlink case, and the two would never have been told apart.
 * ------------------------------------------------------------------ */

/** A base with no symlink component anywhere, so a case can add exactly one. */
let base: string;
/** The package reached through a symlinked directory; no space in the path. */
let symlinked: string;
/** The package reached through a path containing a space; no symlink in it. */
let spaced: string;

function scratchFor(name: string): string {
  const dir = join(base, 'scratch', name.replace(/\W+/g, '-'));
  mkdirSync(dir, { recursive: true });
  return dir;
}

beforeAll(() => {
  base = mkdtempSync(join(realpathSync(tmpdir()), 'entry-guard-'));

  symlinked = join(base, 'link');
  symlinkSync(PKG, symlinked, 'dir');

  // A real copy, so nothing about this case is a symlink. `vendor/` travels
  // because build-psl resolves its input relative to its own real location.
  spaced = join(base, 'has space', 'pkg');
  mkdirSync(spaced, { recursive: true });
  cpSync(SCRIPTS, join(spaced, 'scripts'), { recursive: true });
  cpSync(join(PKG, 'vendor'), join(spaced, 'vendor'), { recursive: true });
});

afterAll(() => {
  // `rmSync` on the base removes the symlink itself, never its target: the
  // recursive walk does not descend through a symlinked directory.
  rmSync(base, { recursive: true, force: true });
});

describe('a build script runs however its path is spelled', () => {
  it.each(GUARDED.map((s) => [s.file, s] as const))(
    '%s does its work when invoked through a SYMLINKED directory',
    (_file, script) => {
      const scratch = scratchFor(`symlink-${script.file}`);
      const stdout = script.run(symlinked, scratch);
      expect(stdout.trim()).not.toBe('');
      script.assertWorked(scratch, stdout);
    },
  );

  it.each(GUARDED.map((s) => [s.file, s] as const))(
    '%s does its work when invoked through a path containing a SPACE',
    (_file, script) => {
      const scratch = scratchFor(`space-${script.file}`);
      const stdout = script.run(spaced, scratch);
      expect(stdout.trim()).not.toBe('');
      script.assertWorked(scratch, stdout);
    },
  );

  it('stages each distortion ALONE, so neither case is quietly the other', () => {
    const probe = (root: string): string => join(root, 'scripts', 'pack-extension.mjs');

    // The symlink case really traverses a symlink, and carries no space.
    expect(realpathSync(probe(symlinked))).not.toBe(probe(symlinked));
    expect(symlinked).not.toContain(' ');

    // The space case really carries a space, and traverses no symlink —
    // including in the temp base, which on macOS is symlinked by default.
    expect(spaced).toContain(' ');
    expect(realpathSync(probe(spaced))).toBe(probe(spaced));
    expect(realpathSync(base)).toBe(base);
  });
});

/* ------------------------------------------------------------------ */

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

/** Scripts that do entry-point detection at all, however they spell it. */
function guardBearingScripts(): string[] {
  return readdirSync(SCRIPTS)
    .filter((f) => f.endsWith('.mjs'))
    .filter((f) => {
      const source = stripComments(readFileSync(join(SCRIPTS, f), 'utf8'));
      return source.includes('process.argv[1]') || /import\.meta\.url\s*===/.test(source);
    });
}

describe('every entry-point guard resolves BOTH sides', () => {
  it('finds a plausible number of scripts to check', () => {
    // Anti-vacuity. Every assertion below is trivially true of an empty
    // directory listing, and a scan that quietly matches nothing is this
    // repo's most-repeated way for a fence to go green while meaning nothing.
    const all = readdirSync(SCRIPTS).filter((f) => f.endsWith('.mjs'));
    expect(all.length).toBeGreaterThanOrEqual(6);
    expect(stripComments('a /* b */ c // d\ne')).toBe('a  c \ne');
  });

  it('declares exactly the scripts that have a guard', () => {
    // Both directions. An undeclared guard is one nothing above exercises; a
    // declared entry for a script that no longer guards is a case testing
    // something other than what it is named for.
    expect(guardBearingScripts().sort()).toEqual(GUARDED.map((s) => s.file).sort());
    expect(GUARDED.length).toBeGreaterThanOrEqual(2);
  });

  it.each(GUARDED.map((s) => s.file))('%s compares two RESOLVED file URLs', (file) => {
    const source = stripComments(readFileSync(join(SCRIPTS, file), 'utf8'));

    // The exact shape is asserted because the shape IS the property: each of
    // the two calls repairs a distortion the other does not, so dropping
    // either one silently reintroduces a measured defect. Rewriting this is
    // meant to be a deliberate act that edits this line too.
    expect(source).toMatch(
      /pathToFileURL\(\s*realpathSync\(\s*process\.argv\[1\]\s*\)\s*\)\s*\.href/,
    );
    expect(source).toMatch(/import\.meta\.url\s*===/);

    // And the form both of these grew out of is refused by name, so a revert
    // fails here rather than only in the behavioural cases above.
    expect(source).not.toMatch(/`file:\/\/\$\{/);
    expect(source).not.toMatch(/pathToFileURL\(\s*process\.argv\[1\]\s*\)/);
  });
});
