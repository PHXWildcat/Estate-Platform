/**
 * THE PUBLIC SUFFIX LIST IS A SECURITY PARAMETER, so it is pinned, and its age
 * is reported rather than ignored.
 *
 * It is vendored because this package has no runtime dependencies and must not
 * fetch a security parameter at runtime (docs/04 M16 decision 2). Vendoring
 * trades one risk for another: it cannot be tampered with in transit, and it
 * goes stale. Both halves are checked here.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { PUBLIC_SUFFIX_RULES } from '../src/psl-data';

const ROOT = join(__dirname, '..');
const SOURCE = readFileSync(join(ROOT, 'vendor', 'public-suffix-list.dat'), 'utf8');

/**
 * The digest of the snapshot in `vendor/`. Changing the list means changing
 * this line, which is the point: a security parameter should not be updatable
 * without somebody deciding to.
 */
const PINNED_SHA256 = '084a5674d77c1d14900b16da5fc8afee9765af2f00a638552a8c7aa18f44ae81';

/** From the list's own `// VERSION:` header — the snapshot's own claim. */
const SNAPSHOT = '2026-07-25_14-20-03_UTC';

/**
 * How old the snapshot may get before this test complains.
 *
 * A YEAR is deliberately generous, because the failure mode of a stale list is
 * mild and one-directional: a suffix added AFTER this snapshot is unknown, so
 * `registrableDomain` falls back to the implicit `*` rule and returns a SHORTER
 * domain — which can make two hosts under a new multi-label registry compare
 * equal. That is a real (narrow) over-match, recorded in docs/03 §6j; it is not
 * a reason to fail a build weekly, which is how a staleness check becomes noise
 * people learn to bump.
 */
const MAX_AGE_DAYS = 365;

describe('the vendored Public Suffix List', () => {
  it('matches its pinned digest', () => {
    const actual = createHash('sha256').update(SOURCE, 'utf8').digest('hex');
    expect(actual).toBe(PINNED_SHA256);
  });

  it('carries its licence header, because vendoring it is redistribution', () => {
    expect(SOURCE).toContain('Mozilla Public');
    expect(SOURCE).toContain('mozilla.org/MPL/2.0');
    // And the instruction that it be pulled only from publicsuffix.org, which
    // is how the next person knows where a refresh comes from.
    expect(SOURCE).toContain('https://publicsuffix.org/list/public_suffix_list.dat');
  });

  it('declares the snapshot this pin was taken from', () => {
    expect(SOURCE).toContain(`// VERSION: ${SNAPSHOT}`);
  });

  it('is not older than the age this project accepts', () => {
    const stamp = /^\/\/ VERSION: (\d{4})-(\d{2})-(\d{2})/m.exec(SOURCE);
    if (stamp === null) throw new Error('the vendored list carries no VERSION header');
    const [year = 0, month = 1, day = 1] = [stamp[1], stamp[2], stamp[3]].map(Number);
    const taken = Date.UTC(year, month - 1, day);
    const ageDays = (Date.now() - taken) / 86_400_000;
    expect(ageDays).toBeLessThan(MAX_AGE_DAYS);
  });

  /**
   * THE GENERATED MODULE CANNOT DRIFT FROM THE SOURCE.
   *
   * `src/psl-data.ts` is committed rather than built, so it is reviewable and so
   * a fresh clone typechecks — but a committed generated file is a file somebody
   * can edit. Regenerating from the vendored bytes and comparing is what makes
   * the digest pin above mean anything for the code that actually runs.
   */
  it('the generated module is exactly what the script produces from it', () => {
    // Run the REAL generator as a subprocess into a temp file (the
    // `build-package.mjs` precedent — ts-jest cannot import a plain .mjs), so
    // this compares against what the build actually emits rather than against a
    // second implementation living in the test.
    const out = join(mkdtempSync(join(tmpdir(), 'psl-')), 'psl-data.ts');
    try {
      execFileSync(process.execPath, [join(ROOT, 'scripts', 'build-psl.mjs')], {
        cwd: ROOT,
        env: { ...process.env, OUT_FILE: out },
        stdio: 'pipe',
      });
      expect(readFileSync(join(ROOT, 'src', 'psl-data.ts'), 'utf8')).toBe(
        readFileSync(out, 'utf8'),
      );
    } finally {
      rmSync(out, { force: true });
    }
  });

  it('parses to a plausible number of rules, so a truncated list fails loudly', () => {
    // Anti-vacuity: every matcher assertion elsewhere is true of an empty list
    // in ways nobody would notice.
    expect(PUBLIC_SUFFIX_RULES.length).toBeGreaterThan(9000);
    expect(PUBLIC_SUFFIX_RULES).toContain('com');
    expect(PUBLIC_SUFFIX_RULES).toContain('co.uk');
    // The wildcard and exception rules the algorithm depends on really exist.
    expect(PUBLIC_SUFFIX_RULES.some((r) => r.startsWith('*.'))).toBe(true);
    expect(PUBLIC_SUFFIX_RULES.some((r) => r.startsWith('!'))).toBe(true);
  });

  it('contains no comments or blanks — the parse happened at build time', () => {
    for (const rule of PUBLIC_SUFFIX_RULES) {
      expect(rule.startsWith('//')).toBe(false);
      expect(rule.trim()).toBe(rule);
      expect(rule.length).toBeGreaterThan(0);
    }
  });
});
