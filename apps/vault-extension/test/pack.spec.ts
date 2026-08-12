/**
 * THE ARCHIVE IS REPRODUCIBLE, AND EACH REASON IS ASSERTED SEPARATELY.
 *
 * "Two runs matched" is the weakest possible version of this test: two runs on
 * one machine, seconds apart, match for reasons that have nothing to do with the
 * writer — the mtimes did not change, the walk order did not change, the umask
 * did not change. A third party rebuilding this on another machine, another day,
 * hits all three. So the cases below CHANGE each variable and assert the digest
 * does not move.
 *
 * The five were measured against `zip 3.0` while designing the writer, each
 * producing a differing archive: mtime, entry order, file mode, Info-ZIP extra
 * fields, and deflate.
 *
 * THE FIFTH IS NOT PINNED, IT IS REMOVED, and that changed after the first CI
 * run measured it: the same commit produced 118,147 bytes on the runner and
 * 118,875 on a laptop, all 42 CRCs and uncompressed sizes identical, 40 entries
 * compressing differently. The cause is how Node was BUILT — Homebrew links
 * system zlib, official builds vendor Chromium's — not its version and not the
 * CPU, isolated by reproducing the runner's digest exactly under official
 * `node:22` on a different architecture. So every entry is STORED, and the
 * factor that could never be tested from inside one Node becomes the assertion
 * below.
 *
 * A subprocess, because ts-jest cannot import a plain `.mjs` — the `psl.spec.ts`
 * precedent.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PACKER = join(__dirname, '..', 'scripts', 'pack-extension.mjs');

/** Pack a directory in a subprocess and return the archive's digest. */
function digestOf(dir: string): string {
  const out = join(mkdtempSync(join(tmpdir(), 'zip-')), 'out.zip');
  execFileSync(process.execPath, [PACKER], {
    env: { ...process.env, PACK_DIR: dir, PACK_OUT: out },
    stdio: 'pipe',
  });
  const bytes = execFileSync('cat', [out], { encoding: 'buffer' });
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * ONE FIXTURE MUST BE WORTH COMPRESSING, and the reason is a mutation this
 * file's own harness caught. Every fixture was originally an 18-byte line —
 * and 18 bytes deflate LARGER than they store, so the writer's old
 * `deflated.length < raw.length` branch was never taken. Reintroducing deflate
 * verbatim left the "STORES every entry" case GREEN: the fixtures made the
 * mutation unobservable, which is the "named for a property it never touched"
 * shape this repo keeps finding.
 *
 * `big.js` is long and repetitive, so any writer that would compress does.
 */
const COMPRESSIBLE = 'big.js';
const FILES = ['a.js', 'b.js', COMPRESSIBLE, 'lib/c.js'] as const;

function bodyFor(name: string): string {
  return name === COMPRESSIBLE
    ? 'the same line over and over\n'.repeat(400)
    : `contents of ${name}\n`;
}

/** A small tree, created in a caller-chosen order so order can be varied. */
function tree(order: readonly string[]): string {
  const dir = mkdtempSync(join(tmpdir(), 'src-'));
  mkdirSync(join(dir, 'lib'), { recursive: true });
  for (const name of order) {
    writeFileSync(join(dir, name), bodyFor(name));
    // Pin mtimes so a case that is not ABOUT mtime does not vary by it.
    utimesSync(join(dir, name), new Date(2020, 0, 1), new Date(2020, 0, 1));
  }
  return dir;
}

describe('the packaged archive is reproducible', () => {
  const made: string[] = [];
  afterAll(() => {
    for (const dir of made) rmSync(dir, { recursive: true, force: true });
  });
  const build = (order: readonly string[]): string => {
    const dir = tree(order);
    made.push(dir);
    return dir;
  };

  it('is byte-identical for identical content', () => {
    const dir = build(FILES);
    expect(digestOf(dir)).toBe(digestOf(dir));
  });

  it('does not change when MTIMES change', () => {
    // The classic culprit: ZIP stores an MS-DOS date/time per entry, so an
    // archive built from the same bytes an hour later differs. The writer pins
    // a constant, and this moves the clock to prove it.
    const dir = build(FILES);
    const before = digestOf(dir);
    for (const name of FILES) {
      utimesSync(join(dir, name), new Date(2031, 5, 5), new Date(2031, 5, 5));
    }
    expect(digestOf(dir)).toBe(before);
  });

  it('writes entries in SORTED order, whatever readdir returned', () => {
    /*
     * ASSERTED OVER THE BYTES, and the first version of this case was not.
     *
     * It built the same tree in two creation orders and compared digests —
     * which passed with the writer's `.sort()` REMOVED, because APFS returns
     * directory entries in a stable name-derived order anyway. The test was
     * measuring this filesystem rather than the writer.
     *
     * Reading the names out of the local headers tests the CONTRACT — entries
     * come out in codepoint order — which catches any writer that reorders
     * them: grouping directories first, insertion order from a Map, reversing.
     *
     * WHAT IT STILL CANNOT CATCH, stated rather than implied: deleting the
     * `.sort()` itself. Measured — `readdir` on APFS returns names already in
     * codepoint order (`9nine ALPHA2 Mango _under alpha beta lib zebra`), so on
     * this filesystem the sort is a no-op and no arrangement of files can
     * provoke it. It is defence for filesystems that return creation or inode
     * order, and this machine is not one. The M16 PR3a shape: a branch the local
     * environment cannot exercise, recorded here instead of credited with
     * coverage it does not have.
     */
    const dir = build([...FILES].reverse());
    const out = join(mkdtempSync(join(tmpdir(), 'zip-')), 'out.zip');
    execFileSync(process.execPath, [PACKER], {
      env: { ...process.env, PACK_DIR: dir, PACK_OUT: out },
      stdio: 'pipe',
    });
    const zip = execFileSync('cat', [out], { encoding: 'buffer' });

    const names: string[] = [];
    for (let i = 0; i + 30 <= zip.length; i += 1) {
      if (zip.readUInt32LE(i) !== 0x04034b50) continue;
      const length = zip.readUInt16LE(i + 26);
      names.push(zip.subarray(i + 30, i + 30 + length).toString('utf8'));
    }
    expect(names).toEqual([...names].sort());
    expect(names).toEqual([...FILES].sort());
  });

  it('does not change when a FILE MODE changes', () => {
    // The Unix mode lives in the central directory and `zip -X` does NOT strip
    // it, so a developer's umask would otherwise reach the artifact.
    const dir = build(FILES);
    const before = digestOf(dir);
    chmodSync(join(dir, 'a.js'), 0o600);
    expect(digestOf(dir)).toBe(before);
  });

  it('carries NO extra fields, so no uid/gid or timestamp can leak in', () => {
    // Asserted over the bytes rather than inferred: every local header's extra
    // length field (offset 28) must be zero. Info-ZIP's default is not.
    const dir = build(FILES);
    const out = join(mkdtempSync(join(tmpdir(), 'zip-')), 'out.zip');
    execFileSync(process.execPath, [PACKER], {
      env: { ...process.env, PACK_DIR: dir, PACK_OUT: out },
      stdio: 'pipe',
    });
    const zip = execFileSync('cat', [out], { encoding: 'buffer' });
    let found = 0;
    for (let i = 0; i + 30 <= zip.length; i += 1) {
      if (zip.readUInt32LE(i) !== 0x04034b50) continue;
      found += 1;
      expect({ header: found, extraLength: zip.readUInt16LE(i + 28) }).toEqual({
        header: found,
        extraLength: 0,
      });
    }
    expect(found).toBe(FILES.length);
  });

  it('STORES every entry, so no zlib can reach the digest', () => {
    /*
     * The load-bearing one, and the only reason this archive is checkable by
     * someone who did not install their Node the way we installed ours.
     * `node:zlib`'s deflate output depends on the zlib Node was BUILT against,
     * which differs between a Homebrew node (shared, 1.2.12) and an official
     * one (vendored Chromium, 1.3.1-e00f703) — measured, on the same version.
     *
     * Read out of the local headers rather than inferred from sizes: an entry
     * that happens not to compress is not the same fact as a writer that never
     * compresses. Method 0 is STORED, method 8 is deflate.
     */
    // The fixture must be worth compressing or this proves nothing — see
    // `bodyFor`. Asserted rather than assumed, because a future edit that
    // shrinks it would silently disarm the case instead of failing it.
    const big = Buffer.from(bodyFor(COMPRESSIBLE));
    expect(deflateRawSync(big, { level: 9 }).length).toBeLessThan(big.length);

    const dir = build(FILES);
    const out = join(mkdtempSync(join(tmpdir(), 'zip-')), 'out.zip');
    execFileSync(process.execPath, [PACKER], {
      env: { ...process.env, PACK_DIR: dir, PACK_OUT: out },
      stdio: 'pipe',
    });
    const zip = execFileSync('cat', [out], { encoding: 'buffer' });

    const methods: number[] = [];
    for (let i = 0; i + 30 <= zip.length; i += 1) {
      if (zip.readUInt32LE(i) === 0x04034b50) methods.push(zip.readUInt16LE(i + 8));
      // The central directory keeps its own copy, and an extractor may believe
      // either — so both must say stored.
      if (zip.readUInt32LE(i) === 0x02014b50) methods.push(zip.readUInt16LE(i + 10));
    }
    expect(methods).toHaveLength(FILES.length * 2);
    expect(methods.every((m) => m === 0)).toBe(true);
  });

  it('changes when the CONTENT changes, so the digest means something', () => {
    // Anti-vacuity: a writer that ignored its input would pass every case above.
    const dir = build(FILES);
    const before = digestOf(dir);
    writeFileSync(join(dir, 'a.js'), 'different\n');
    utimesSync(join(dir, 'a.js'), new Date(2020, 0, 1), new Date(2020, 0, 1));
    expect(digestOf(dir)).not.toBe(before);
  });

  it('produces an archive a real unzip accepts', () => {
    // The writer is hand-rolled, so "reproducible" is worth nothing unless the
    // bytes are also a valid ZIP that extracts to what went in.
    const dir = build(FILES);
    const out = join(mkdtempSync(join(tmpdir(), 'zip-')), 'out.zip');
    execFileSync(process.execPath, [PACKER], {
      env: { ...process.env, PACK_DIR: dir, PACK_OUT: out },
      stdio: 'pipe',
    });
    expect(() => execFileSync('unzip', ['-t', out], { stdio: 'pipe' })).not.toThrow();
    const listing = execFileSync('unzip', ['-Z', '-1', out], { encoding: 'utf8' })
      .split('\n')
      .filter((line) => line.length > 0)
      .sort();
    expect(listing).toEqual([...FILES].sort());
  });
});
