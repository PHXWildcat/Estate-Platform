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

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;

/** Pack a directory in a subprocess and return the archive bytes. */
function packBytes(dir: string): Buffer {
  const out = join(mkdtempSync(join(tmpdir(), 'zip-')), 'out.zip');
  execFileSync(process.execPath, [PACKER], {
    env: { ...process.env, PACK_DIR: dir, PACK_OUT: out },
    stdio: 'pipe',
  });
  return execFileSync('cat', [out], { encoding: 'buffer' });
}

function digestOf(dir: string): string {
  return createHash('sha256').update(packBytes(dir)).digest('hex');
}

interface Entry {
  name: string;
  centralMethod: number;
  localMethod: number;
  centralExtraLength: number;
  centralCommentLength: number;
  localExtraLength: number;
  centralFlags: number;
  localFlags: number;
  versionMadeBy: number;
  internalAttrs: number;
  externalAttrs: number;
  centralTime: number;
  centralDate: number;
  localTime: number;
  localDate: number;
}

/**
 * WALK THE ARCHIVE THE WAY AN EXTRACTOR DOES, from the end-of-central-directory
 * record through each central record to its local header.
 *
 * Every case here used to scan the whole file for signature bytes, and that is
 * wrong twice over. It reads the LOCAL headers only, which is how the
 * extra-fields case missed 462 bytes of uid/gid living in the CENTRAL directory
 * — a real mutation that both CI checks passed. And now that entries are
 * STORED, file content is raw in the archive, so a `.js` file containing the
 * four bytes `PK\x03\x04` would be counted as an entry that does not exist.
 *
 * Following the structure removes both. It also verifies the linkage: a central
 * record whose offset does not land on a local header is itself a defect.
 */
function readArchive(zip: Buffer): Entry[] {
  let eocd = -1;
  for (let i = zip.length - 22; i >= 0; i -= 1) {
    if (zip.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('no end-of-central-directory record');

  const count = zip.readUInt16LE(eocd + 10);
  let at = zip.readUInt32LE(eocd + 16);
  const entries: Entry[] = [];
  for (let n = 0; n < count; n += 1) {
    if (zip.readUInt32LE(at) !== SIG_CENTRAL) {
      throw new Error(`central record ${String(n)} not where the directory says it is`);
    }
    const nameLength = zip.readUInt16LE(at + 28);
    const centralExtraLength = zip.readUInt16LE(at + 30);
    const centralCommentLength = zip.readUInt16LE(at + 32);
    const localAt = zip.readUInt32LE(at + 42);
    const name = zip.subarray(at + 46, at + 46 + nameLength).toString('utf8');
    if (zip.readUInt32LE(localAt) !== SIG_LOCAL) {
      throw new Error(`central record for ${name} points at no local header`);
    }
    entries.push({
      name,
      centralMethod: zip.readUInt16LE(at + 10),
      localMethod: zip.readUInt16LE(localAt + 8),
      centralExtraLength,
      centralCommentLength,
      localExtraLength: zip.readUInt16LE(localAt + 28),
      centralFlags: zip.readUInt16LE(at + 8),
      localFlags: zip.readUInt16LE(localAt + 6),
      versionMadeBy: zip.readUInt16LE(at + 4),
      internalAttrs: zip.readUInt16LE(at + 36),
      externalAttrs: zip.readUInt32LE(at + 38),
      centralTime: zip.readUInt16LE(at + 12),
      centralDate: zip.readUInt16LE(at + 14),
      localTime: zip.readUInt16LE(localAt + 10),
      localDate: zip.readUInt16LE(localAt + 12),
    });
    at += 46 + nameLength + centralExtraLength + centralCommentLength;
  }
  return entries;
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
     * Reading the names out of the archive tests the CONTRACT — entries come
     * out in codepoint order — which catches any writer that reorders them:
     * grouping directories first, insertion order from a Map, reversing.
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
    const names = readArchive(packBytes(build([...FILES].reverse()))).map((e) => e.name);
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

  it('carries NO extra fields IN EITHER DIRECTORY, so no uid/gid can leak in', () => {
    /*
     * THIS CASE FAILED TO CATCH A REAL MUTATION, WHICH IS WHY IT LOOKS LIKE
     * THIS NOW.
     *
     * It used to check the LOCAL headers only. An adversarial review agent
     * added an Info-ZIP `ux` field — `process.getuid()` and `getgid()`, 11
     * bytes per entry — to the CENTRAL records alone, and this case stayed
     * green while 462 bytes of the builder's identity went into every archive.
     * So did the whole pipeline: the `package` job builds twice on ONE runner,
     * where both builds share a uid, so their digests agreed. Nothing saw it.
     *
     * A ZIP keeps two records per entry and an extractor may read either, so
     * "no extra fields" is a claim about BOTH. Comment lengths too: the field
     * next door is just as good a place to put a build host's name.
     */
    const entries = readArchive(packBytes(build(FILES)));
    expect(entries).toHaveLength(FILES.length);
    expect(
      entries.map((e) => ({
        name: e.name,
        localExtraLength: e.localExtraLength,
        centralExtraLength: e.centralExtraLength,
        centralCommentLength: e.centralCommentLength,
      })),
    ).toEqual(
      [...FILES].sort().map((name) => ({
        name,
        localExtraLength: 0,
        centralExtraLength: 0,
        centralCommentLength: 0,
      })),
    );
  });

  it('STORES every entry, so no zlib can reach the digest', () => {
    /*
     * The load-bearing one, and the only reason this archive is checkable by
     * someone who did not install their Node the way we installed ours.
     * `node:zlib`'s deflate output depends on the zlib Node was BUILT against,
     * which differs between a Homebrew node (shared, 1.2.12) and an official
     * one (vendored Chromium, 1.3.1-e00f703) — measured, on the same version.
     *
     * Read out of the headers rather than inferred from sizes: an entry that
     * happens not to compress is not the same fact as a writer that never
     * compresses. Method 0 is STORED, method 8 is deflate — and BOTH records
     * must say so, since an extractor may believe either.
     */
    // The fixture must be worth compressing or this proves nothing — see
    // `bodyFor`. Asserted rather than assumed, because a future edit that
    // shrinks it would silently disarm the case instead of failing it.
    const big = Buffer.from(bodyFor(COMPRESSIBLE));
    expect(deflateRawSync(big, { level: 9 }).length).toBeLessThan(big.length);

    const entries = readArchive(packBytes(build(FILES)));
    expect(entries).toHaveLength(FILES.length);
    expect(
      entries.map((e) => ({ name: e.name, local: e.localMethod, central: e.centralMethod })),
    ).toEqual([...FILES].sort().map((name) => ({ name, local: 0, central: 0 })));
  });

  it('produces EXACTLY these bytes for a known tree — the catch-all', () => {
    /*
     * EVERY OTHER CASE HERE CHECKS A FIELD SOMEBODY THOUGHT OF, and three
     * independent review lenses found the same hole in that approach: the
     * perturbation cases vary mtime, mode and content and assert the digest
     * does not move, and the structural cases assert that certain LENGTHS and
     * METHODS are zero — but nothing asserted the VALUE of any pinned field.
     * A writer folding the builder's identity into the external attributes,
     * the internal attributes, version-made-by, the DOS date/time words or the
     * archive comment at the end of the file passed all eight, and passed CI's
     * double build too, because two builds on one runner share an identity.
     *
     * A golden digest has no such blind spot: it is the whole artifact. Any
     * byte that changes anywhere turns this red, including bytes in fields
     * nobody has thought of yet, which is the only kind that matters.
     *
     * It is deliberately BRITTLE. An intentional change to the archive format
     * must edit this constant, and that edit is the review — the same argument
     * as every other reviewed constant in this repo. The cases above stay
     * because when this one fails they say WHY.
     */
    expect(digestOf(build(FILES))).toBe(
      '95e9c6136ebf484cda5587b61badd9900bde861bad29f3e90b3269bcc8cd689f',
    );
  });

  it('pins the VALUE of every fixed header field, not just its length', () => {
    // Diagnosability for the golden digest above: when it moves, this says
    // which field moved. The values are the packer's own constants.
    const entries = readArchive(packBytes(build(FILES)));
    expect(entries).toHaveLength(FILES.length);
    for (const e of entries) {
      expect(e).toMatchObject({
        // 0x0800 = general-purpose bit 11, "the filename is UTF-8". Names are
        // written as UTF-8, so with this clear an extractor is entitled to read
        // an accented name as CP437 and mangle it.
        localFlags: 0x0800,
        centralFlags: 0x0800,
        // Host 3 (Unix) in the high byte. It said 0 (MS-DOS/FAT), under which
        // the external attributes below mean DOS attribute flags rather than a
        // Unix mode — so the fixed 0644 was a field extractors could ignore.
        versionMadeBy: (3 << 8) | 20,
        internalAttrs: 0,
        externalAttrs: (0o100644 << 16) >>> 0,
        // 1980-01-01 00:00, the earliest MS-DOS can express: obviously a
        // constant rather than a plausible build time. Asserted in BOTH
        // records, because a clock reaching only one of them would still leave
        // the mtime perturbation case green.
        localTime: 0,
        localDate: 0x21,
        centralTime: 0,
        centralDate: 0x21,
      });
    }
  });

  it('ends with NO archive comment, the one field that is not per-entry', () => {
    // The end-of-central-directory record has its own comment, outside every
    // per-entry check above — room for a hostname that no entry-level
    // assertion would ever see.
    const zip = packBytes(build(FILES));
    let eocd = -1;
    for (let i = zip.length - 22; i >= 0; i -= 1) {
      if (zip.readUInt32LE(i) === SIG_EOCD) {
        eocd = i;
        break;
      }
    }
    expect(eocd).toBeGreaterThanOrEqual(0);
    expect(zip.readUInt16LE(eocd + 20)).toBe(0);
    // And the record really is last: a non-empty comment would sit after it.
    expect(eocd + 22).toBe(zip.length);
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
