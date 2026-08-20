/**
 * Pack `dist/` into a BYTE-REPRODUCIBLE ZIP, with no dependencies.
 *
 * WHY THIS EXISTS. docs/04 M16 commits PR4 to reproducible builds, and a third
 * party can only check a build by rebuilding it and comparing a digest. The
 * compile is already reproducible — measured, not assumed: `tsc` and the whole
 * three-step pipeline emit byte-identical trees across runs, there is no
 * `incremental`/`composite` so no `.tsbuildinfo` state, and TypeScript's
 * `getNewLineCharacter` returns LF regardless of platform. The ZIP was the only
 * step that was not, and it was non-deterministic in FIVE independent ways, each
 * measured against `zip 3.0` by producing two archives that differed:
 *
 *   1. MTIME       — ZIP stores an MS-DOS date/time per entry.
 *   2. ENTRY ORDER — directory-walk order is filesystem-dependent.
 *   3. FILE MODE   — the Unix mode lives in the central directory, and `-X`
 *                    does NOT strip it.
 *   4. EXTRA FIELDS— Info-ZIP adds UID/GID and extended timestamps by default,
 *                    which differ between a laptop and a CI runner.
 *   5. DEFLATE     — the level, and the zlib implementation behind it.
 *
 * WHY NOT `zip -X`. With all five pinned the CLI is reproducible on ONE machine,
 * so it is not disqualified — but factors 3–5 then depend on whichever Info-ZIP
 * and zlib the runner ships, which is exactly the variable a reproducibility
 * claim must not rest on.
 *
 * HOW EACH FACTOR IS PINNED. Four are pinned; the fifth is REMOVED:
 *   · names sorted with a plain codepoint `.sort()`, so order is content-derived
 *   · DOS date/time fixed at the epoch this file declares, never `Date.now()`
 *   · external attributes fixed at 0644, so a developer's umask cannot leak in
 *   · no extra fields at all, in either the local header or the central record
 *   · every entry is STORED — see below
 *
 * ═══ NOTHING IS COMPRESSED, AND THAT IS THE POINT ═══
 *
 * The first version of this file deflated at level 9 and treated the zlib
 * IMPLEMENTATION as a variable to pin by pinning Node, with a comment conceding
 * that stability across Node releases was "unverified". Then the first CI run
 * measured it, and the concession was too generous: CI's archive was 118,147
 * bytes where the same commit on a laptop produced 118,875 — 40 of 42 entries
 * compressing differently, one of them LARGER, with every CRC and uncompressed
 * size identical. Same Node version on both.
 *
 * The cause is not the version and not the CPU. It is HOW NODE WAS BUILT:
 * Homebrew's node is `node_shared_zlib: true` against system zlib 1.2.12, while
 * official builds vendor Chromium's zlib (1.3.1-e00f703). Isolated by running
 * this packer under official `node:22` in Docker on arm64, which reproduced the
 * x86-64 CI digest EXACTLY — so architecture is irrelevant and the zlib build
 * is everything. Two people on the same OS with the same `node -v` get
 * different digests depending on whether they installed Node from Homebrew or
 * from nodejs.org.
 *
 * That is fatal to the only claim this file exists to support. A verification
 * procedure whose failure mode is "your digest differs, and the remedy is a
 * paragraph about how you installed Node" trains people to shrug at exactly the
 * signal it was built to raise.
 *
 * So the variable is removed rather than labelled: METHOD 0, every entry. The
 * archive is then a pure function of the file bytes plus the four constants
 * above — no zlib, no Node, no platform. It also becomes TESTABLE, which the
 * deflate factor never was from inside one Node: `pack.spec.ts` asserts no
 * entry uses method 8.
 *
 * The cost is size — roughly 350 KB instead of 118 KB — which is nothing
 * against being checkable by a stranger, and is invisible to the store, which
 * repackages into its own CRX3 regardless. (UNVERIFIED, like the
 * directory-entry note below: whether any store's tooling objects to a
 * fully-stored archive. Checked at first submission.)
 *
 * The COMPILE, meanwhile, is reproducible and now measured to be: all 42
 * entries matched by CRC and uncompressed size across macOS/arm64 with a
 * Homebrew Node and Linux/x86-64 with an official one. There is no
 * `incremental`/`composite` so no `.tsbuildinfo` state, and TypeScript emits LF
 * regardless of platform.
 */
import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { crc32 } from 'node:zlib';

/**
 * A FIXED TIMESTAMP, because a build's inputs do not include the clock.
 *
 * 1980-01-01 00:00:00 is the earliest value the MS-DOS format can express, so
 * it is the one choice that is obviously a constant rather than a plausible
 * build time somebody might later read as meaningful.
 */
const DOS_EPOCH_TIME = 0;
const DOS_EPOCH_DATE = 0x21; // 1980-01-01

/** 0644, shifted into the high half where the ZIP spec keeps the Unix mode. */
const FIXED_EXTERNAL_ATTRS = (0o100644 << 16) >>> 0;

/** ZIP compression method 0. Method 8 is deflate, and is never used here. */
const STORED = 0;

/**
 * General-purpose bit 11: "the filename is UTF-8".
 *
 * Names are written with `Buffer.from(name, 'utf8')`, and with this flag clear
 * the spec says an extractor should read them as CP437 — so an accented
 * filename would extract under a mangled name. Every name in `dist` is ASCII
 * today, where the two encodings agree, which is exactly why this was easy to
 * miss and cheap to fix.
 */
const UTF8_NAMES = 0x0800;

/**
 * version-made-by: host 3 (Unix) in the high byte, spec 2.0 in the low.
 *
 * It said 0 (MS-DOS/FAT), which contradicts putting a Unix mode in the external
 * attributes below — under FAT those bytes mean DOS attribute flags, so the
 * fixed 0644 was a field extractors were entitled to read as something else.
 */
const VERSION_MADE_BY = (3 << 8) | 20;

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/** Every file under `dir`, as slash-separated paths relative to it. */
async function filesUnder(dir) {
  const out = [];
  const walk = async (current) => {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile()) out.push(relative(dir, full).split(sep).join('/'));
    }
  };
  await walk(dir);
  return out;
}

/**
 * Build the archive.
 *
 * Directory ENTRIES are deliberately not emitted — only slash-bearing file
 * names. Every extractor tested creates the parents, and an entry carrying a
 * mode and a timestamp is one more thing to pin. (UNVERIFIED: whether the
 * Chrome Web Store accepts an archive with no directory records. It is checked
 * at first submission, and the procedure says so rather than assuming.)
 */
export async function packDirectory(dir) {
  const names = (await filesUnder(dir)).sort();
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const name of names) {
    const raw = await readFile(join(dir, name));
    // STORED, always — see the header. Compression is the one factor that
    // cannot be pinned from inside this file, because the zlib behind
    // `node:zlib` depends on how the reader's Node was built.
    const body = raw;
    const method = STORED;
    const nameBytes = Buffer.from(name, 'utf8');
    const sum = crc32(raw);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(UTF8_NAMES, 6); // no data descriptor; names are UTF-8
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(DOS_EPOCH_TIME, 10);
    local.writeUInt16LE(DOS_EPOCH_DATE, 12);
    local.writeUInt32LE(sum, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28); // extra field length: none, ever
    locals.push(local, nameBytes, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(VERSION_MADE_BY, 4);
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(UTF8_NAMES, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(DOS_EPOCH_TIME, 12);
    central.writeUInt16LE(DOS_EPOCH_DATE, 14);
    central.writeUInt32LE(sum, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk number
    central.writeUInt16LE(0, 36); // internal attrs
    central.writeUInt32LE(FIXED_EXTERNAL_ATTRS, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);

    offset += local.length + nameBytes.length + body.length;
  }

  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20); // no archive comment

  return { zip: Buffer.concat([...locals, centralBytes, end]), entries: names.length };
}

// Run main only when this file IS the entry point, so importing `packDirectory`
// from the test does not write an archive.
//
// BOTH SIDES ARE RESOLVED, because each repairs a distortion the other does
// not. `pathToFileURL` repairs the SPACE that broke the original
// `file://${process.argv[1]}` template (M16 PR4b). `realpathSync` repairs the
// SYMLINK, which that fix did not: node reports the RESOLVED REAL path in
// `import.meta.url` and the path AS TYPED in `process.argv[1]`.
//
// WHICH SYMLINKS REACH THIS, measured rather than assumed — and the distinction
// is why the defect survived PR4b's own check. argv[1] is resolved against the
// PHYSICAL cwd, so every symlink ABOVE the working directory is collapsed and
// can never be seen: that is why running the packer from `/tmp/has space/probe`
// passed on a macOS whose /tmp IS a symlink to /private/tmp. A symlink AT OR
// BELOW the working directory is NOT collapsed — the segments stay in argv[1]
// as typed while `import.meta.url` resolves them — so
// `node apps/vault-extension/scripts/pack-extension.mjs` from a root where any
// of those segments is a link compares .../root/apps/... against the resolved
// .../root/real/..., and so does any absolute-path invocation through a link.
//
// IT FAILS SILENTLY IN THE REASSURING DIRECTION, which is what makes it worth a
// guard rather than a note. That command is VERIFYING.md's own, and the line
// after it there is `sha256sum` on the archive. Measured: with the guard
// unfired the packer exits 0 having written and printed nothing, so that hash
// is of the archive LEFT BY AN EARLIER RUN — a digest MATCH reported for a
// build that never happened, in the one procedure whose entire purpose is to
// detect that the bytes are not what they claim to be.
//
// `realpathSync` THROWS rather than answering "not the entry point" when
// argv[1] names nothing on disk. That is deliberate and it is the safe
// direction: argv[1] is the script node is running, so it exists — the only way
// to reach the throw is an `-e` invocation carrying a trailing argument, and
// swallowing it would mean a guard that silently declines to fire, which is the
// entire defect this shape exists to prevent.
const entryPoint =
  process.argv[1] === undefined ? undefined : pathToFileURL(realpathSync(process.argv[1])).href;
if (import.meta.url === entryPoint) {
  const dir = process.env.PACK_DIR ?? join(root, 'dist');
  const out = process.env.PACK_OUT ?? join(root, 'vault-extension.zip');
  await stat(dir); // fail loudly if there is nothing built to pack
  const { zip, entries } = await packDirectory(dir);
  await writeFile(out, zip);
  const digest = createHash('sha256').update(zip).digest('hex');
  process.stdout.write(
    `${digest}  ${out}\n${String(entries)} entries, ${String(zip.length)} bytes, node ${process.version}\n`,
  );
}
