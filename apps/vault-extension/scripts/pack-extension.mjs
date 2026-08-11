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
 * claim must not rest on. Writing the archive here pins deflate to the Node
 * version the repo already pins (`engines: node >= 22.11`), which is a
 * dependency this project has anyway. Same reasoning as the node:crypto webhook
 * verifier and the node:net clamd client: no new dependency on a path whose
 * whole job is to be checkable.
 *
 * HOW EACH FACTOR IS PINNED:
 *   · names sorted with a plain codepoint `.sort()`, so order is content-derived
 *   · DOS date/time fixed at the epoch this file declares, never `Date.now()`
 *   · external attributes fixed at 0644, so a developer's umask cannot leak in
 *   · no extra fields at all, in either the local header or the central record
 *   · `deflateRawSync({ level: 9 })`, so the level is stated rather than default
 *
 * STILL OPEN, and stated rather than implied: whether deflate output is stable
 * across Node PATCH releases within a major is unverified. The published
 * procedure therefore records the exact Node version a digest was produced with,
 * and a Node bump is a reviewed republish rather than a silent difference.
 */
import { createHash } from 'node:crypto';
import { readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32, deflateRawSync } from 'node:zlib';

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
    const deflated = deflateRawSync(raw, { level: 9 });
    // A store's own tooling has been known to reject an entry whose compressed
    // form is larger than the original, and it is also simply wrong to spend
    // bytes on it, so such an entry is STORED instead.
    const useDeflate = deflated.length < raw.length;
    const body = useDeflate ? deflated : raw;
    const method = useDeflate ? 8 : 0;
    const nameBytes = Buffer.from(name, 'utf8');
    const sum = crc32(raw);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // no flags — notably no data descriptor
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
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0, 8);
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

if (import.meta.url === `file://${process.argv[1]}`) {
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
