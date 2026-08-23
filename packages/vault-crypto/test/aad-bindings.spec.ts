/**
 * WHAT EVERY AAD BINDS, declared as data (M27 PR1a).
 *
 * WHY THIS EXISTS. Migration 005 splits `vault_items.revision` out of
 * `blob_version` because one integer was doing two contradictory jobs: an AEAD
 * binding that must travel with its ciphertext and may recur, and a concurrency
 * token that must never recur. The migration justified touching exactly one
 * table by asserting a fact about the tree — that `itemContentAad` is the ONLY
 * additional-authenticated-data builder here binding a mutable per-write
 * counter, so no other table carries the same conflation.
 *
 * THAT COMMENT WAS WRONG IN ITS DETAIL WHEN IT WAS WRITTEN. It hand-listed the
 * other builders as `fieldAad`, `aliasAad`, `itemKeyAad`, `masterKeyAad`,
 * `recoveryWrapAad` and `shareAad`. Two of those names do not exist and never
 * did, and the list omitted every AAD that is built inline rather than by a
 * named function — which is all of Zone B's. The CLAIM survived the check; the
 * list supporting it did not. A comment that justifies an omission by asserting
 * a fact about the tree is a test nobody runs, so the tree becomes the input
 * here and the migration points at this spec instead of restating a list.
 *
 * ANCHORED ON THE LITERAL, NOT THE FUNCTION NAME. The key of each entry is the
 * string the runtime actually feeds to AEAD. A builder renamed tomorrow still
 * produces `estate.vault.item.v1|…`, so this fence cannot be renamed into
 * invisibility — the failure mode a name-keyed fence has here.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO = join(__dirname, '..', '..', '..');
const ZONE_A_SRC = join(REPO, 'packages', 'vault-crypto', 'src');
const ZONE_B_SERVICES = join(REPO, 'apps', 'services');

/** Every string literal whose content starts with `estate.` — Zone A's whole domain vocabulary. */
const ESTATE_LITERAL = /[`'"](estate\.[^`'"]*)[`'"]/g;
/** The interpolated components of one literal, in source order. */
const INTERPOLATION = /\$\{([^}]*)\}/g;

/**
 * Component names that read as a per-write counter. This is the property the
 * migration turns on, so it is checked mechanically rather than by eye: a NEW
 * AAD that interpolates something matching this must be declared `mutable`,
 * and a second `mutable` entry fails the build regardless of what it is called.
 */
const COUNTER_LIKE = /version|revision|seq|counter|generation/i;

interface Binding {
  /** The file that builds it — asserted, so a literal moving package is visible. */
  readonly file: string;
  /** Interpolated components, in order. `[]` means a constant domain separator. */
  readonly binds: readonly string[];
  /** Does any component change when the row it protects is REWRITTEN? */
  readonly mutable: boolean;
  readonly why: string;
}

/**
 * ZONE A, declared. A reason per entry, because "which literals exist" is
 * answerable by the scan below and "what each one is allowed to bind" is not.
 */
const ZONE_A: Readonly<Record<string, Binding>> = {
  'estate.vault.item.v1|${ref.userId}|${ref.itemId}|${ref.blobVersion}': {
    file: 'items.ts',
    binds: ['ref.userId', 'ref.itemId', 'ref.blobVersion'],
    mutable: true,
    why:
      'THE ONE. Item content is sealed against the version it will be written ' +
      'at, so a blob only opens when the reader is told the same number. That ' +
      'is why the version must travel with the ciphertext and may RECUR when a ' +
      'restore puts a captured version back — and why it cannot also be the ' +
      'concurrency token, which is `vault_items.revision` since migration 005.',
  },
  'estate.vault.wrap.itemkey.v1|${userId}|${itemId}': {
    file: 'items.ts',
    binds: ['userId', 'itemId'],
    mutable: false,
    why: 'Wraps a per-item key to its owner and item. Both identities are immutable.',
  },
  'estate.vault.wrap.master.v1|${userId}': {
    file: 'keyset.ts',
    binds: ['userId'],
    mutable: false,
    why: 'Wraps the master key to its owner. Rewrapping under a new AUK keeps the same AAD.',
  },
  'estate.vault.wrap.recovery.v1|${ownerUserId}': {
    file: 'recovery.ts',
    binds: ['ownerUserId'],
    mutable: false,
    why: 'Wraps the recovery copy of the master key to the owner alone.',
  },
  'estate.vault.share.v1|${ownerUserId}|${granteeUserId}|${publicKeySha256Base64}': {
    file: 'recovery.ts',
    binds: ['ownerUserId', 'granteeUserId', 'publicKeySha256Base64'],
    mutable: false,
    why:
      'Binds a share to BOTH parties and to the exact grantee key that may open ' +
      'it. The digest changes only when the grantee rotates keys, which mints a ' +
      'new share rather than rewriting one — so it is an identity, not a counter.',
  },
  'estate.vault.grantee-key.v1': {
    file: 'ecies.ts',
    binds: [],
    mutable: false,
    why: 'Domain separator for the grantee public-key digest. Not an AEAD input.',
  },
  'estate.vault.ecies.v1': {
    file: 'ecies.ts',
    binds: [],
    mutable: false,
    why: 'HKDF info for the ECIES shared secret. Not an AEAD input.',
  },
  'estate.vault.keyset.v1': {
    file: 'keyset.ts',
    binds: [],
    mutable: false,
    why: 'Constant AAD over the serialised keyset envelope.',
  },
  'estate.vault.2skd.salt.v1': {
    file: 'kdf.ts',
    binds: [],
    mutable: false,
    why: '2SKD salt domain separator.',
  },
  'estate.vault.2skd.sk.v1': {
    file: 'kdf.ts',
    binds: [],
    mutable: false,
    why: '2SKD Secret Key domain separator.',
  },
  'estate.vault.auk.v1': {
    file: 'kdf.ts',
    binds: [],
    mutable: false,
    why: 'Account Unlock Key domain separator.',
  },
  'estate.vault.srp-x.v1': {
    file: 'kdf.ts',
    binds: [],
    mutable: false,
    why: 'SRP private-key domain separator.',
  },
  'estate.vault.keyset-auth.v1': {
    file: 'kdf.ts',
    binds: [],
    mutable: false,
    why: 'Keyset authentication key domain separator.',
  },
};

function tsFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist' || entry === 'dist-esm') continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...tsFilesUnder(full));
    else if (entry.endsWith('.ts') && !entry.endsWith('.spec.ts')) out.push(full);
  }
  return out;
}

/** literal -> the basename that builds it. */
function scanZoneA(): Map<string, string> {
  const found = new Map<string, string>();
  for (const entry of readdirSync(ZONE_A_SRC).filter((n) => n.endsWith('.ts'))) {
    const source = readFileSync(join(ZONE_A_SRC, entry), 'utf8');
    for (const match of source.matchAll(ESTATE_LITERAL)) found.set(match[1] as string, entry);
  }
  return found;
}

describe('what every AAD binds, and the one that binds a counter (M27 PR1a)', () => {
  const scanned = scanZoneA();

  it('finds a corpus at all, and in more than one file', () => {
    // ANTI-VACUITY, AT EVERY LEVEL. A regex that silently stopped matching and
    // a tree with no AADs left look identical, and a total alone cannot see a
    // whole file drop out — so the floor is stated per level, not once.
    expect(scanned.size).toBeGreaterThanOrEqual(13);
    expect(new Set(scanned.values()).size).toBeGreaterThanOrEqual(5);
  });

  it('declares exactly the literals the tree contains, in both directions', () => {
    // SETS, not counts: a literal moving between files preserves every count.
    expect(new Set(scanned.keys())).toEqual(new Set(Object.keys(ZONE_A)));
  });

  it('agrees with the tree about which file builds each one', () => {
    const actual = new Map([...scanned].map(([literal, file]) => [literal, file]));
    const declared = new Map(Object.entries(ZONE_A).map(([literal, b]) => [literal, b.file]));
    expect(actual).toEqual(declared);
  });

  it('agrees with the tree about what each one interpolates', () => {
    for (const [literal, binding] of Object.entries(ZONE_A)) {
      const actual = [...literal.matchAll(INTERPOLATION)].map((m) => m[1] as string);
      expect({ literal, binds: actual }).toEqual({ literal, binds: [...binding.binds] });
    }
  });

  it('binds a mutable per-write counter in EXACTLY ONE place, and names it', () => {
    const mutable = Object.entries(ZONE_A)
      .filter(([, b]) => b.mutable)
      .map(([literal]) => literal);
    expect(mutable).toEqual([
      'estate.vault.item.v1|${ref.userId}|${ref.itemId}|${ref.blobVersion}',
    ]);
  });

  it('lets no counter-shaped component hide in an entry declared stable', () => {
    // The declaration is not taken on trust: if a new AAD interpolates
    // something that reads as a counter, the entry claiming otherwise fails.
    for (const [literal, binding] of Object.entries(ZONE_A)) {
      const counters = binding.binds.filter((component) => COUNTER_LIKE.test(component));
      if (binding.mutable) expect(counters.length).toBeGreaterThan(0);
      else expect({ literal, counters }).toEqual({ literal, counters: [] });
    }
  });
});

/**
 * ZONE B's AADs are built inline at the call site rather than by a named
 * builder, which is exactly why the migration's hand-list missed them. The
 * claim spans this corpus too, so it is scanned here rather than assumed.
 */
const ZONE_B_AAD = /cipher\.(?:encrypt|decrypt)\(\s*[A-Za-z0-9_.]+\s*,\s*[`'"]([^`'"]*)[`'"]/g;

describe('Zone B AADs bind identities, never a per-write counter (M27 PR1a)', () => {
  const found = new Map<string, string>();
  for (const file of tsFilesUnder(ZONE_B_SERVICES)) {
    for (const match of readFileSync(file, 'utf8').matchAll(ZONE_B_AAD)) {
      found.set(match[1] as string, file.slice(REPO.length + 1));
    }
  }

  it('finds Zone B AADs across more than one service', () => {
    expect(found.size).toBeGreaterThanOrEqual(11);
    expect(new Set(found.values()).size).toBeGreaterThanOrEqual(3);
  });

  it('interpolates only identifiers — no version, revision or sequence', () => {
    const offenders = [...found]
      .flatMap(([aad, file]) =>
        [...aad.matchAll(INTERPOLATION)].map((m) => ({ aad, file, component: m[1] as string })),
      )
      .filter(({ component }) => COUNTER_LIKE.test(component));
    expect(offenders).toEqual([]);
  });
});
