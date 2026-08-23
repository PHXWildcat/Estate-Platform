/**
 * THE REQUEST VALIDATOR AGREES WITH THE REQUEST TYPE (M27 PR1a).
 *
 * WHY THIS EXISTS, MEASURED RATHER THAN IMAGINED. PR1a added a required
 * `revision` to the `update` message and changed the hop that READS it, and the
 * hop that BUILDS it was never widened. Typecheck, lint and 488 tests were
 * green, because two boundaries were unsound in opposite directions: the popup
 * sent through `ask(message: unknown)`, and the offscreen router received
 * through a predicate that asserted `value is VaultRequest` after inspecting
 * `target` and `kind` alone. Every field between those two points was a
 * promise nothing checked. The extension would have 400'd on every edit.
 *
 * The send side is now typed, so the compiler catches it. This is the receive
 * side, where a type cannot help: `isVaultRequest` must decide at RUNTIME, so
 * it carries a hand-written table of required fields — and a hand-maintained
 * list beside a thing that grows is this repo's most repeated defect. So the
 * union in `messages.ts` is the input here, parsed from source, and compared
 * in BOTH directions against the table the predicate actually consults at
 * runtime. Adding a field to a message without teaching the gate about it, or
 * teaching the gate a field no message has, fails the build either way.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { isVaultRequest, OFFSCREEN, VAULT_REQUEST_REQUIRED_FIELDS } from '../src/messages';

const SOURCE = readFileSync(join(__dirname, '..', 'src', 'messages.ts'), 'utf8');

/** The `VaultRequest` union's text: from its declaration to the first `;` at column 0. */
function unionText(): string {
  const start = SOURCE.indexOf('export type VaultRequest =');
  expect(start).toBeGreaterThan(-1);
  const end = SOURCE.indexOf('\n\n', start);
  expect(end).toBeGreaterThan(start);
  return SOURCE.slice(start, end);
}

interface Variant {
  readonly kind: string;
  /** Required field names, excluding the `target`/`kind` envelope and optionals. */
  readonly required: ReadonlySet<string>;
}

/**
 * Derive each variant from the union's own source. A variant is a `{ … }`
 * member carrying a literal `kind:`; its required fields are the `readonly`
 * members that are not optional and not the envelope.
 */
function variantsFromSource(): Variant[] {
  const text = unionText();
  const out: Variant[] = [];
  // Split on the union bar that opens an object member, at any indentation.
  for (const chunk of text.split(/\n\s*\|\s*/).slice(1)) {
    const kindMatch = /kind:\s*'([a-z]+)'/.exec(chunk);
    if (kindMatch === null) continue;
    const required = new Set<string>();
    for (const field of chunk.matchAll(/readonly\s+([A-Za-z0-9_]+)(\??):/g)) {
      const name = field[1] as string;
      const optional = field[2] === '?';
      if (name === 'target' || name === 'kind' || optional) continue;
      required.add(name);
    }
    out.push({ kind: kindMatch[1] as string, required });
  }
  return out;
}

/**
 * The validator's table as the RUNTIME holds it, not as its source reads. A
 * second parser here would be a second thing to be wrong, and the object the
 * predicate actually consults is the honest side of this comparison.
 */
function table(): Map<string, Set<string>> {
  return new Map(
    Object.entries(VAULT_REQUEST_REQUIRED_FIELDS).map(([kind, fields]) => [
      kind,
      new Set(Object.keys(fields)),
    ]),
  );
}

describe('isVaultRequest validates every field the union requires (M27 PR1a)', () => {
  const variants = variantsFromSource();
  const table_ = table();

  it('parses a corpus at all, at every level', () => {
    // ANTI-VACUITY. A regex that stopped matching and a union with no variants
    // look identical, and a total alone cannot see one variant lose its fields
    // — so the floor is stated for the variants AND for the fields they carry.
    expect(variants.length).toBeGreaterThanOrEqual(8);
    expect(table_.size).toBeGreaterThanOrEqual(8);
    expect(variants.flatMap((v) => [...v.required]).length).toBeGreaterThanOrEqual(18);
  });

  it('covers exactly the kinds the union declares, in both directions', () => {
    expect(new Set(table_.keys())).toEqual(new Set(variants.map((v) => v.kind)));
  });

  it('requires exactly the fields each variant declares, per kind', () => {
    // SETS per kind, not a total: a field moving between two messages preserves
    // every count, and would leave one message unvalidated.
    for (const variant of variants) {
      expect({ kind: variant.kind, fields: table_.get(variant.kind) }).toEqual({
        kind: variant.kind,
        fields: variant.required,
      });
    }
  });
});

describe('isVaultRequest refuses what it cannot vouch for', () => {
  const wellFormed: Record<string, unknown> = {
    target: OFFSCREEN,
    kind: 'update',
    bearer: 'b',
    itemId: 'i',
    itemType: 'password',
    changes: { secret: 'x' },
    blobVersion: 4,
    revision: 41,
  };

  it('accepts a complete update', () => {
    expect(isVaultRequest(wellFormed)).toBe(true);
  });

  it('refuses an update missing ANY required field, naming each one', () => {
    // Driven from the message itself rather than a hand-picked field, so a
    // newly required field is covered the moment it is added.
    const fields = Object.keys(wellFormed).filter((k) => k !== 'target' && k !== 'kind');
    expect(fields.length).toBeGreaterThanOrEqual(6);
    for (const omitted of fields) {
      const partial = { ...wellFormed };
      delete partial[omitted];
      expect({ omitted, accepted: isVaultRequest(partial) }).toEqual({ omitted, accepted: false });
    }
  });

  it('refuses the exact message M27 PR1a would have sent', () => {
    // THE REGRESSION, stated as itself: the popup built this, the router typed
    // `revision` as a number, and nothing between them objected.
    const { revision: _dropped, ...withoutRevision } = wellFormed as { revision: number };
    expect(isVaultRequest(withoutRevision)).toBe(false);
  });

  it('refuses a field of the wrong type, not merely an absent one', () => {
    expect(isVaultRequest({ ...wellFormed, revision: '41' })).toBe(false);
    expect(isVaultRequest({ ...wellFormed, changes: 'not-an-object' })).toBe(false);
    expect(isVaultRequest({ ...wellFormed, changes: null })).toBe(false);
  });

  it('still refuses a stray message and an unknown kind', () => {
    expect(isVaultRequest(null)).toBe(false);
    expect(isVaultRequest({ target: 'somewhere-else', kind: 'update' })).toBe(false);
    expect(isVaultRequest({ target: OFFSCREEN, kind: 'exfiltrate' })).toBe(false);
    // A prototype-borrowed name must not read as a declared kind.
    expect(isVaultRequest({ target: OFFSCREEN, kind: 'toString' })).toBe(false);
  });

  it('accepts a lock with no bearer, because that field is genuinely optional', () => {
    expect(isVaultRequest({ target: OFFSCREEN, kind: 'lock' })).toBe(true);
  });
});
