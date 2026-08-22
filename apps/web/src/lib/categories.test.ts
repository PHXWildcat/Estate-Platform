import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { CATEGORY_LABELS, INSURANCE_CATEGORIES } from './categories';

/**
 * The category vocabulary is OWNED by the `assets_view` CHECK constraint; this
 * fence derives that vocabulary from the migration DDL and pins the display
 * map to it IN BOTH DIRECTIONS — a category added to the ledger without
 * wording, or wording kept for a category the ledger dropped, each fail here
 * rather than shipping a raw token or a ghost label.
 *
 * THE INPUT IS THE WHOLE MIGRATIONS CORPUS, not one file: migrations are
 * append-only and checksummed, so the constraint can only ever change via a
 * NEW file (ALTER … DROP/ADD CONSTRAINT) — a fence reading only
 * 001_financial_schema.sql would parse a frozen snapshot forever and its
 * ledger-side trigger could never fire (this PR's review caught exactly
 * that). Scanning every file, this fence asserts the corpus holds EXACTLY ONE
 * category CHECK definition; the migration that redefines it must come here
 * and make the LATEST definition the derivation, deliberately. (apps/web
 * already declares the cross-package turbo test inputs, so these reads are
 * cache-correct.)
 */

const MIGRATIONS_DIR = join(__dirname, '../../../..', 'apps/services/assets/migrations');

function categoryCheckDefinitions(): { file: string; members: string[] }[] {
  const files = readdirSync(MIGRATIONS_DIR)
    .filter((name) => name.endsWith('.sql'))
    .sort();
  // Anti-vacuity on the corpus itself: the migrations directory is real and
  // has grown past its first file.
  expect(files.length).toBeGreaterThanOrEqual(2);
  const definitions: { file: string; members: string[] }[] = [];
  for (const file of files) {
    const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8');
    for (const match of sql.matchAll(/CHECK \(category IN \(([\s\S]*?)\)\)/g)) {
      definitions.push({
        file,
        members: [...(match[1] as string).matchAll(/'([a-z_]+)'/g)].map(
          (token) => token[1] as string,
        ),
      });
    }
  }
  return definitions;
}

describe('asset category labels', () => {
  it('the corpus holds exactly ONE category CHECK, and the label map equals it, both directions', () => {
    const definitions = categoryCheckDefinitions();
    // A second definition means a later migration redefined the vocabulary —
    // this fence must be re-pointed at the LATEST one in the same change,
    // never left green against the frozen original.
    expect(definitions.map((d) => d.file)).toEqual(['001_financial_schema.sql']);

    const ddl = (definitions[0] as { members: string[] }).members;
    // Anti-vacuity: the parse saw the real vocabulary, not a fragment.
    expect(ddl.length).toBeGreaterThanOrEqual(15);
    expect(ddl).toContain('cash');
    expect(ddl).toContain('other');

    expect([...Object.keys(CATEGORY_LABELS)].sort()).toEqual([...ddl].sort());
  });

  it('every label is real wording, not a placeholder', () => {
    for (const label of Object.values(CATEGORY_LABELS)) {
      expect(label.trim().length).toBeGreaterThan(0);
    }
  });

  it('the insurance facet names real DDL members, each with wording', () => {
    const definitions = categoryCheckDefinitions();
    const ddl = definitions.flatMap((d) => d.members);
    expect(INSURANCE_CATEGORIES.length).toBe(3);
    for (const category of INSURANCE_CATEGORIES) {
      expect(ddl).toContain(category);
      expect(CATEGORY_LABELS[category].trim().length).toBeGreaterThan(0);
    }
  });
});
