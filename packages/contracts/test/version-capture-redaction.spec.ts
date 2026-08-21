/**
 * NO VERSION-CAPTURE IMAGE KEEPS A BLIND INDEX, AND THE CATEGORY IS DERIVED.
 *
 * WHY THIS EXISTS. A `*_bidx` is an HMAC under a SERVICE-WIDE blind-index key,
 * not a `*_ct` + `dek_id` pair. It sits outside the envelope, so destroying
 * every DEK a user has does not touch it — and `<table>_versions` shadows
 * REVOKE UPDATE and DELETE, so anything captured there is permanent. Erasure
 * must UPDATE the row it is closing, which is precisely the moment a capture
 * would immortalise the identifier being erased.
 *
 * WHY IT IS A FENCE AND NOT THREE MIGRATIONS. M25 PR0 recorded this as ONE
 * column — `users.email_bidx` — because that is the one the erasure path walked
 * into. Deriving the same question from the schema found THREE tables carrying
 * both a blind index and a capturing shadow, in three different services, and
 * the one PR0 named is not the most sensitive of them: `contacts.email_bidx`
 * indexes a LIVING THIRD PARTY's address, not the account holder's. A rule
 * applied to one member of a category is a rule half-applied, and the way this
 * repo stops doing that is to make the category the input.
 *
 * WHAT IT ASSERTS. From the migrations — the only source of truth for a
 * deployed schema, since `versionsTableSql` is a TEMPLATE that is copied into
 * `.sql` files and never executed at runtime:
 *
 *   1. Every `CREATE TABLE` whose column list contains a `*_bidx` column.
 *   2. Which of those tables also have a `<table>_versions` shadow.
 *   3. That each such table's service ships a `CREATE OR REPLACE FUNCTION
 *      <table>_capture_version` whose body performs the `_bidx` redaction.
 *
 * THE POSITIVE CONTROL IS `document_search_tokens`, and it is the reason step 2
 * is a real predicate rather than decoration. That table has a `token_bidx` —
 * per-user HMACs of document CONTENT, the most sensitive blind index in the
 * repo — and deliberately NO version shadow: it is a rebuildable projection,
 * exempt from the soft-delete/_versions conventions. It must therefore be found
 * by step 1 and EXCLUDED by step 2. A predicate that quietly matched everything
 * would sweep it in; one that quietly matched nothing would produce an empty
 * category and pass. Both directions are asserted.
 *
 * `document_search_tokens` is not thereby safe — erasure has to PURGE it, since
 * its tokens derive from content the DEK destruction erases. That is PR3's, it
 * is named in docs/03 §6ll, and this fence does not cover it. Stated here
 * because the tempting misreading of a green run is "blind indexes are handled".
 *
 * WHAT THIS DOES NOT PROVE. That the redaction EXECUTES. This reads SQL text;
 * a function that parses correctly and behaves wrongly passes. The behavioural
 * half lives in each service's own PG-gated int suite, which updates a real row
 * and asserts the captured image carries no `*_bidx` key. Two halves, stated so
 * neither is mistaken for the whole.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const SERVICES_DIR = join(__dirname, '..', '..', '..', 'apps', 'services');

/**
 * Floors. Two scans that quietly match nothing agree perfectly. Set below the
 * values measured at M25 PR1 (5 blind-index tables, 3 of them captured) so
 * ordinary work does not trip them, and high enough that a broken parse cannot
 * pass.
 */
const MIN_BIDX_TABLES = 4;
const MIN_CAPTURED = 3;

/** The redaction mechanism, as the migrations actually spell it. */
const REDACTION = /right\(\s*k\s*,\s*5\s*\)\s*=\s*'_bidx'/;

interface Schema {
  /** service → tables declaring a `*_bidx` column. */
  readonly bidxTables: Map<string, Set<string>>;
  /** service → every table name the migrations create. */
  readonly allTables: Map<string, Set<string>>;
  /** service → concatenated migration SQL. */
  readonly sql: Map<string, string>;
}

function services(): string[] {
  return readdirSync(SERVICES_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(SERVICES_DIR, e.name, 'migrations')))
    .map((e) => e.name)
    .sort();
}

function readSchema(): Schema {
  const bidxTables = new Map<string, Set<string>>();
  const allTables = new Map<string, Set<string>>();
  const sql = new Map<string, string>();

  for (const service of services()) {
    const dir = join(SERVICES_DIR, service, 'migrations');
    const text = readdirSync(dir)
      .filter((f) => f.endsWith('.sql'))
      .sort()
      .map((f) => readFileSync(join(dir, f), 'utf8'))
      .join('\n');
    sql.set(service, text);

    const tables = new Set<string>();
    const withBidx = new Set<string>();
    // A CREATE TABLE and the column list that follows it, up to the closing
    // paren at the start of a line — the shape every migration in this repo
    // uses. The floors below are what catch this going wrong.
    const re = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_]+)\s*\(([\s\S]*?)^\)/gim;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const table = m[1] as string;
      const columns = m[2] as string;
      tables.add(table);
      if (/^\s*[a-z_]*_bidx\s/m.test(columns) || /,\s*[a-z_]*_bidx\s/.test(columns)) {
        withBidx.add(table);
      }
    }
    allTables.set(service, tables);
    bidxTables.set(service, withBidx);
  }
  return { bidxTables, allTables, sql };
}

/** Tables carrying BOTH a blind index and a shadow that captures it. */
function captured(schema: Schema): Array<{ service: string; table: string }> {
  const out: Array<{ service: string; table: string }> = [];
  for (const [service, tables] of schema.bidxTables) {
    for (const table of tables) {
      if (schema.allTables.get(service)?.has(`${table}_versions`) === true) {
        out.push({ service, table });
      }
    }
  }
  return out.sort((a, b) => `${a.service}.${a.table}`.localeCompare(`${b.service}.${b.table}`));
}

/** The latest `CREATE OR REPLACE FUNCTION <table>_capture_version` body. */
function captureBody(sql: string, table: string): string | null {
  const re = new RegExp(
    `CREATE\\s+OR\\s+REPLACE\\s+FUNCTION\\s+${table}_capture_version\\(\\)([\\s\\S]*?)\\$\\$\\s+LANGUAGE`,
    'gi',
  );
  let last: string | null = null;
  let m: RegExpExecArray | null;
  while ((m = re.exec(sql)) !== null) {
    last = m[1] as string;
  }
  return last;
}

describe('version captures never keep a blind index', () => {
  const schema = readSchema();
  const all = [...schema.bidxTables].flatMap(([service, tables]) =>
    [...tables].map((table) => ({ service, table })),
  );

  it('finds the blind-index tables at all (anti-vacuity)', () => {
    expect(all.length).toBeGreaterThanOrEqual(MIN_BIDX_TABLES);
    // And the table scan itself is not the thing that broke: every service's
    // migrations create tables, so a parse returning nothing anywhere is a bug.
    const totalTables = [...schema.allTables.values()].reduce((n, s) => n + s.size, 0);
    expect(totalTables).toBeGreaterThanOrEqual(30);
  });

  it('the captured set is a STRICT subset — the shadow predicate discriminates', () => {
    // THE POSITIVE CONTROL. `document_search_tokens` carries the repo's most
    // sensitive blind index (per-user HMACs of document content) and has no
    // version shadow by design. It must be SEEN by the column scan and
    // EXCLUDED by the shadow predicate. If this stops holding, either the
    // predicate has started matching everything or that table grew a shadow.
    expect(all.map((t) => t.table)).toContain('document_search_tokens');
    expect(captured(schema).map((t) => t.table)).not.toContain('document_search_tokens');
    expect(captured(schema).length).toBeLessThan(all.length);
  });

  it('every captured blind index is redacted by its own capture function', () => {
    const rows = captured(schema);
    expect(rows.length).toBeGreaterThanOrEqual(MIN_CAPTURED);

    const unredacted = rows
      .filter(({ service, table }) => {
        const body = captureBody(schema.sql.get(service) ?? '', table);
        return body === null || !REDACTION.test(body);
      })
      .map(({ service, table }) => `${service}.${table}`);
    expect(unredacted).toEqual([]);
  });

  it('the redaction is derived from the row, not a hand-listed column name', () => {
    // A capture that named `email_bidx` literally would pass the assertion
    // above while leaving the NEXT blind index on that table captured. The
    // mechanism must read the image's own keys.
    for (const { service, table } of captured(schema)) {
      const body = captureBody(schema.sql.get(service) ?? '', table) ?? '';
      expect(body).toMatch(/jsonb_object_keys\(\s*image\s*\)/);
      expect(body).not.toMatch(/-\s*'[a-z_]*_bidx'/);
    }
  });
});
