/**
 * Fence for the decrypt-SUBJECT registry (M19 follow-up, docs/03 §6q).
 *
 * `DECRYPT_FIELD_SUBJECTS` says where the subject's id sits inside a decrypt
 * field name, and the M18 detector uses that position to count DISTINCT
 * subjects — a number that can SUPPRESS an alarm. So a wrong entry here is a
 * blind spot rather than noise, and the declaration's own docstring commits
 * that "every entry is verified against the field's own construction in the
 * owning service, and this spec re-checks that against source". This is that
 * spec: without it the commitment is the shape this repo keeps closing — a
 * fence a document claims and nobody wrote.
 *
 * Mechanism: each declared prefix names the source file that BUILDS its field
 * name and the identifier the declared segment must interpolate. Every
 * template literal in that file whose head starts `<prefix>.` is split into
 * dot segments (brace-aware, so `${a.b}` stays one segment) and the declared
 * position must be exactly `${<identifier>}` in ALL of them — one disagreeing
 * construction is the defect, because the detector applies one position to
 * every field under the prefix.
 *
 * THE `doc` CASE IS ASSERTED POSITIVELY, not left as a warning. Its field is
 * `doc.<ownerUserId>.v<n>.<sha>`, so segment 2 is the OWNER — the same value
 * for every document a person holds, which sampling the live stream cannot
 * tell from a per-row id. Declaring it would collapse an owner's whole library
 * to one subject and suppress a mass document read. So this fence asserts both
 * halves: `doc` is absent from the declaration, AND documents' own constructor
 * really does put the owner where a careless declaration would point.
 *
 * COMMENTS ARE STRIPPED FIRST, and the fence's own first run is why that line
 * exists: `assets.service.ts` documents the audit action `asset.estate.viewed`
 * inside a `//` comment, in markdown backticks — which a raw scan reads as a
 * template literal beginning `asset.`, and which duly failed against a segment
 * that is a fixed word rather than an interpolation. The repo's `code()` rule
 * (a scan of source means a scan of CODE) restated for a scanner that must
 * keep template bodies intact, so the prefixes fence's literal-extractor could
 * not be reused as-is.
 *
 * Residuals, stated: the template scan is a `/`...`/` match, exact for these
 * one-line field constructors and wrong for a nested template; and the
 * comment-stripper does not disambiguate a regex literal from division, so a
 * regex containing `//` would eat the rest of its line. The per-prefix floor
 * is the tripwire for both; neither shape exists in the scanned files today.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  DECRYPT_FIELD_PREFIXES,
  DECRYPT_FIELD_SUBJECTS,
  decryptFieldSubject,
  type DecryptFieldPrefix,
} from '../src';

const REPO_ROOT = join(__dirname, '..', '..', '..');

interface Construction {
  /** Repo-relative file that builds the field name. */
  file: string;
  /** Identifier the declared segment must interpolate. */
  identifier: string;
  /** Minimum template literals expected — the anti-vacuity floor. */
  minTemplates: number;
  why: string;
}

/**
 * One entry per declared subject position. Bidirectional with
 * `DECRYPT_FIELD_SUBJECTS` below, so a declaration added without a
 * construction — or a construction left behind by a removed declaration —
 * fails rather than passing quietly.
 *
 * The IDENTIFIER is part of the pin on purpose. Asserting only "segment 2 is
 * some interpolation" would stay green if the constructor's arguments were
 * reordered, which is precisely the change that makes the detector count the
 * wrong thing while every other test in the repo passes. A rename is a red
 * fence, and a red fence here is a review of a security parameter.
 */
const SUBJECT_CONSTRUCTIONS: Partial<Record<DecryptFieldPrefix, Construction>> = {
  asset: {
    file: 'apps/services/assets/src/assets.service.ts',
    identifier: 'assetId',
    minTemplates: 1,
    why: 'viewField(assetId, field) is the ONE constructor of asset.* field names; both decrypt sites (assets.service reads, rebuild.service diffView) call it',
  },
};

/** The cautionary counter-example, asserted rather than described. */
const OWNER_KEYED_CONSTRUCTIONS: {
  prefix: string;
  file: string;
  at: number;
  identifier: string;
}[] = [
  {
    prefix: 'doc',
    file: 'apps/services/documents/src/content-cipher.ts',
    at: 2,
    identifier: 'ownerUserId',
  },
];

/**
 * Remove line and block comments while leaving every literal — including
 * template bodies and their `${ }` — verbatim. Quote- and template-aware, so
 * a `//` inside a string is not a comment and a comment inside `${ }` is.
 */
function stripComments(source: string): string {
  let out = '';
  let i = 0;
  /** Open template frames; 0 ⇒ inside the template's literal text. */
  const templates: number[] = [];
  let mode: 'code' | 'line' | 'block' | 'single' | 'double' = 'code';
  while (i < source.length) {
    const c = source[i] as string;
    const next = source[i + 1];
    if (mode === 'line') {
      if (c === '\n') {
        mode = 'code';
        out += c;
      }
      i += 1;
      continue;
    }
    if (mode === 'block') {
      if (c === '*' && next === '/') {
        mode = 'code';
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }
    if (mode === 'single' || mode === 'double') {
      const quote = mode === 'single' ? "'" : '"';
      if (c === '\\') {
        out += c + (next ?? '');
        i += 2;
        continue;
      }
      out += c;
      if (c === quote) {
        mode = 'code';
      }
      i += 1;
      continue;
    }
    const depth = templates.length > 0 ? (templates[templates.length - 1] as number) : undefined;
    if (depth === 0) {
      // Inside a template's literal text: no comments here.
      if (c === '\\') {
        out += c + (next ?? '');
        i += 2;
        continue;
      }
      if (c === '`') {
        templates.pop();
        out += c;
        i += 1;
        continue;
      }
      if (c === '$' && next === '{') {
        templates[templates.length - 1] = 1;
        out += '${';
        i += 2;
        continue;
      }
      out += c;
      i += 1;
      continue;
    }
    // Plain code, or inside a template's `${ }` expression.
    if (c === '/' && next === '/') {
      mode = 'line';
      i += 2;
      continue;
    }
    if (c === '/' && next === '*') {
      mode = 'block';
      i += 2;
      continue;
    }
    if (c === "'" || c === '"') {
      mode = c === "'" ? 'single' : 'double';
      out += c;
      i += 1;
      continue;
    }
    if (c === '`') {
      templates.push(0);
      out += c;
      i += 1;
      continue;
    }
    if (depth !== undefined && depth > 0) {
      if (c === '{') {
        templates[templates.length - 1] = depth + 1;
      } else if (c === '}') {
        templates[templates.length - 1] = depth - 1;
      }
    }
    out += c;
    i += 1;
  }
  return out;
}

/** Template literals in `source` whose head begins `<prefix>.`, body only. */
function templatesFor(source: string, prefix: string): string[] {
  const found: string[] = [];
  const re = /`([^`]*)`/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(stripComments(source))) !== null) {
    const body = m[1] as string;
    if (body.startsWith(`${prefix}.`)) {
      found.push(body);
    }
  }
  return found;
}

/** Split a template body on dots that sit OUTSIDE a `${ }` interpolation. */
function segmentsOf(body: string): string[] {
  const out: string[] = [];
  let buf = '';
  let depth = 0;
  for (let i = 0; i < body.length; i += 1) {
    const c = body[i] as string;
    if (c === '$' && body[i + 1] === '{') {
      depth += 1;
      buf += '${';
      i += 1;
      continue;
    }
    if (depth > 0) {
      if (c === '{') {
        depth += 1;
      } else if (c === '}') {
        depth -= 1;
      }
      buf += c;
      continue;
    }
    if (c === '.') {
      out.push(buf);
      buf = '';
      continue;
    }
    buf += c;
  }
  out.push(buf);
  return out;
}

const read = (file: string): string => readFileSync(join(REPO_ROOT, file), 'utf8');

describe('DECRYPT_FIELD_SUBJECTS declaration shape', () => {
  it('declares only registered prefixes', () => {
    for (const prefix of Object.keys(DECRYPT_FIELD_SUBJECTS)) {
      expect(Object.keys(DECRYPT_FIELD_PREFIXES)).toContain(prefix);
    }
  });

  it('declares only positions past the prefix itself', () => {
    // Position 1 IS the prefix, which is the class rather than the subject —
    // declaring it would make every field under the prefix one subject and
    // suppress everything.
    for (const at of Object.values(DECRYPT_FIELD_SUBJECTS)) {
      expect(at).toBeGreaterThanOrEqual(2);
      expect(Number.isInteger(at)).toBe(true);
    }
  });

  it('has a construction for every declaration, and no orphan constructions', () => {
    expect(Object.keys(SUBJECT_CONSTRUCTIONS).sort()).toEqual(
      Object.keys(DECRYPT_FIELD_SUBJECTS).sort(),
    );
  });

  it('declares at least one prefix (vacuity guard)', () => {
    expect(Object.keys(DECRYPT_FIELD_SUBJECTS).length).toBeGreaterThanOrEqual(1);
  });
});

describe('each declared position is pinned to its construction in source', () => {
  it.each(Object.entries(SUBJECT_CONSTRUCTIONS))('%s', (prefix, construction) => {
    const c = construction;
    const at = DECRYPT_FIELD_SUBJECTS[prefix as DecryptFieldPrefix] as number;
    const templates = templatesFor(read(c.file), prefix);
    expect(templates.length).toBeGreaterThanOrEqual(c.minTemplates);
    for (const body of templates) {
      const segments = segmentsOf(body);
      expect(segments.length).toBeGreaterThanOrEqual(at);
      expect(segments[at - 1]).toBe(`\${${c.identifier}}`);
    }
  });
});

describe('the owner-keyed counter-examples stay undeclared', () => {
  it.each(OWNER_KEYED_CONSTRUCTIONS)(
    '$prefix is not declared, and segment $at really is $identifier',
    ({ prefix, file, at, identifier }) => {
      // Half one: the declaration must not name it.
      expect(Object.keys(DECRYPT_FIELD_SUBJECTS)).not.toContain(prefix);
      // Half two: WHY — the tempting position holds a value shared across
      // every row the principal owns, so a declaration would suppress a mass
      // read. Asserted from source, so this stays true only while it is true.
      const templates = templatesFor(read(file), prefix);
      expect(templates.length).toBeGreaterThanOrEqual(1);
      for (const body of templates) {
        expect(segmentsOf(body)[at - 1]).toBe(`\${${identifier}}`);
      }
    },
  );
});

describe('decryptFieldSubject', () => {
  it('extracts the declared segment', () => {
    expect(decryptFieldSubject('asset.9f0e.est_value')).toBe('9f0e');
    expect(decryptFieldSubject('asset.9f0e.notes')).toBe('9f0e');
  });

  it('answers null for a prefix that declares no subject', () => {
    // Undeclared ⇒ the detector counts 0 distinct and no bound suppresses.
    expect(decryptFieldSubject('doc.owner.v2.abc')).toBeNull();
    expect(decryptFieldSubject('contact.name')).toBeNull();
    expect(decryptFieldSubject('plaid_item.access_token.42')).toBeNull();
  });

  it('answers null for an unregistered prefix', () => {
    expect(decryptFieldSubject('trust.9f0e.name')).toBeNull();
    expect(decryptFieldSubject('nodots')).toBeNull();
  });

  it('answers null when the declared segment is missing or empty', () => {
    // A truncated field name must not resolve to '' and merge every such
    // event onto one phantom subject.
    expect(decryptFieldSubject('asset')).toBeNull();
    expect(decryptFieldSubject('asset.')).toBeNull();
    expect(decryptFieldSubject('asset..est_value')).toBeNull();
  });

  it('never resolves through the object prototype', () => {
    expect(decryptFieldSubject('constructor.x')).toBeNull();
    expect(decryptFieldSubject('toString.x')).toBeNull();
    expect(decryptFieldSubject('__proto__.x')).toBeNull();
  });
});
