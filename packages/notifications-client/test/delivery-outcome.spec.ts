/**
 * Fence for the delivery-outcome derivation (M20 PR0).
 *
 * `SendOutcome` is a discriminated union and `accepted` is its DISCRIMINANT.
 * It says a healthy notifications service answered — not that the mail went.
 * The service answers `accepted: true, delivered: false` for `no_recipient`
 * and `carrier_failure` (and for a crypto-shredded DEK, which lands in the
 * latter), and the union's own docstring states the rule: "Callers record
 * either as a non-delivery."
 *
 * THREE IDENTITY CALL SITES BROKE THAT RULE and no gate could see it, because
 * stopping at the narrowing guard TYPE-CHECKS PERFECTLY:
 *
 *   const delivered = outcome.accepted;          // password-reset, twice
 *   ... this.events.passwordChanged(..., notified.accepted);   // auth
 *
 * Each of those booleans renders as the literal string `delivered` or `failed`
 * in an append-only audit event, so a mail the carrier refused was recorded as
 * delivered — on the password-reset ceremony, whose whole failure mode is a
 * user who cannot get in. The M14 PR0 shape (an audit claim inverted), in the
 * one place M20 is about to put a UI.
 *
 * So the derivation has ONE spelling for a CALLER, `wasDelivered`, and this
 * fence makes the wrong one unwritable: a service may not NAME the
 * discriminant unless it is a declared notifications adapter.
 *
 * WHY THE ADAPTERS ARE EXEMPT — corrected, because the first version of this
 * file gave the wrong reason and the wrong reason was checkable. It said they
 * name it "to turn an unreachable service into a 503". They do not: the 503
 * `notifications_unavailable` comes from `deliversToRealChannels`, a property
 * of the adapter CLASS tested before any send (vault/emergency.service.ts
 * assertNotificationsUsable, and its settlement/profile twins). What the
 * adapters actually do with `!outcome.accepted` is collapse it to
 * `delivered: false` — the SAME answer `wasDelivered` gives. The real reason
 * they must narrow is that they also read `recipientVerified`, which exists
 * only on the accepted arm, so the discriminant is unavoidable there and
 * nowhere else.
 *
 * WHY A FENCE AND NOT JUST THE HELPER: the helper fixes the seven sites that
 * exist; the fence is what stops the eighth being written by hand. This repo's
 * standing finding is that one behaviour with several places to spell it grows
 * one bug per copy (M8 PR2's seven byte-identical audit producers).
 *
 * MECHANISM, and every part of it is a hole an adversarial pass actually drove
 * through the first version:
 *
 *  - It scans EVERY source file under apps/ and packages/ (435 of them), not
 *    just files that import this package by name. The first version keyed
 *    membership on the literal specifier appearing in the text, so a helper
 *    typed structurally — `(outcome: { accepted: boolean })`, no import — was
 *    never scanned at all, and its caller named nothing.
 *  - The package is excluded by DIRECTORY PREFIX, not by
 *    `path.includes('notifications-client')`, which also excluded any service
 *    file whose own name contained that substring.
 *  - `identifiers()` strips comments AND the CONTENTS of string, template and
 *    REGEX literals. Comments, because "accepted" is common in prose. String
 *    contents, because otherwise a piece of user-facing copy ("That code was
 *    not accepted") failed the fence and the remedy a reader would infer —
 *    declare the file an adapter — is wrong. Regex literals, because a `/'/`
 *    desynchronised the first version's quote tracking and hid a real
 *    derivation with the fence fully green.
 *
 * Anti-vacuity floors on the file count, on the adapters really naming it, and
 * on the `wasDelivered` call count, because two scans that quietly match
 * nothing agree perfectly.
 *
 * RESIDUALS, stated rather than assumed. The scan is on the IDENTIFIER, so a
 * destructure is caught; `Object.values(outcome)[0]` is not, and closing that
 * wants the TypeScript AST, which is more than a fence should carry. The
 * `wasDelivered` floor is a fixed number, so it catches a converted site being
 * reverted and not an eighth site being added — the identifier scan is what
 * covers the latter. And the regex-literal heuristic is the usual one (a `/`
 * after an operator starts a literal); it is not a parser.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { wasDelivered } from '../src';

const REPO_ROOT = join(__dirname, '..', '..', '..');
/** Excluded by PREFIX — a substring test also excluded service files named for us. */
const THIS_PACKAGE = `${join(REPO_ROOT, 'packages', 'notifications-client')}/`;

interface Adapter {
  /** Repo-relative file permitted to name the discriminant. */
  file: string;
  why: string;
}

/**
 * The ONLY files outside this package that may name `accepted`.
 *
 * Each narrows the union because it ALSO reads `recipientVerified`, which the
 * refused arm does not carry — so `wasDelivered` alone cannot serve them. That
 * is the whole exemption; it is not about producing a 503, which comes from
 * `deliversToRealChannels` before any send.
 */
const ADAPTERS: Adapter[] = [
  {
    file: 'apps/services/settlement/src/notifications.ts',
    why: 'must read recipientVerified off the accepted arm — §5.1 intake records "sent to an unproved address" on the case trail without holding the status credential',
  },
  {
    file: 'apps/services/profile/src/notifications.ts',
    why: 'must read recipientVerified off the accepted arm — the M13 link-claim notice records whether the owner was reachably told',
  },
  {
    file: 'apps/services/vault/src/notifications.ts',
    why: 'must read recipientVerified off the accepted arm — M6 emergency access stamps delivered_at and records reach for §5.2',
  },
];

/** Every source file under apps/ and packages/, excluding tests and this package. */
function sourceFiles(): string[] {
  const found: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      if (['node_modules', 'dist', 'dist-esm', '.next', 'test'].includes(entry)) {
        continue;
      }
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) {
        walk(path);
      } else if (
        path.endsWith('.ts') &&
        !path.endsWith('.d.ts') &&
        !path.endsWith('.spec.ts') &&
        !path.startsWith(THIS_PACKAGE)
      ) {
        found.push(relative(REPO_ROOT, path));
      }
    }
  };
  walk(join(REPO_ROOT, 'apps'));
  walk(join(REPO_ROOT, 'packages'));
  return found.sort();
}

/**
 * Source reduced to IDENTIFIERS: comments removed, and the contents of string,
 * template and regex literals blanked. What survives is code a reader would
 * call a name.
 */
export function identifiers(source: string): string {
  let out = '';
  let mode: 'code' | 'line' | 'block' | 'sq' | 'dq' | 'tpl' | 're' = 'code';
  let prev = '';
  for (let i = 0; i < source.length; i += 1) {
    const c = source[i] as string;
    const next = source[i + 1];
    if (mode === 'line') {
      if (c === '\n') {
        mode = 'code';
        out += c;
      }
      continue;
    }
    if (mode === 'block') {
      if (c === '*' && next === '/') {
        mode = 'code';
        i += 1;
      }
      continue;
    }
    if (mode === 'sq' || mode === 'dq' || mode === 'tpl' || mode === 're') {
      const quote = mode === 'sq' ? "'" : mode === 'dq' ? '"' : mode === 'tpl' ? '`' : '/';
      if (c === '\\') {
        i += 1;
        continue;
      }
      if (c === quote) {
        mode = 'code';
        out += ' ';
      }
      continue;
    }
    if (c === '/' && next === '/') {
      mode = 'line';
      i += 1;
      continue;
    }
    if (c === '/' && next === '*') {
      mode = 'block';
      i += 1;
      continue;
    }
    // The usual heuristic: a `/` following an operator opens a regex literal.
    if (c === '/' && /[=(,:;[!&|?{}+\-*%<>~^]/.test(prev)) {
      mode = 're';
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      mode = c === "'" ? 'sq' : c === '"' ? 'dq' : 'tpl';
      continue;
    }
    out += c;
    if (!/\s/.test(c)) {
      prev = c;
    }
  }
  return out;
}

const read = (file: string): string => identifiers(readFileSync(join(REPO_ROOT, file), 'utf8'));
const names = (source: string): boolean => /\baccepted\b/.test(source);

describe('the delivery-outcome discriminant is named only by declared adapters', () => {
  const sources = sourceFiles();

  it('scanned the whole source tree (vacuity guard)', () => {
    // Hundreds of files, not the fifteen that name this package. If this
    // collapses, the equality below holds trivially over two empty sets.
    expect(sources.length).toBeGreaterThanOrEqual(300);
  });

  it('every source file naming `accepted` is a declared adapter, and every declared adapter names it', () => {
    const naming = sources.filter((file) => names(read(file)));
    expect(naming).toEqual(ADAPTERS.map((a) => a.file).sort());
  });

  it('every adapter carries a substantive reason', () => {
    for (const adapter of ADAPTERS) {
      expect(adapter.why.length).toBeGreaterThan(30);
    }
  });

  it('an adapter names it ONLY as `if (!x.accepted)`', () => {
    // The whole permitted use. Counting "is it negated somewhere" is not
    // enough: `delivered: !!outcome.accepted` satisfies a naive negation test
    // and reproduces this milestone's defect INSIDE an exempted file, which an
    // adversarial pass drove through the first version of this check.
    for (const adapter of ADAPTERS) {
      const source = read(adapter.file);
      const all = source.match(/\baccepted\b/g) ?? [];
      const gates = source.match(/if\s*\(\s*!\s*[A-Za-z_$][\w$]*\.accepted\s*\)/g) ?? [];
      expect(all.length).toBeGreaterThanOrEqual(1);
      expect(gates.length).toBe(all.length);
    }
  });
});

/**
 * THE DOUBLES, which is where the defect actually hid.
 *
 * No production gate could see the three wrong reads, because the specs in
 * identity's test directory hand-rolled their own notifications doubles and
 * the shapes they answered were not `SendOutcome`s. Four answered a bare
 * `{ accepted: true }` — the accepted arm carries `delivered`, `channel` and
 * `recipientVerified` too — and others omitted `recipientVerified` or declared
 * a loose `Promise<{ accepted: boolean }>` return. So a simulated send
 * "succeeded" in a way the real service cannot, and reading the discriminant
 * alone scored true against a shape that does not exist. A DOUBLE MORE
 * GENEROUS THAN THE PLATFORM IS WHERE THE BUG LIVES — the M16 PR2b lesson,
 * one layer beneath the fixtures.
 *
 * The compiler cannot be the enforcement here, and that was measured rather
 * than assumed: the doubles reach the constructor through `as never` and
 * `as unknown as NotificationsPort`, and a cast on the OUTER object means the
 * inner method's return type is inferred and never checked against the port.
 * Some of these literals were already complete and still uncheckable.
 *
 * So the outcomes are named constants in `test/notifications-double.ts`, typed
 * as `SendOutcome` — that annotation is the real check, since it is the one
 * place no cast intervenes — and this asserts nobody reintroduces a literal.
 */
describe('identity doubles the notifications port with declared outcomes only', () => {
  const TEST_DIR = 'apps/services/identity/test';
  const DECLARATION = `${TEST_DIR}/notifications-double.ts`;

  /** RECURSIVE: jest collects a spec in a subdirectory, so the fence must see it. */
  function specFiles(dir: string): string[] {
    const found: string[] = [];
    for (const entry of readdirSync(join(REPO_ROOT, dir))) {
      const rel = `${dir}/${entry}`;
      if (statSync(join(REPO_ROOT, rel)).isDirectory()) {
        found.push(...specFiles(rel));
      } else if (rel.endsWith('.ts') && rel !== DECLARATION) {
        found.push(rel);
      }
    }
    return found;
  }

  const files = specFiles(TEST_DIR);

  it('scanned identity’s test directory (vacuity guard)', () => {
    expect(files.length).toBeGreaterThanOrEqual(20);
  });

  it('no spec hand-rolls a send outcome', () => {
    const offenders = files.filter((file) => /\baccepted\s*:/.test(read(file)));
    expect(offenders).toEqual([]);
  });

  it('the declaration types its outcomes as SendOutcome, which is the actual check', () => {
    const source = read(DECLARATION);
    for (const name of ['DELIVERED', 'UNDELIVERED', 'DELIVERED_UNVERIFIED', 'UNREACHABLE']) {
      expect(source).toMatch(new RegExp(`export const ${name}\\s*:\\s*SendOutcome\\b`));
    }
  });
});

describe('the one spelling is actually used', () => {
  const sources = sourceFiles();

  it('wasDelivered is called at every site that derives a delivery fact', () => {
    // The floor is the seven identity call sites this PR converted (two in
    // password-reset, two in email-change, one each in auth, email-verification
    // and webauthn). It catches a converted site being reverted; an EIGHTH site
    // written by hand is caught by the identifier scan above, not by this.
    const calls = sources
      .map((file) => (read(file).match(/\bwasDelivered\s*\(/g) ?? []).length)
      .reduce((a, b) => a + b, 0);
    expect(calls).toBeGreaterThanOrEqual(7);
  });

  it('is exported from the package root, so a consumer has one import to reach', () => {
    // Imported from the ROOT rather than from `../src/client`: a helper the
    // barrel does not re-export is one every consumer must reach past, and the
    // reaching is how a second local spelling gets written instead.
    expect(typeof wasDelivered).toBe('function');
    expect(
      wasDelivered({
        accepted: true,
        delivered: false,
        channel: 'email',
        recipientVerified: false,
      }),
    ).toBe(false);
    expect(
      wasDelivered({ accepted: true, delivered: true, channel: 'email', recipientVerified: false }),
    ).toBe(true);
    expect(wasDelivered({ accepted: false })).toBe(false);
  });
});

describe('identifiers(): the scanner the fence rests on', () => {
  // Each case is an evasion an adversarial pass actually drove through the
  // first version of this file, with the fence fully green.
  it('blanks a regex literal, which cannot be allowed to desynchronise quoting', () => {
    const src = "const APOSTROPHE = /'/; export function p(o: X) { return o.accepted; }";
    expect(names(identifiers(src))).toBe(true);
  });

  it('blanks string contents, so user-facing copy is not mistaken for a derivation', () => {
    expect(names(identifiers("const m = 'That code was not accepted.';"))).toBe(false);
  });

  it('blanks a comment that discusses the discriminant', () => {
    expect(names(identifiers('// `wasDelivered`, NOT outcome.accepted\nconst x = 1;'))).toBe(false);
  });

  it('keeps a genuine derivation hidden behind a comment-lookalike string', () => {
    const src = "const HINT = 'match /* any'; const d = o.accepted; const E = 'until */ here';";
    expect(names(identifiers(src))).toBe(true);
  });
});
