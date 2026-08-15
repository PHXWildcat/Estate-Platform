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
 * So the derivation has ONE spelling, `wasDelivered`, and this fence makes the
 * wrong one unwritable: a consumer of this package may not NAME the
 * discriminant at all unless it is a declared notifications adapter, which
 * names it for the genuinely different question — is the service reachable —
 * and turns that into a 503 `notifications_unavailable`.
 *
 * WHY A FENCE AND NOT JUST THE HELPER: the helper fixes the seven sites that
 * exist; the fence is what stops the eighth being written by hand. This repo's
 * standing finding is that one behaviour with several places to spell it grows
 * one bug per copy (M8 PR2's seven byte-identical audit producers).
 *
 * Mechanism: scan every non-test source file that imports this package,
 * comment-stripped (the `code()` rule — the word "accepted" is common in
 * prose, and password-reset.service.ts now discusses the discriminant in a
 * comment directly above the line that no longer uses it). Bidirectional
 * against the declared table, with anti-vacuity floors on both the number of
 * importers scanned and the number of `wasDelivered` call sites, because two
 * scans that quietly match nothing agree perfectly.
 *
 * Residuals, stated rather than assumed. A destructure (`const { accepted } =
 * outcome`) is caught — the scan is on the IDENTIFIER, not on `.accepted` —
 * but a rename through an intermediate (`const a = outcome; a.accepted`) is
 * caught only because that still names it, while `Object.values(outcome)[0]`
 * would not; closing that wants the TypeScript AST, which is more than a fence
 * should carry. The comment stripper is a compact second copy of the one in
 * `packages/contracts/test/decrypt-field-subjects.spec.ts`; sharing would need
 * a test-only package, and each is independently pinned by its own floor.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { wasDelivered } from '../src';

const REPO_ROOT = join(__dirname, '..', '..', '..');
const PACKAGE_SPECIFIER = '@estate/notifications-client';

interface Adapter {
  /** Repo-relative file permitted to name the discriminant. */
  file: string;
  why: string;
}

/**
 * The ONLY files outside this package that may name `accepted`.
 *
 * All three ask the reachability question, not the delivery one: an
 * unreachable notifications service is a REFUSAL of the caller's whole action
 * (M6's rule that a waiting period nobody can be told about is not a control),
 * while an undelivered notification is a fact the caller records and proceeds
 * past. Those are different answers to different questions, which is exactly
 * why the discriminant is legitimate here and a mistake everywhere else.
 */
const ADAPTERS: Adapter[] = [
  {
    file: 'apps/services/settlement/src/notifications.ts',
    why: 'gates the §5.1 intake/review-approve routes: unreachable ⇒ 503, so a death case cannot open silently unannounced',
  },
  {
    file: 'apps/services/profile/src/notifications.ts',
    why: 'gates the M13 link-code ceremony: unreachable ⇒ 503, so a claimed link cannot go untold',
  },
  {
    file: 'apps/services/vault/src/notifications.ts',
    why: 'gates M6 emergency access: unreachable ⇒ 503, so a §5.2 waiting period cannot start unannounced',
  },
];

/** Every source file that imports this package, non-test, repo-wide. */
function consumerFiles(): string[] {
  const found: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      if (
        entry === 'node_modules' ||
        entry === 'dist' ||
        entry === 'dist-esm' ||
        entry === '.next'
      ) {
        continue;
      }
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) {
        walk(path);
      } else if (
        path.endsWith('.ts') &&
        !path.endsWith('.d.ts') &&
        !path.endsWith('.spec.ts') &&
        !path.includes(`${'/'}test${'/'}`) &&
        !path.includes('notifications-client') &&
        readFileSync(path, 'utf8').includes(PACKAGE_SPECIFIER)
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
 * Remove line and block comments, leaving string and template literals intact.
 * Quote-aware, so a `//` inside a string is not a comment.
 */
function code(source: string): string {
  let out = '';
  let mode: 'code' | 'line' | 'block' | 'single' | 'double' | 'tpl' = 'code';
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
    if (mode === 'single' || mode === 'double' || mode === 'tpl') {
      const quote = mode === 'single' ? "'" : mode === 'double' ? '"' : '`';
      if (c === '\\') {
        out += c + (next ?? '');
        i += 1;
        continue;
      }
      out += c;
      if (c === quote) {
        mode = 'code';
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
    if (c === "'" || c === '"' || c === '`') {
      mode = c === "'" ? 'single' : c === '"' ? 'double' : 'tpl';
    }
    out += c;
  }
  return out;
}

const read = (file: string): string => code(readFileSync(join(REPO_ROOT, file), 'utf8'));
const names = (source: string): boolean => /\baccepted\b/.test(source);

describe('the delivery-outcome discriminant is named only by declared adapters', () => {
  const consumers = consumerFiles();

  it('scanned a plausible number of consumers (vacuity guard)', () => {
    // Nine services plus their modules; if this collapses the equality below
    // holds trivially over two empty sets.
    expect(consumers.length).toBeGreaterThanOrEqual(10);
  });

  it('every consumer naming `accepted` is a declared adapter, and every declared adapter names it', () => {
    const naming = consumers.filter((file) => names(read(file)));
    expect(naming).toEqual(ADAPTERS.map((a) => a.file).sort());
  });

  it('every adapter carries a substantive reason', () => {
    for (const adapter of ADAPTERS) {
      expect(adapter.why.length).toBeGreaterThan(30);
    }
  });

  it('an adapter names it ONLY as a negated reachability gate', () => {
    // `if (!outcome.accepted)` is the whole permitted use. An adapter that
    // started deriving a DELIVERY fact from the discriminant would be the same
    // defect one layer down, in the files this table exempts.
    for (const adapter of ADAPTERS) {
      const source = read(adapter.file);
      const all = source.match(/\baccepted\b/g) ?? [];
      const negated = source.match(/!\s*[A-Za-z_$][\w$]*\.accepted\b/g) ?? [];
      expect(all.length).toBeGreaterThanOrEqual(1);
      expect(negated.length).toBe(all.length);
    }
  });
});

/**
 * THE DOUBLES, which is where the defect actually hid.
 *
 * No production gate could see the three wrong reads, because every spec in
 * identity's test directory hand-rolled its own notifications double and every
 * one of them answered a bare `{ accepted: true }` — NOT a valid `SendOutcome`,
 * since the accepted arm carries `delivered`, `channel` and `recipientVerified`
 * too. So the simulated send always "succeeded" in a way the real service
 * cannot, and reading the discriminant alone scored true against a shape that
 * does not exist. A DOUBLE MORE GENEROUS THAN THE PLATFORM IS WHERE THE BUG
 * LIVES — the M16 PR2b lesson, one layer beneath the fixtures.
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
  const DECLARATION = 'notifications-double.ts';

  const files = readdirSync(join(REPO_ROOT, TEST_DIR))
    .filter((f) => f.endsWith('.ts') && f !== DECLARATION)
    .map((f) => `${TEST_DIR}/${f}`);

  it('scanned identity’s test directory (vacuity guard)', () => {
    expect(files.length).toBeGreaterThanOrEqual(20);
  });

  it('no spec hand-rolls a send outcome', () => {
    const offenders = files.filter((file) => /\baccepted\s*:/.test(read(file)));
    expect(offenders).toEqual([]);
  });

  it('the declaration types its outcomes as SendOutcome, which is the actual check', () => {
    const source = read(`${TEST_DIR}/${DECLARATION}`);
    for (const name of ['DELIVERED', 'UNDELIVERED', 'DELIVERED_UNVERIFIED', 'UNREACHABLE']) {
      expect(source).toMatch(new RegExp(`export const ${name}\\s*:\\s*SendOutcome\\b`));
    }
  });
});

describe('the one spelling is actually used', () => {
  const consumers = consumerFiles();

  it('wasDelivered is called at every site that derives a delivery fact', () => {
    // The floor is the seven identity call sites this PR converted (two in
    // password-reset, two in email-change, one each in auth, email-verification
    // and webauthn). Without it, deleting every call and the reads with them
    // would leave the equality above green over a repo that asks the question
    // nowhere.
    const calls = consumers
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
