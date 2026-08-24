/**
 * EVERY REFUSAL THIS ORIGIN CAN MEET IS A DECISION SOMEBODY RECORDED (M27 PR5).
 *
 * WHY THIS EXISTS. M27 PR3b named four refusals on the grantee's READING screen
 * and left the RELEASE screen's two unnamed one route over. `waiting_period_active`
 * — the §5.2 window itself, the control this entire feature is built around —
 * fell off the end of the 403 block to `UNKNOWN` and reached the reader as
 * "Something went wrong. Try again."; `not_requested` fell to `CONFLICT`'s "This
 * item changed since you opened it. Reload and try again" on a screen holding no
 * item. Both were found by driving the running product, and neither was visible
 * to any test, because the only thing watching this mapping was a hand-written
 * table scoped to the read route.
 *
 * THE PATTERN IS LIFTED, NOT INVENTED. `apps/operator-web/test/copy.spec.ts`
 * already derives its `ApiFailure` union from its own `api.ts` and asserts a
 * distinct sentence per code. That fence existed while this origin had none —
 * the same rule, applied to one of the two clients that needed it.
 *
 * TWO HALVES, WITH DIFFERENT CORPORA, because the two failure modes differ:
 *
 *   A. A CODE WITH NO SENTENCE. Derived from the union's own declaration, so a
 *      member added without copy reddens. This is the cheap half.
 *   B. A SERVICE TOKEN NOBODY CLASSIFIED. Derived from the vault service's own
 *      throws. This is the half that would have caught PR3b's omission: a new
 *      token arrives UNCLASSIFIED and must be either mapped in `failureFor` or
 *      recorded below with a reason. Silence is not an option, which is the
 *      whole difference between this and the table it supplements.
 *
 * BY SOURCE, NOT BY IMPORT. `messageFor` and `failureFor` are module-private and
 * stay that way: a test-only export into a Zone A client is a surface, and this
 * origin's whole argument is that it has none it did not choose. `fences.spec.ts`
 * reads this same source the same way.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const API = join(__dirname, '..', 'src', 'client', 'api.ts');
const APP = join(__dirname, '..', 'src', 'client', 'app.ts');
const SERVICE_DIR = join(__dirname, '..', '..', 'services', 'vault', 'src');

const API_SRC = readFileSync(API, 'utf8');
const APP_SRC = readFileSync(APP, 'utf8');

/** Comments out, so a fence never reads its own documentation. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
}

/** The `ApiFailure` union's own members. */
function declaredCodes(): string[] {
  // STRIPPED FIRST, and the first draft of this function is why the comment is
  // here: reading the RAW source, `indexOf(';')` stopped at a semicolon inside
  // the union's own documentation and derived 12 of 28 members. A floor caught
  // it, which is the only reason it is not still silently under-deriving.
  const src = stripComments(API_SRC);
  const start = src.indexOf('export type ApiFailure =');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = src.indexOf(';', start);
  expect(end).toBeGreaterThan(start);
  return [...src.slice(start, end).matchAll(/\|\s*'([A-Z_]+)'/g)].map((m) => m[1] as string);
}

/** The `case '...'` labels `messageFor` answers. */
function spokenCodes(): string[] {
  const src = stripComments(APP_SRC);
  const start = src.indexOf('function messageFor(');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = src.indexOf('\nfunction ', start + 10);
  return [...src.slice(start, end).matchAll(/case '([A-Z_]+)':/g)].map((m) => m[1] as string);
}

/** Every token the vault service throws, from the service's own source. */
function serviceTokens(): string[] {
  // THE WHOLE DIRECTORY, never a named file list — `restorable-corpus.spec.ts`
  // leg B's rule, and the first draft of this function broke it. Naming three
  // services missed `http-error.filter.ts`, `vault-session.guard.ts` and
  // `schemas.ts`, which is where `internal_error` and `invalid_request` are
  // actually thrown — so the fence written to catch a corpus narrower than its
  // claim shipped with a corpus narrower than its claim. Caught by its own
  // stale-exemption assertion, which is the half most fences do not have.
  const out = new Set<string>();
  for (const file of readdirSync(SERVICE_DIR).filter((f) => f.endsWith('.ts'))) {
    const src = stripComments(readFileSync(join(SERVICE_DIR, file), 'utf8'));
    for (const m of src.matchAll(/error:\s*'([a-z_]+)'/g)) out.add(m[1] as string);
  }
  return [...out].sort();
}

/** Tokens `failureFor` matches by name. */
function mappedTokens(): string[] {
  const src = stripComments(API_SRC);
  const start = src.indexOf('function failureFor(');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = src.indexOf('\n}', start);
  return [...src.slice(start, end).matchAll(/token === '([a-z_]+)'/g)].map((m) => m[1] as string);
}

/**
 * TOKENS THAT DELIBERATELY CARRY NO NAME, each with the reason it does not need
 * one. A token is here or in `failureFor`; there is no third state, and that is
 * the point of the assertion below.
 *
 * The test is that the STATUS already carries the whole remedy. Where it does
 * not — where two refusals at one status need different advice — the token is
 * named instead. `invalid_cursor` states the rule at length in `api.ts`: prefer
 * the ABSENCE to the filter.
 */
const UNNAMED: ReadonlyMap<string, string> = new Map([
  ['not_found', 'THE uniform 404. Naming it would defeat the fusion it exists for.'],
  ['escrow_not_found', '404. Same uniform answer; the screen it lands on says what is missing.'],
  ['keyset_not_found', '404, and the unlock screen is the remedy rather than a sentence.'],
  ['recovery_key_not_found', '404, handled locally where the offer is made (app.ts overrides it).'],
  ['grantee_key_not_found', '404, handled locally at the key-offer site for the same reason.'],
  ['version_owner_mismatch', '404 on a row that is not yours — the uniform answer again.'],
  ['invalid_request', '400. INVALID_REQUEST already says exactly this and nothing more.'],
  ['invalid_cursor', 'A bug in THIS client, never a user condition. See api.ts.'],
  ['internal_error', 'The error filter generic. UNKNOWN is the honest sentence for it.'],
  ['item_exists', '409 CONFLICT, and the form it lands on names the field.'],
  ['keyset_exists', '409 CONFLICT, same.'],
  [
    'already_released',
    'Unreachable from this client: `rearm` is an OWNER control and the screen refuses it before the call.',
  ],
  [
    'duplicate_grantee',
    '400 from the picker, which cannot construct one — INVALID_REQUEST suffices.',
  ],
  ['self_grantee', '400 from the picker, likewise.'],
  ['no_grantees', '400 from the arm form, likewise.'],
  ['threshold_exceeds_grantees', '400; this client pins threshold to 1 and cannot raise it.'],
  ['srp_failed', 'The unlock ceremony owns its own copy — one message for both halves of 2SKD.'],
  ['invalid_keyset_proof', 'Same ceremony, same dedicated screen.'],
]);

describe('every failure code has a sentence of its own', () => {
  const codes = declaredCodes();
  const spoken = spokenCodes();

  it('derives the whole union', () => {
    // ANTI-VACUITY: a scan matching nothing agrees with every table below.
    expect(codes.length).toBeGreaterThanOrEqual(20);
    expect(codes).toContain('WAITING_PERIOD');
    expect(codes).toContain('ACCESS_STOPPED');
  });

  it('answers every declared code, and the two that share are the two that mean one thing', () => {
    // SETS, not counts. `UNKNOWN` is the `default` arm and `UNAVAILABLE`/`NETWORK`
    // share a case deliberately — both are "the vault is unreachable", one
    // remedy — so they are named here rather than left to be inferred.
    const missing = codes.filter((c) => !spoken.includes(c) && c !== 'UNKNOWN');
    expect(missing).toEqual([]);
    // And nothing is spoken that the union does not declare.
    expect(spoken.filter((c) => !codes.includes(c))).toEqual([]);
  });
});

describe('every service refusal is classified', () => {
  const tokens = serviceTokens();
  const mapped = mappedTokens();

  it('derives the service vocabulary', () => {
    // ANTI-VACUITY on the corpus, and on a member that must be there: the
    // token this whole fence was written because of.
    expect(tokens.length).toBeGreaterThanOrEqual(25);
    expect(tokens).toContain('waiting_period_active');
    expect(tokens).toContain('not_requested');
    expect(mapped).toContain('denied_by_owner');
  });

  it('leaves NO token unclassified — named in failureFor, or recorded with a reason', () => {
    /*
     * THE ASSERTION THAT WOULD HAVE CAUGHT M27 PR3b'S OMISSION.
     *
     * A token this origin can meet must be a decision somebody made. Named, so
     * the reader gets a sentence about what actually happened; or listed in
     * UNNAMED with the reason the STATUS already carries the whole remedy.
     * Adding a refusal to the service and shipping it is what put "Something
     * went wrong. Try again." in front of a grantee holding a waiting period.
     */
    const unclassified = tokens.filter((t) => !mapped.includes(t) && !UNNAMED.has(t));
    expect(unclassified).toEqual([]);
  });

  it('and records no reason for a token that no longer exists', () => {
    // THE OTHER DIRECTION, because a stale exemption is a claim about the tree
    // that nobody checks — this repo's most repeated defect, in miniature.
    const stale = [...UNNAMED.keys()].filter((t) => !tokens.includes(t));
    expect(stale).toEqual([]);
    // A token cannot be both named and excused: that is two answers to one
    // question, and the next reader would not know which is current.
    expect(mapped.filter((t) => UNNAMED.has(t))).toEqual([]);
  });
});
