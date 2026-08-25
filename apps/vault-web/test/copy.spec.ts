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
 *   B. A SERVICE TOKEN NOBODY CLASSIFIED. Derived from the throws of every
 *      service `PROXY_ROUTES` names — the vault service alone until M44 PR1
 *      widened it, which is the narrowing described under `upstreams()` below.
 *      This is the half that would have caught PR3b's omission: a new
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
const SERVER = join(__dirname, '..', 'src', 'server.ts');
const SERVICES = join(__dirname, '..', '..', 'services');

/**
 * WHICH SERVICES THIS ORIGIN CAN RELAY A REFUSAL FROM, read out of the runtime's
 * own routing table rather than named here (M44 PR1).
 *
 * The corpus was `apps/services/vault/src` alone, and the claim over it was
 * "every service refusal is classified" — a corpus narrower than its claim, in
 * a fence written to catch exactly that. This origin also PROXIES three
 * identity routes, so `invalid_code`, `unauthorized` and `too_many_attempts`
 * are refusals it can put in front of a user, and none of them was in the
 * corpus. The step-up prompt was answering a dead session with "try the current
 * one" the whole time this fence was green.
 *
 * Deriving the upstream SET from `PROXY_ROUTES` means adding a fourth upstream
 * turns this red instead of silently leaving its vocabulary unchecked.
 *
 * `PASS_THROUGH_ROUTES` is deliberately NOT read, and the reason is structural
 * rather than a judgement: that table has no `upstream` field at all. Its two
 * entries are the EXTENSION's credential-free identity calls, identity-only by
 * construction, so there is nothing there to derive and no upstream it can name
 * that `PROXY_ROUTES` does not. Pointing one at a different service would mean
 * adding that field — a visible change that lands next to this comment.
 */
function upstreams(): string[] {
  const src = stripComments(readFileSync(SERVER, 'utf8'));
  const start = src.indexOf('const PROXY_ROUTES');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = src.indexOf('];', start);
  expect(end).toBeGreaterThan(start);
  const found = [...src.slice(start, end).matchAll(/upstream: '([a-z-]+)'/g)].map(
    (m) => m[1] as string,
  );
  // ANTI-VACUITY: a slice that matched nothing yields an empty set, which would
  // agree with any expectation below.
  expect(found.length).toBeGreaterThanOrEqual(4);
  return [...new Set(found)].sort();
}

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
  // the union's own documentation and derived 12 of 21 members. A floor caught
  // it, which is the only reason it is not still silently under-deriving.
  const src = stripComments(API_SRC);
  const start = src.indexOf('export type ApiFailure =');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = src.indexOf(';', start);
  expect(end).toBeGreaterThan(start);
  return [...src.slice(start, end).matchAll(/\|\s*'([A-Z_]+)'/g)].map((m) => m[1] as string);
}

/**
 * Each code `messageFor` answers, MAPPED TO THE SENTENCE IT RETURNS.
 *
 * THIS USED TO COLLECT LABELS AND NOTHING ELSE, and that is the hole an
 * adversarial lens found: the file is called "every failure code has a sentence
 * of its own" and no assertion in it could see two codes returning the SAME
 * English. Measured — restoring the exact defect M44 PR1 exists to fix, one
 * sentence for both a refused code and a dead session, left the whole package
 * green — 325 tests at that point in the branch, up from 318 at the base
 * commit and 327 once the two fences below landed. The whole user-visible effect of that change was unfenced
 * while the file's own suite name — "every failure code has a sentence of its
 * own" — and a case named "the two that share are the two that mean one thing",
 * whose COMMENT named the sharing pair because nothing here could compute it,
 * both said otherwise. (Counted as "three separate comments" in a first draft,
 * then as two; the header's appeal to `operator-web`'s fence is arguable either
 * way, which is the tell that the count was never the useful part.)
 *
 * Fall-through groups are resolved rather than skipped: labels accumulate until
 * a `return`, and that sentence is assigned to all of them, so a deliberate
 * pair like UNAVAILABLE/NETWORK is VISIBLE as a pair instead of invisible.
 */
function spokenSentences(): ReadonlyMap<string, string> {
  const src = stripComments(APP_SRC);
  const start = src.indexOf('function messageFor(');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = src.indexOf('\nfunction ', start + 10);
  expect(end).toBeGreaterThan(start);
  const spoken = new Map<string, string>();
  let pending: string[] = [];
  for (const line of src.slice(start, end).split('\n')) {
    const label = /case '([A-Z_]+)':/.exec(line);
    if (label) {
      pending.push(label[1] as string);
      continue;
    }
    const answer = /return '((?:[^'\\]|\\.)*)';/.exec(line);
    if (answer) {
      for (const code of pending) spoken.set(code, answer[1] as string);
      pending = [];
    }
  }
  // ANTI-VACUITY: a parser that matched no returns yields an empty map, which
  // would satisfy every "no duplicates" assertion below perfectly.
  expect(spoken.size).toBeGreaterThanOrEqual(20);
  return spoken;
}

/** The `case '...'` labels `messageFor` answers. */
function spokenCodes(): string[] {
  return [...spokenSentences().keys()];
}

/**
 * Codes that DELIBERATELY share one sentence, keyed by the group, with the
 * reason. A group is here or its codes each say something of their own; there
 * is no third state, which is what makes the assertion below mean anything.
 */
const SHARED: ReadonlyMap<string, string> = new Map([
  [
    'NETWORK|UNAVAILABLE',
    'One remedy — the vault is unreachable and the answer is to wait — so they share a case on purpose. Splitting them would invent a distinction the user cannot act on.',
  ],
]);

/**
 * REFUSALS THAT REACH THE WIRE THROUGH A VARIABLE, declared per site (M44 PR1).
 *
 * `serviceTokens()` reads `error: '<literal>'`, so a throw that computes its
 * token is INVISIBLE to it — and a fence written to catch "a corpus narrower
 * than its claim" had one. `already_waiting` never appears in the
 * `error: '<literal>'` SHAPE this scan reads, anywhere in the scanned service
 * sources — which is the whole of why it was invisible. (It is spelled
 * literally, at `emergency.service.ts:580` and in an integration test; an
 * earlier draft of this comment said "nowhere in this repo", which the very
 * next clause contradicts.) `blockReason` returns it and `emergency.service.ts` throws
 * `{ error: outcome.blocked }`. It could never have appeared unclassified,
 * because it could never have appeared at all.
 *
 * The fix is not a wider regex — a regex that chases values through variables
 * is a parser, and the next indirection defeats it silently. Instead the SITES
 * are derived and the VALUES are declared, asserted BOTH WAYS: a new computed
 * throw reddens as an undeclared site, and a site that stops computing its
 * token reddens as a stale key. What cannot be read is at least COUNTED.
 */
const INDIRECT: ReadonlyMap<string, readonly string[]> = new Map([
  [
    'vault/emergency.service.ts: outcome.blocked',
    // `blockReason`, which returns exactly these three or null.
    ['already_released', 'already_waiting', 'denied_by_owner'],
  ],
  [
    "vault/http-error.filter.ts: typeof errorToken === 'string' ? errorToken : 'request_failed'",
    ['request_failed'],
  ],
  [
    "identity/http-error.filter.ts: typeof errorToken === 'string' ? errorToken : 'request_failed'",
    ['request_failed'],
  ],
  [
    'identity/erasure.service.ts: refusalToken(refusal)',
    ['open_death_report', 'erasure_not_permitted'],
  ],
]);

/** Every `error:` throw whose token is NOT a literal, keyed `<upstream>/<file>: <expr>`. */
function indirectSites(): string[] {
  const found: string[] = [];
  for (const upstream of upstreams()) {
    const dir = join(SERVICES, upstream, 'src');
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.ts'))) {
      const src = stripComments(readFileSync(join(dir, file), 'utf8'));
      for (const m of src.matchAll(/error:\s*([^,}\n]+)/g)) {
        // NOT `(?!')` in the pattern: `\s*` backtracks to zero-width and the
        // lookahead then passes on a literal, so the first draft of this
        // "non-literal sites" scan returned every site in the corpus (92 today,
        // 88 of them literal) instead of the 4 it exists to find. Decide on the
        // captured text instead. The counts are illustrative and deliberately
        // not asserted — the FLOOR below is the assertion, and pinning a total
        // here would be a hand-maintained number beside a growing thing.
        const expr = (m[1] as string).trim();
        if (!expr.startsWith("'")) found.push(`${upstream}/${file}: ${expr}`);
      }
    }
  }
  return [...new Set(found)].sort();
}

/** Every token the upstream services throw, from their own sources. */
function serviceTokens(): string[] {
  // THE WHOLE DIRECTORY, never a named file list — `restorable-corpus.spec.ts`
  // leg B's rule, and the first draft of this function broke it. Naming three
  // services missed `http-error.filter.ts`, `vault-session.guard.ts` and
  // `schemas.ts`, which is where `internal_error` and `invalid_request` are
  // actually thrown — so the fence written to catch a corpus narrower than its
  // claim shipped with a corpus narrower than its claim. Caught by its own
  // stale-exemption assertion, which is the half most fences do not have.
  const out = new Set<string>();
  for (const upstream of upstreams()) {
    const dir = join(SERVICES, upstream, 'src');
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.ts'))) {
      const src = stripComments(readFileSync(join(dir, file), 'utf8'));
      for (const m of src.matchAll(/error:\s*'([a-z_]+)'/g)) out.add(m[1] as string);
    }
  }
  // The ones no regex can read, declared above and asserted site-for-site.
  for (const tokens of INDIRECT.values()) for (const t of tokens) out.add(t);
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
/**
 * THE ROUTES THIS ORIGIN RELAYS TO IDENTITY, declared so that "that ceremony is
 * not proxied here" stops being unchecked prose.
 *
 * Most identity tokens below are exempted because the ceremony that throws them
 * — login, registration, WebAuthn, e-mail change, the settlement lock — is not
 * reachable through this origin at all. That premise is only as good as the
 * route table, so the route table is asserted: proxy a fourth identity route
 * and this fence goes red, which is the prompt to re-read every reason here.
 */
const PROXIED_IDENTITY_ROUTES: readonly string[] = [
  '/api/auth/logout',
  '/api/auth/session',
  '/api/auth/stepup',
];

/**
 * Tokens handled by their STATUS rather than by name, with the status.
 *
 * `mappedTokens()` reads `token === '…'` tests out of `failureFor`, so a refusal
 * the client answers correctly via a status branch looks exactly like one nobody
 * classified. Both of these are REACHABLE on `POST /api/auth/stepup` and both
 * are answered correctly — recording them as unreachable would have been false,
 * and leaving them out of the map would have made this fence unpassable for the
 * wrong reason. The status branch itself is asserted below.
 */
const BY_STATUS: ReadonlyMap<string, number> = new Map([
  ['unauthorized', 401],
  ['too_many_attempts', 429],
]);

const UNNAMED: ReadonlyMap<string, string> = new Map([
  [
    'invalid_credentials',
    'identity: the LOGIN refusal. This origin proxies no login route — see PROXIED_IDENTITY_ROUTES.',
  ],
  [
    'invalid_token',
    'identity: a refused REFRESH token. `/api/auth/refresh` is a pass-through for the EXTENSION; this client never calls it.',
  ],
  ['webauthn_failed', 'identity: passkey ceremony, not proxied here.'],
  ['too_soon', 'identity: the e-mail-change cooldown, not proxied here.'],
  ['verification_unavailable', 'identity: address verification, not proxied here.'],
  [
    'content_erased',
    'identity: a crypto-shredded account, reached through routes this origin does not proxy.',
  ],
  ['invalid_transition', 'identity: the settlement lock state machine, not proxied here.'],
  ['owner_alive', 'identity: the settlement lock liveness refusal, not proxied here.'],
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
    '409 CONFLICT, and "reload" is the true remedy. Two throw sites: `rearm`, an OWNER control the screen refuses before the call; and `blockReason` on the grantee REQUEST path, reachable only from a view that predates the release. The first reason alone was what this entry used to say, and it stopped being the whole truth the moment INDIRECT made the second site visible.',
  ],
  [
    'already_waiting',
    '409 CONFLICT on a request the grantee already made. The button is offered only for `configured`/`requested`, so this needs a STALE VIEW to reach — which is exactly what CONFLICT says, and reloading does show the running waiting period. Judged rather than defaulted: unlike `denied_by_owner`, which is sticky until the owner re-arms and where "reload and try again" is the wrong advice, here the view really is the thing that is out of date.',
  ],
  [
    'request_failed',
    "The error filter generic for a non-string upstream token — `internal_error`'s sibling, and UNKNOWN is the honest sentence for both.",
  ],
  [
    'open_death_report',
    'identity: the ERASURE ceremony. Not proxied here — see PROXIED_IDENTITY_ROUTES.',
  ],
  ['erasure_not_permitted', 'identity: the same erasure ceremony, likewise not proxied.'],
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

  it('gives every code a sentence of its OWN, and the sharing that remains is declared', () => {
    /*
     * DISCRIMINATION, NOT PRESENCE. Set-membership over case labels is
     * satisfied by a `messageFor` that returns one string for everything —
     * which is precisely the shape of the defect this origin shipped.
     */
    const spoken = spokenSentences();
    const groups = new Map<string, string[]>();
    for (const [code, sentence] of spoken) {
      groups.set(sentence, [...(groups.get(sentence) ?? []), code]);
    }
    const sharing = [...groups.values()]
      .filter((codes) => codes.length > 1)
      .map((codes) => [...codes].sort().join('|'))
      .sort();
    const undeclared = sharing.filter((group) => !SHARED.has(group));
    expect(undeclared).toEqual([]);
    // The other direction: a declared pair that no longer shares anything is a
    // claim about the tree nobody checks.
    const stale = [...SHARED.keys()].filter((group) => !sharing.includes(group));
    expect(stale).toEqual([]);
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

  it('accounts for every refusal whose token is COMPUTED, not spelled', () => {
    /*
     * WHAT A REGEX CANNOT READ, COUNTED. The literal scan above is blind to
     * `throw new ConflictException({ error: outcome.blocked })`, and that is
     * how `already_waiting` — which `blockReason` returns but no `error:`
     * literal ever spells — stayed outside a corpus this file claims is
     * complete.
     *
     * BOTH DIRECTIONS. A new computed throw reddens here as an undeclared
     * site; a site that becomes a literal, or moves, reddens as a stale key.
     * Neither can be satisfied by the other, which is the difference between
     * this and a hand-list that happens to agree today.
     */
    const sites = indirectSites();
    // ANTI-VACUITY: a scan matching nothing would make `undeclared` empty and
    // agree with the first assertion while proving nothing.
    expect(sites.length).toBeGreaterThanOrEqual(4);
    expect(sites.filter((site) => !INDIRECT.has(site))).toEqual([]);
    expect([...INDIRECT.keys()].filter((site) => !sites.includes(site))).toEqual([]);
    // And the point of it all: the tokens it contributes really are in the
    // corpus the classification assertion runs over.
    expect(serviceTokens()).toContain('already_waiting');
  });

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
    const unclassified = tokens.filter(
      (t) => !mapped.includes(t) && !UNNAMED.has(t) && !BY_STATUS.has(t),
    );
    expect(unclassified).toEqual([]);
  });

  it('the STATUS-handled tokens really do have a status branch', () => {
    // A token excused as "the status covers it" is a claim about `failureFor`.
    // Without this, deleting the 429 branch would leave `too_many_attempts`
    // looking classified while the cap read as an outage again.
    const src = stripComments(API_SRC);
    const start = src.indexOf('function failureFor(');
    expect(start).toBeGreaterThanOrEqual(0);
    const body = src.slice(start, src.indexOf('\n}', start));
    const missing = [...BY_STATUS.entries()]
      .filter(([, status]) => !body.includes(`status === ${status}`))
      .map(([token, status]) => `${token} claims status ${status}`);
    expect(missing).toEqual([]);
  });

  it('the proxied identity route set is what the server actually declares', () => {
    // The premise under most reasons in UNNAMED: those ceremonies are not
    // reachable through this origin. Proxy a fourth identity route and this
    // goes red rather than leaving eight stale excuses in place.
    const src = stripComments(readFileSync(SERVER, 'utf8'));
    const start = src.indexOf('const PROXY_ROUTES');
    const table = src.slice(start, src.indexOf('];', start));
    const identityRoutes = [...table.matchAll(/prefix: '([^']+)',\s*upstream: 'identity'/g)]
      .map((m) => m[1] as string)
      .sort();
    expect(identityRoutes).toEqual([...PROXIED_IDENTITY_ROUTES]);
  });

  it('and records no reason for a token that no longer exists', () => {
    // THE OTHER DIRECTION, because a stale exemption is a claim about the tree
    // that nobody checks — this repo's most repeated defect, in miniature.
    const stale = [...UNNAMED.keys()].filter((t) => !tokens.includes(t));
    expect(stale).toEqual([]);
    const staleByStatus = [...BY_STATUS.keys()].filter((t) => !tokens.includes(t));
    expect(staleByStatus).toEqual([]);
    // A token cannot be both named and excused: that is two answers to one
    // question, and the next reader would not know which is current.
    expect(mapped.filter((t) => UNNAMED.has(t))).toEqual([]);
  });
});
