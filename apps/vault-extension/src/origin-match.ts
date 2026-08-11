import { normaliseHost, registrableDomain } from './registrable-domain.js';

/**
 * SHOULD THIS SAVED CREDENTIAL BE OFFERED ON THIS PAGE?
 *
 * The boundary's defining decision (docs/03 §4 TB9): *a filled credential
 * belongs to the page that received it*. The isolated world protects the
 * extension's variables, not the DOM value, so this function IS the disclosure
 * decision — every other control in the milestone is downstream of it.
 *
 * A VERDICT, NOT A BOOLEAN. `no-match` and `confusable` are different facts: one
 * means the user has nothing saved here, the other means they have something
 * saved somewhere that looks like here, which is the moment worth telling them
 * about. Collapsing them would make a refusal indistinguishable from an absence
 * — the shape this repository keeps finding (M10 PR4's readiness statuses, M9's
 * "a control firing must not read as an outage").
 *
 * REFUSAL, NOT A WARNING. §4 TB9 commits to refusing a confusable rather than
 * warning about it, and PR3b's fill offers only `match`. The popup may EXPLAIN a
 * refusal; nothing acts on one.
 */

export type MatchVerdict =
  /** Same registrable domain, and the scheme is acceptable. Fillable (PR3b). */
  | { readonly kind: 'match'; readonly domain: string }
  /** Nothing about this saved item relates to this page. */
  | { readonly kind: 'no-match' }
  /**
   * Same domain, but the page is `http` and the credential was saved on
   * `https`. Refused: a network attacker who can serve the page can read what
   * is typed into it, and "it is the right domain" is exactly the reasoning
   * that makes the downgrade valuable.
   */
  | { readonly kind: 'scheme-downgrade'; readonly domain: string }
  /**
   * Not the saved domain, but close enough to it that a person would not
   * notice. REFUSED rather than warned about.
   */
  | { readonly kind: 'confusable'; readonly savedDomain: string; readonly pageDomain: string }
  /** The saved item has no usable URL, or the page has no registrable domain. */
  | { readonly kind: 'unusable' };

/** Parsed once; a URL that will not parse can never match anything. */
function parse(url: string | undefined): URL | null {
  if (typeof url !== 'string' || url.length === 0) return null;
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/**
 * Levenshtein distance, bounded — we only ever ask "is it within 1?", so the
 * moment two edits are needed the answer is no and the work stops.
 */
export function withinOneEdit(a: string, b: string): boolean {
  if (a === b) return false; // identical is not "confusable", it is the same
  if (Math.abs(a.length - b.length) > 1) return false;
  const [shorter, longer] = a.length <= b.length ? [a, b] : [b, a];
  let i = 0;
  let j = 0;
  let edits = 0;
  while (i < shorter.length && j < longer.length) {
    if (shorter[i] === longer[j]) {
      i += 1;
      j += 1;
      continue;
    }
    edits += 1;
    if (edits > 1) return false;
    if (shorter.length === longer.length) i += 1; // substitution
    j += 1; // insertion, or the substituted character
  }
  return edits + (longer.length - j) + (shorter.length - i) <= 1;
}

/**
 * A POOR MAN'S SKELETON: fold the multi-character homoglyphs that carry the
 * classic attacks, then compare.
 *
 * Edit distance alone does NOT catch these, and finding that out is what this
 * function exists for. `exarnple.com` is TWO edits from `example.com`
 * (substitute `m`→`r`, insert `n`), so a distance-1 check calls it `no-match` —
 * refused for filling, but never FLAGGED, and `rn`/`m` is the most-cited
 * homograph there is. The scope decision for this PR was taken on the claim
 * that punycode plus edit-distance-1 covered it. It did not.
 *
 * Both sides are folded, so the comparison is symmetric. Digits that read as
 * letters go the same way (`paypa1` → `paypal`). This is deliberately NOT UTS
 * #39: the full skeleton algorithm needs a vendored Unicode confusables table
 * and is a named follow-up (docs/03 §6j). What this adds is the short list of
 * ASCII sequences that actually get used, and every miss remains a REFUSAL —
 * the failure is a missing explanation, never a wrongful fill.
 */
const HOMOGLYPH_SEQUENCES: readonly (readonly [string, string])[] = [
  ['rn', 'm'],
  ['vv', 'w'],
  ['cl', 'd'],
  ['nn', 'm'],
];

export function homoglyphSkeleton(domain: string): string {
  let folded = domain;
  for (const [from, to] of HOMOGLYPH_SEQUENCES) folded = folded.split(from).join(to);
  return folded.replace(/1/g, 'l').replace(/0/g, 'o').replace(/5/g, 's');
}

/** Is this host an internationalised (punycode) label? */
function hasPunycode(host: string): boolean {
  return host.split('.').some((label) => label.startsWith('xn--'));
}

/**
 * WHAT THIS CATCHES AND WHAT IT DOES NOT — stated here because the gap is real.
 *
 * Caught: a punycode host that is not the saved one (so a homograph of
 * `example.com` never matches it); a domain whose ASCII homoglyph SKELETON
 * equals the saved one (`exarnple.com`, `paypa1.com`, `vvells.com`); and a
 * domain within one edit (a doubled or dropped character).
 *
 * NOT caught: the general Unicode confusable case. Full UTS #39 skeletons need a
 * vendored confusables table, which is a named follow-up (docs/03 §6j). A
 * multi-character homograph that is neither punycode nor within one edit will
 * simply be `no-match` — refused for filling, but not FLAGGED as confusable.
 * That is the safe direction: the failure is a missing explanation, never a
 * wrongful fill.
 */
function isConfusable(savedDomain: string, pageDomain: string): boolean {
  if (savedDomain === pageDomain) return false;
  // Any punycode on either side, against a domain that is not identical, is
  // refused as confusable — an IDN that is not the saved domain has no business
  // being offered the saved domain's credential.
  if (hasPunycode(pageDomain) || hasPunycode(savedDomain)) return true;
  if (homoglyphSkeleton(savedDomain) === homoglyphSkeleton(pageDomain)) return true;
  return withinOneEdit(savedDomain, pageDomain);
}

/**
 * The decision.
 *
 * `savedUrl` is the item's own `url` field — which lives INSIDE the encrypted
 * blob, so this runs in the key holder and nowhere else.
 */
export function matchOrigin(savedUrl: string | undefined, pageUrl: string): MatchVerdict {
  const saved = parse(savedUrl);
  const page = parse(pageUrl);
  if (!saved || !page) return { kind: 'unusable' };

  const savedDomain = registrableDomain(saved.hostname);
  const pageDomain = registrableDomain(page.hostname);
  if (savedDomain === null || pageDomain === null) return { kind: 'unusable' };

  if (savedDomain === pageDomain) {
    // SCHEME BINDING. `https` saved may only be offered on `https`; a credential
    // saved on plain `http` carries no such promise and is offered on either,
    // because refusing it would be refusing the only thing that site supports.
    const savedSecure = saved.protocol === 'https:';
    const pageSecure = page.protocol === 'https:';
    if (savedSecure && !pageSecure) return { kind: 'scheme-downgrade', domain: pageDomain };
    return { kind: 'match', domain: pageDomain };
  }

  if (isConfusable(savedDomain, pageDomain)) {
    return { kind: 'confusable', savedDomain, pageDomain };
  }
  return { kind: 'no-match' };
}

/** True only for the one verdict PR3b's fill will act on. */
export function isFillable(verdict: MatchVerdict): boolean {
  return verdict.kind === 'match';
}

/**
 * A SUBFRAME IS FILLABLE ONLY IF IT IS SAME-ORIGIN WITH THE TOP FRAME (§4 TB9).
 *
 * NARROWED IN PR3b FROM SAME-SITE TO SAME-ORIGIN, because the platform was
 * measured and the old rule was more permissive than the platform is. PR3a
 * allowed any subframe sharing a registrable domain and scheme, on the reasoning
 * that "a same-site iframe is the page". Chrome disagrees: `activeTab` grants
 * exactly the main frame's ORIGIN — Chromium builds the pattern as
 * `origin.Serialize() + "/*"`, which is host-exact and does not match
 * subdomains. Measured in Chrome 151 against a page carrying all three shapes:
 *
 *   http://example.test/        top          INJECTED
 *   http://example.test/        same origin  INJECTED
 *   http://pay.example.test/    same site    REFUSED — "Cannot access contents
 *                                            of the page. Extension manifest
 *                                            must request permission to access
 *                                            the respective host."
 *   http://other.test/          cross origin REFUSED
 *
 * So the old rule computed "allowed" for a frame the fill could only ever fail
 * on. A rule that disagrees with the platform is worse than no rule: it puts
 * the refusal at the bottom of the stack, as an opaque platform error, instead
 * of at the top as a decision this code took on purpose.
 *
 * THE PER-ITEM OPT-IN IS GONE, not deferred. It was documented as the escape
 * hatch for a cross-origin frame, and the same measurement shows it cannot be
 * built on `activeTab` at all — honouring it needs host permissions for the
 * third-party origin, i.e. `optional_host_permissions` plus a runtime
 * `chrome.permissions.request()`: a new manifest key and a new consent surface,
 * neither of which this milestone has. A flag that can never be honoured is the
 * M4 zero-callers shape with an extra step, so it is removed here and docs/03
 * §6j is corrected rather than left describing a capability that cannot exist.
 */
export function frameIsAllowed(input: {
  readonly isTopFrame: boolean;
  readonly topUrl: string;
  readonly frameUrl: string;
}): boolean {
  if (input.isTopFrame) return true;
  const top = parse(input.topUrl);
  const frame = parse(input.frameUrl);
  if (!top || !frame) return false;
  // `URL.origin` is scheme + host + port, which is exactly what the grant is
  // keyed on — so this asks the platform's own question rather than a proxy for
  // it. It also keeps the scheme binding the old rule checked separately.
  return top.origin === frame.origin && top.origin !== 'null';
}

export { normaliseHost };
