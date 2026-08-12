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

/**
 * Is this host an internationalised (punycode) label?
 *
 * A FACT ABOUT ONE DOMAIN, and after the M16 review it is used as one. It used
 * to feed `isConfusable` directly — "any punycode on either side, against a
 * domain that is not identical, is refused as confusable" — which read as
 * cautious and was not a comparison at all: it took no account of the OTHER
 * domain, so it answered true for every unrelated pair. See `isConfusable`.
 */
export function hasPunycode(host: string): boolean {
  return host.split('.').some((label) => label.startsWith('xn--'));
}

/**
 * IS THIS PAGE'S DOMAIN A LOOKALIKE OF THIS SAVED ONE — a question about a PAIR.
 *
 * ═══ THE PUNYCODE CLAUSE IS GONE, AND REMOVING IT MADE THIS STRONGER ═══
 *
 * It used to begin "any punycode on either side, against a domain that is not
 * identical, is refused as confusable". That is not a comparison: it ignores
 * the other domain entirely, so it answered TRUE for every unrelated pair. The
 * M16 review measured what that cost. Because `matchesFor` keeps `confusable`
 * verdicts and drops only `no-match`, ONE VISIT TO ANY INTERNATIONALISED PAGE
 * returned the WHOLE VAULT from the key holder — every item's title and every
 * item's registrable domain — which is precisely the disclosure `matchesFor`'s
 * own docstring says the design exists to prevent ("would disclose a list of
 * every site the user has an account with in order to answer a question about
 * ONE origin"). Five saved items, five `confusable` rows, on a page related to
 * none of them.
 *
 * It cost the control as well as the secret. A lookalike refusal that fires on
 * every item at once, on ordinary pages, is an alarm nobody reads — and this
 * refusal is the one bound §4 TB9 says M16 owes against phishing.
 *
 * IT GAVE UP NOTHING THE BOUNDARY NEEDED, which is why the answer is deletion
 * rather than a cleverer rule. Filling requires `savedDomain === pageDomain`,
 * so a punycode host that is not the saved domain was ALREADY unfillable; the
 * clause only decided how the refusal was LABELLED. What is lost is the
 * explanation for a genuine punycode homograph, and §6j already names that as
 * the accepted failure direction for the general Unicode case: "a miss is a
 * `no-match`, so it is still REFUSED for filling — what is lost is the
 * explanation, never the boundary."
 *
 * Telling a user their page is internationalised is a fact about the PAGE, so
 * it belongs to the page and not to each item: `hasPunycode` is exported and
 * the popup says it once. Deciding whether a specific IDN is a homograph OF a
 * specific saved domain needs punycode decoding plus UTS #39 skeletons, which
 * remains the named follow-up.
 *
 * WHAT THIS CATCHES: a domain whose ASCII homoglyph SKELETON equals the saved
 * one (`exarnple.com`, `paypa1.com`, `vvells.com`), and a domain within one
 * edit (a doubled or dropped character).
 */
function isConfusable(savedDomain: string, pageDomain: string): boolean {
  if (savedDomain === pageDomain) return false;
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

/*
 * `frameIsAllowed` LIVED HERE AND IS GONE (M16 PR3b).
 *
 * PR3a declared it for PR3b to wire, and PR3b narrowed it from same-site to
 * same-origin after measuring the platform. Then wiring it showed it cannot
 * have a caller at all, which is a better answer than either:
 *
 *   · The popup cannot enumerate frames. Reading frame ids needs `webNavigation`
 *     or `tabs`, and this extension deliberately holds neither — the only
 *     permission-free route is `executeScript({allFrames:true})`, which is an
 *     injection into every reachable frame BEFORE any origin decision, i.e. the
 *     opposite order from the one TB9 wants.
 *   · The injected function cannot import it. `func` is serialized for
 *     injection, so it closes over nothing and carries no module.
 *
 * So the rule had nowhere to run, and a rule with nowhere to run is the M4
 * zero-callers shape — the thing this milestone keeps closing. It is deleted
 * rather than kept "for later", and what replaces it is not a weaker rule but a
 * stronger one: THE PLATFORM ENFORCES THIS ITSELF, measured in Chrome 151. An
 * `executeScript` at a frame the activeTab grant does not cover is refused with
 * "Cannot access contents of the page", and the grant is the top frame's origin,
 * host-exact. PR3b fills the TOP FRAME ONLY; a login form inside even a
 * same-origin subframe is not filled, and that limitation is stated in docs/03
 * §6j rather than papered over with a rule that would only have agreed with the
 * platform when the platform was already saying no.
 */

export { normaliseHost };
