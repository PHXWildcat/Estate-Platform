/**
 * THE MATCHER IS THE CONTROL, so it gets a table rather than a few examples.
 *
 * docs/03 §4 TB9: *a filled credential belongs to the page that received it*.
 * Every case below is either a way that goes wrong in the wild or a rule the
 * threat model commits to in writing. The two traps at the top are the ones a
 * naive `includes()` passes and a naive "last two labels" passes — both named
 * in §4 TB9, both exploitable rather than sloppy.
 */
import { hasPunycode, matchOrigin, isFillable, withinOneEdit } from '../src/origin-match';
import { normaliseHost, publicSuffix, registrableDomain } from '../src/registrable-domain';

describe('the registrable domain comes from the list, not from string surgery', () => {
  it.each([
    ['www.example.com', 'example.com'],
    ['example.com', 'example.com'],
    ['deep.sub.example.com', 'example.com'],
    // MULTI-LABEL SUFFIXES: "last two labels" would call this `co.uk`, which
    // would make every British site one registrable domain.
    ['www.example.co.uk', 'example.co.uk'],
    ['example.co.uk', 'example.co.uk'],
    ['a.b.c.example.co.uk', 'example.co.uk'],
    // An unknown TLD falls to the implicit `*` rule: the last label.
    ['thing.somebrandnewtld', 'thing.somebrandnewtld'],
  ])('%s → %s', (host, expected) => {
    expect(registrableDomain(host)).toBe(expected);
  });

  it.each([
    ['com'], // a bare suffix is not registrable
    ['co.uk'],
    ['localhost'], // single label
    ['127.0.0.1'], // an IP is not a domain
    ['::1'],
    [''],
    ['..'],
  ])('%s has no registrable domain', (host) => {
    expect(registrableDomain(host)).toBeNull();
  });

  it('applies the list’s wildcard and exception rules', () => {
    // `*.ck` with `!www.ck`: the exception wins outright.
    expect(publicSuffix('anything.ck')).toBe('anything.ck');
    expect(registrableDomain('foo.anything.ck')).toBe('foo.anything.ck');
    expect(publicSuffix('www.ck')).toBe('ck');
    expect(registrableDomain('www.ck')).toBe('www.ck');
  });

  it('refuses a host with an empty label', () => {
    // `a..com` is not a host; guessing a suffix for it is how a matcher starts
    // answering questions about strings nobody could register.
    expect(registrableDomain('a..com')).toBeNull();
    expect(publicSuffix('a..com')).toBeNull();
  });

  it('is case- and trailing-dot-insensitive', () => {
    expect(registrableDomain('WWW.Example.COM.')).toBe('example.com');
  });
});

describe('matchOrigin', () => {
  const saved = 'https://www.example.com/login';

  it('matches the same registrable domain, across subdomains', () => {
    for (const page of [
      'https://example.com/',
      'https://www.example.com/anything?q=1',
      'https://accounts.example.com/signin',
    ]) {
      expect(matchOrigin(saved, page)).toEqual({ kind: 'match', domain: 'example.com' });
    }
  });

  /**
   * THE SUBSTRING TRAPS. A matcher built on `includes()` fills an attacker's
   * origin with the user's bank password, which is the exact failure §4 TB9
   * describes.
   */
  it.each([
    ['https://evil-example.com/', 'a domain that CONTAINS the saved one'],
    ['https://example.com.evil.net/', 'the saved domain as a SUBDOMAIN of evil'],
    ['https://notexample.com/', 'a suffix collision'],
    ['https://example.com.br/', 'the same label under a different suffix'],
  ])('refuses %s (%s)', (page) => {
    expect(matchOrigin(saved, page).kind).not.toBe('match');
  });

  it('refuses a sibling site under the same multi-label suffix', () => {
    // `bank.co.uk` and `shop.co.uk` share `co.uk` and nothing else. A
    // label-stripping matcher offers one's credential at the other.
    expect(matchOrigin('https://bank.co.uk/', 'https://shop.co.uk/').kind).not.toBe('match');
  });

  /*
   * THE SAME REFUSAL UNDER AN INTERNATIONALISED SUFFIX, which is where it was
   * NOT happening.
   *
   * `公司.cn` is a registry suffix exactly as `co.uk` is, and the list contains
   * it — but the list stores it as a U-label while `URL.hostname` always hands
   * back the A-label (`xn--55qx5d.cn`). Nothing converted, so the rule could
   * never match, the longest match fell back to `cn`, and the registrable
   * domain of BOTH registrants became `xn--55qx5d.cn`. Two different
   * registrants compared equal and `matchOrigin` said `match` — a credential
   * offered on somebody else's site, which is the failure §4 TB9 calls the
   * boundary's defining one and which `registrable-domain.ts` names in its own
   * docstring as the reason it uses the list at all.
   *
   * 459 of the list's 10,239 rules are affected; the ASCII path was always
   * correct, which is why every existing test passed over it.
   */
  it('refuses a sibling site under an INTERNATIONALISED multi-label suffix', () => {
    expect(matchOrigin('https://bank.公司.cn/', 'https://shop.公司.cn/').kind).not.toBe('match');
  });

  it('still matches a site under an internationalised suffix against itself', () => {
    // The refusal above must not be bought by making every IDN host unusable:
    // one registrant is still one registrant across its own subdomains.
    expect(matchOrigin('https://bank.公司.cn/login', 'https://www.bank.公司.cn/').kind).toBe(
      'match',
    );
  });

  it('binds the scheme: https-saved is never offered on http', () => {
    expect(matchOrigin(saved, 'http://www.example.com/')).toEqual({
      kind: 'scheme-downgrade',
      domain: 'example.com',
    });
  });

  it('does not refuse an http-saved credential on http', () => {
    // Refusing would be refusing the only thing that site supports; the saved
    // credential never carried an https promise in the first place.
    expect(matchOrigin('http://intranet.example.com/', 'http://intranet.example.com/')).toEqual({
      kind: 'match',
      domain: 'example.com',
    });
    // ...and an http-saved credential on https is an UPGRADE, so it matches.
    expect(matchOrigin('http://www.example.com/', 'https://www.example.com/').kind).toBe('match');
  });

  it('REFUSES a confusable rather than warning about it', () => {
    const verdict = matchOrigin(saved, 'https://exarnple.com/');
    expect(verdict).toEqual({
      kind: 'confusable',
      savedDomain: 'example.com',
      pageDomain: 'exarnple.com',
    });
    expect(isFillable(verdict)).toBe(false);
  });

  it.each([
    ['https://paypa1.com/', 'https://paypal.com/'], // digit for letter
    ['https://examples.com/', 'https://example.com/'], // one inserted character
    ['https://exampl.com/', 'https://example.com/'], // one dropped character
    ['https://exarnple.com/', 'https://example.com/'], // rn/m — TWO edits
    ['https://vvells.com/', 'https://wells.com/'], // vv/w — two edits
    ['https://clover.com/', 'https://dover.com/'], // cl/d — two edits
  ])('flags %s against %s as confusable', (page, savedUrl) => {
    expect(matchOrigin(savedUrl, page).kind).toBe('confusable');
  });

  /**
   * PUNYCODE IS REFUSED FOR FILLING AND NO LONGER CLAIMED AS CONFUSABLE.
   *
   * The old rule flagged ANY punycode on either side, which is not a comparison
   * — it ignored the other domain — so the M16 review measured it returning the
   * whole vault to the popup on one visit to any internationalised page, since
   * `matchesFor` keeps confusable verdicts and drops only `no-match`. The
   * boundary is unaffected: filling needs the registrable domains to be EQUAL,
   * which these are not. What changed is the label on the refusal.
   */
  it('REFUSES punycode that is not the saved domain — as no-match, not as a claim', () => {
    const verdict = matchOrigin(saved, 'https://xn--exmple-cua.com/');
    expect(verdict.kind).toBe('no-match');
    expect(isFillable(verdict)).toBe(false);
  });

  it('does NOT surface unrelated items just because the PAGE is internationalised', () => {
    // The disclosure itself, at the layer that decides it. Five saved domains
    // with nothing to do with the page; before the fix all five came back.
    const vault = [
      'https://bank.com/',
      'https://betterhelp.com/',
      'https://match.com/',
      'https://aa-meetings.org/',
      'https://example.co.uk/',
    ];
    const surfaced = vault
      .map((savedUrl) => matchOrigin(savedUrl, 'https://xn--80ak6aa92e.com/'))
      .filter((v) => v.kind !== 'no-match' && v.kind !== 'unusable');
    expect(surfaced).toEqual([]);
  });

  it('hasPunycode still answers the question, as a fact about ONE host', () => {
    // Kept and exported, because the popup says it once about the page. The
    // defect was using it as a verdict about a pair.
    expect(hasPunycode('xn--80ak6aa92e.com')).toBe(true);
    expect(hasPunycode('example.com')).toBe(false);
  });

  it('still matches a punycode domain against ITSELF', () => {
    const idn = 'https://xn--exmple-cua.com/';
    expect(matchOrigin(idn, idn).kind).toBe('match');
  });

  it.each([
    [undefined, 'https://example.com/', 'the item has no url'],
    ['', 'https://example.com/', 'the item has an empty url'],
    ['not a url', 'https://example.com/', 'the item url will not parse'],
    ['https://example.com/', 'not a url', 'the page url will not parse'],
    ['https://example.com/', 'https://localhost/', 'the page has no registrable domain'],
    ['https://example.com/', 'https://192.168.1.1/', 'the page is an IP'],
  ])('is unusable when %s / %s (%s)', (savedUrl, page, _why) => {
    expect(matchOrigin(savedUrl, page)).toEqual({ kind: 'unusable' });
  });

  it('a doubled trailing dot does NOT collapse two registrants onto a bare suffix', () => {
    // `normaliseHost` stripped one dot and `publicSuffix` normalised again, so
    // the two ran on different strings and the empty-label guard never fired:
    // `bank.com..` and `evil.com..` both resolved to `com.` and compared EQUAL.
    // `URL.hostname` preserves the doubled dot, so this is a reachable input.
    expect(registrableDomain('bank.com..')).toBe('bank.com');
    expect(registrableDomain('evil.com..')).toBe('evil.com');
    expect(registrableDomain('a.co.uk..')).toBe('a.co.uk');
    expect(matchOrigin('https://bank.com../', 'https://evil.com../').kind).toBe('no-match');
    // And normalisation agrees with itself, which is what went wrong.
    expect(normaliseHost(normaliseHost('bank.com..'))).toBe(normaliseHost('bank.com..'));
  });

  it('never returns match for anything but a match', () => {
    // The one verdict PR3b will act on, asserted as the only one.
    for (const kind of ['no-match', 'scheme-downgrade', 'confusable', 'unusable'] as const) {
      expect(isFillable({ kind } as never)).toBe(false);
    }
    expect(isFillable({ kind: 'match', domain: 'example.com' })).toBe(true);
  });
});

describe('withinOneEdit', () => {
  it.each([
    ['example.com', 'exampl.com'],
    ['example.com', 'examplee.com'],
    ['paypal.com', 'paypa1.com'],
  ])('%s ~ %s', (a, b) => {
    expect(withinOneEdit(a, b)).toBe(true);
  });

  it.each([
    ['example.com', 'example.com'], // identical is not confusable
    ['example.com', 'exarnple.com'], // two edits (r+n for m)
    ['example.com', 'totallyother.com'],
    ['a.com', 'bbbb.com'],
  ])('%s is NOT within one edit of %s', (a, b) => {
    expect(withinOneEdit(a, b)).toBe(false);
  });
});
