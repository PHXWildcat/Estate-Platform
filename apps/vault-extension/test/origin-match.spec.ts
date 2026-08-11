/**
 * THE MATCHER IS THE CONTROL, so it gets a table rather than a few examples.
 *
 * docs/03 §4 TB9: *a filled credential belongs to the page that received it*.
 * Every case below is either a way that goes wrong in the wild or a rule the
 * threat model commits to in writing. The two traps at the top are the ones a
 * naive `includes()` passes and a naive "last two labels" passes — both named
 * in §4 TB9, both exploitable rather than sloppy.
 */
import { matchOrigin, frameIsAllowed, isFillable, withinOneEdit } from '../src/origin-match';
import { publicSuffix, registrableDomain } from '../src/registrable-domain';

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

  it('treats punycode that is not the saved domain as confusable', () => {
    // A homograph of example.com. Refused whether or not it is within one edit
    // of the ASCII form, because an IDN that is not the saved domain has no
    // business being offered the saved domain's credential.
    expect(matchOrigin(saved, 'https://xn--exmple-cua.com/').kind).toBe('confusable');
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

describe('cross-origin frames are refused by default', () => {
  const top = 'https://example.com/';

  it('allows the top frame', () => {
    expect(frameIsAllowed({ isTopFrame: true, topUrl: top, frameUrl: top })).toBe(true);
  });

  it('allows a same-site subframe', () => {
    expect(
      frameIsAllowed({ isTopFrame: false, topUrl: top, frameUrl: 'https://pay.example.com/' }),
    ).toBe(true);
  });

  it('refuses a cross-origin subframe', () => {
    expect(frameIsAllowed({ isTopFrame: false, topUrl: top, frameUrl: 'https://evil.net/' })).toBe(
      false,
    );
  });

  it('refuses a same-domain subframe on a different scheme', () => {
    expect(
      frameIsAllowed({ isTopFrame: false, topUrl: top, frameUrl: 'http://example.com/' }),
    ).toBe(false);
  });

  it('honours a per-item opt-in', () => {
    expect(
      frameIsAllowed({
        isTopFrame: false,
        topUrl: top,
        frameUrl: 'https://evil.net/',
        optedIn: true,
      }),
    ).toBe(true);
  });

  it('refuses when either URL will not parse', () => {
    expect(frameIsAllowed({ isTopFrame: false, topUrl: 'nope', frameUrl: top })).toBe(false);
    expect(frameIsAllowed({ isTopFrame: false, topUrl: top, frameUrl: 'nope' })).toBe(false);
  });
});
