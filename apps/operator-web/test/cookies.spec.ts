/**
 * The cookie layer, which is where this origin's isolation actually lives.
 *
 * Two things are worth asserting rather than reading. The `__Host-` ATTRIBUTES
 * are the control — the browser refuses the cookie without `Secure` and
 * `Path=/`, and refuses it WITH a `Domain`, which is what makes host-only a
 * property the browser enforces instead of a convention someone has to keep.
 * And the PARSER is hand-rolled, on the path that decides which credential a
 * request travels on, so its edges get cases rather than a reading.
 */
import { ServerResponse } from 'node:http';
import { IncomingMessage } from 'node:http';
import { Socket } from 'node:net';
import {
  CSRF_HEADER,
  OPERATOR_SESSION_COOKIE,
  clearSessionCookie,
  parseCookies,
  sessionTokenFrom,
  setSessionCookie,
} from '../src/cookies';

function response(): ServerResponse {
  return new ServerResponse(new IncomingMessage(new Socket()));
}

describe('the operator session cookie', () => {
  it('carries the __Host- prefix and every attribute that prefix requires', () => {
    const res = response();
    setSessionCookie(res, 'tok en/+=');
    const header = String(res.getHeader('Set-Cookie'));

    expect(header.startsWith('__Host-')).toBe(true);
    expect(header).toContain('Path=/');
    expect(header).toContain('Secure');
    expect(header).toContain('HttpOnly');
    // Lax, NOT Strict: the operator ARRIVES by a cross-site top-level POST, and
    // a Strict cookie would not be sent on the navigation that follows — they
    // would land signed out on the origin they were just handed to.
    expect(header).toContain('SameSite=Lax');
    // The prefix is void if a Domain is present, so this one is the control.
    expect(header).not.toContain('Domain=');
    // Values are encoded, so a token containing `;` or `=` cannot forge an
    // attribute.
    expect(header).toContain(encodeURIComponent('tok en/+='));
  });

  it('clears with the SAME attributes it set, or some browsers keep the cookie', () => {
    // A clear whose attributes differ silently fails to remove it, leaving a
    // "signed out" screen over a live session — the M8 PR5 logout lesson.
    const set = response();
    setSessionCookie(set, 't');
    const cleared = response();
    clearSessionCookie(cleared);

    const attributesOf = (header: string): string =>
      header.slice(header.indexOf(';') + 1).replace('; Max-Age=0', '');
    expect(attributesOf(String(cleared.getHeader('Set-Cookie')))).toBe(
      attributesOf(String(set.getHeader('Set-Cookie'))),
    );
    expect(String(cleared.getHeader('Set-Cookie'))).toContain('Max-Age=0');
  });

  it('is named for THIS origin, and the CSRF header is too', () => {
    // The isolation is the prefix; the names are the label — two rows in a
    // cookie jar that say which origin each belongs to, at the moment somebody
    // is debugging a cross-origin session problem.
    expect(OPERATOR_SESSION_COOKIE).toBe('__Host-estate_operator');
    expect(CSRF_HEADER).toBe('x-estate-operator-csrf');
  });
});

describe('the cookie parser', () => {
  it.each([
    ['a single pair', 'k=v', { k: 'v' }],
    ['whitespace around pairs', ' a=1 ;  b=2 ', { a: '1', b: '2' }],
    ['a quoted value', 'a="q"', { a: 'q' }],
    ['a percent-encoded value', 'a=one%20two', { a: 'one two' }],
    // FIRST OCCURRENCE WINS, deliberately: a second cookie of the same name is
    // how a subdomain tries to shadow one, and the `__Host-` prefix already
    // makes that impossible for this cookie — but the parser must not be the
    // thing that changes its mind.
    ['a duplicate name', 'a=first; a=second', { a: 'first' }],
    ['a pair with no equals', 'novalue; a=1', { a: '1' }],
    ['an empty name', '=orphan; a=1', { a: '1' }],
    // A value that is not valid percent-encoding is kept verbatim rather than
    // throwing: a malformed cookie must fail to authenticate, never to parse.
    ['a malformed escape', 'a=%E0%A4%A', { a: '%E0%A4%A' }],
  ])('handles %s', (_label, header, expected) => {
    expect(Object.fromEntries(parseCookies(header))).toEqual(expected);
  });

  it('reads no credential from an absent or unrelated cookie header', () => {
    expect(sessionTokenFrom(undefined)).toBeNull();
    expect(sessionTokenFrom('')).toBeNull();
    // The app origin's own cookies buy nothing here, which was MEASURED in a
    // browser before it was relied on (M15 PR1): cookie scope ignores the port,
    // so a port-only split would have handed this origin the app's session.
    expect(sessionTokenFrom('estate_access=a; estate_refresh=b')).toBeNull();
    // And neither does the vault origin's.
    expect(sessionTokenFrom('__Host-estate_vault=v')).toBeNull();
  });

  it('reads the credential when it is there', () => {
    expect(sessionTokenFrom(`${OPERATOR_SESSION_COOKIE}=abc`)).toBe('abc');
  });
});
