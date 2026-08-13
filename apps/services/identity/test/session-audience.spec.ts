/**
 * WHICH OF IDENTITY'S ROUTES ADMIT A VAULT SESSION — enforced (M15).
 *
 * `session-audience.decorator.ts` states the answer as data. This is what makes
 * the statement load-bearing: it reads the decorated metadata off the real
 * controller class and requires it to match `VAULT_AUDIENCE_ROUTES` exactly, in
 * BOTH directions. A new `@AllowSessionAudiences('vault')` on a fourth route
 * fails here until someone adds it to the list and explains why, and deleting
 * the decorator from a route the list still names fails too.
 *
 * The direction that matters is the second one. Identity owns the routes that
 * mint authority, and the one that must never widen is `handoff` itself: a
 * vault session able to mint another handoff would make the audience a speed
 * bump rather than a boundary.
 */
import { AuthController } from '../src/auth.controller';
import {
  IDENTITY_AUDIENCE_ROUTES,
  SESSION_AUDIENCE_METADATA,
} from '../src/session-audience.decorator';

/** Every method name on the controller prototype, minus the constructor. */
function routeNames(): string[] {
  return Object.getOwnPropertyNames(AuthController.prototype)
    .filter((name) => name !== 'constructor')
    .sort();
}

function admittedAudiences(route: string): readonly string[] | undefined {
  const handler = (AuthController.prototype as unknown as Record<string, object | undefined>)[
    route
  ];
  // `noUncheckedIndexedAccess` makes the lookup possibly-undefined, and that is
  // worth honouring rather than asserting away: a route name that does not
  // exist must not read as "declares no audiences", which is the same answer a
  // real undecorated handler gives. The callers below check existence
  // separately, so this only has to not lie.
  if (handler === undefined) {
    return undefined;
  }
  return Reflect.getMetadata(SESSION_AUDIENCE_METADATA, handler) as readonly string[] | undefined;
}

describe('identity route audiences match the declaration', () => {
  it('finds the routes it is meant to be checking', () => {
    // Never let the scan pass vacuously (the credential-graph anti-drop lesson).
    const routes = routeNames();
    expect(routes.length).toBeGreaterThan(10);
    expect(routes).toContain('session');
    expect(routes).toContain('mintHandoff');
  });

  it('every declared route exists and admits EXACTLY the declared audiences', () => {
    /*
     * Exactly, not merely "at least" — which is the difference a second
     * audience made. M15's version compared against a flat list of route NAMES,
     * so it could see that a route admitted something unusual but not WHICH
     * thing: a handler that quietly gained `extension` when the table granted it
     * only `vault` would have passed.
     *
     * Sorted on both sides so the assertion is about the SET rather than about
     * the order arguments happen to appear in at the decoration site — that
     * order is a style choice, and a fence that fails on it teaches people to
     * stop reading it.
     */
    for (const [route, audiences] of IDENTITY_AUDIENCE_ROUTES) {
      expect(routeNames()).toContain(route);
      expect([...(admittedAudiences(route) ?? [])].sort()).toEqual(
        ['account', ...audiences].sort(),
      );
    }
  });

  it('NO UNDECLARED ROUTE admits a non-account audience', () => {
    for (const route of routeNames()) {
      if (IDENTITY_AUDIENCE_ROUTES.has(route)) continue;
      expect({ route, admits: admittedAudiences(route) }).toEqual({
        route,
        admits: undefined,
      });
    }
  });

  it('MINTING A HANDOFF is account-only, so NO non-account session can chain one', () => {
    // Stated by name as well as covered by the sweep above: this single fact is
    // what stops the audience from being a speed bump, and a regression in it
    // should fail a test that says so. With two non-account audiences it also
    // stops one from being reachable from the other.
    expect(IDENTITY_AUDIENCE_ROUTES.has('mintHandoff')).toBe(false);
    expect(admittedAudiences('mintHandoff')).toBeUndefined();
  });

  it('MINTING AN EXTENSION PAIRING is account-only, like minting a handoff', () => {
    // The same fact as `mintHandoff` above and for a stronger reason: this
    // ceremony produces a session with a REAL refresh token, so a non-account
    // session able to mint one could chain a short-lived credential into a
    // long-lived one. Named rather than left to the sweep, because that is the
    // sentence docs/03 §6j makes a claim about.
    expect(routeNames()).toContain('mintExtensionPairing');
    expect(IDENTITY_AUDIENCE_ROUTES.has('mintExtensionPairing')).toBe(false);
    expect(admittedAudiences('mintExtensionPairing')).toBeUndefined();
    // And redemption is unauthenticated, so it carries no audience decision at
    // all — there is no session to have one.
    expect(admittedAudiences('redeemExtensionPairing')).toBeUndefined();
  });

  it('CHANGING THE PASSWORD is account-only — a derived credential cannot rewrite its root', () => {
    // Named rather than left to the sweep, for the same reason minting is. A
    // vault session and an extension session are narrow, derived credentials
    // whose whole safety argument is that they reach a fixed small set of
    // routes; letting either replace the account password would let a leaked
    // one chain itself into permanent, unrecoverable control of the account —
    // strictly worse than anything else on their reachable surface, because it
    // survives revoking the credential that did it.
    expect(routeNames()).toContain('changePassword');
    expect(IDENTITY_AUDIENCE_ROUTES.has('changePassword')).toBe(false);
    expect(admittedAudiences('changePassword')).toBeUndefined();
  });

  it('the extension reaches introspection, step-up and logout — and only those', () => {
    // Named rather than derived, because "which of identity's routes does the
    // browser extension reach" is a sentence docs/03 §6j makes a claim about,
    // and a claim in prose should have a test that fails when it stops being
    // true. Step-up is the load-bearing one: both vault SRP legs are step-up
    // gated, so without it the extension could never open a vault at all.
    const reaches = [...IDENTITY_AUDIENCE_ROUTES.entries()]
      .filter(([, audiences]) => audiences.includes('extension'))
      .map(([route]) => route)
      .sort();
    expect(reaches).toEqual(['logout', 'session', 'stepUp']);
  });
});
