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
  SESSION_AUDIENCE_METADATA,
  VAULT_AUDIENCE_ROUTES,
} from '../src/session-audience.decorator';

/** Every method name on the controller prototype, minus the constructor. */
function routeNames(): string[] {
  return Object.getOwnPropertyNames(AuthController.prototype)
    .filter((name) => name !== 'constructor')
    .sort();
}

function admittedAudiences(route: string): readonly string[] | undefined {
  const handler = (AuthController.prototype as unknown as Record<string, object>)[route];
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

  it('every declared route exists and admits vault', () => {
    for (const route of VAULT_AUDIENCE_ROUTES) {
      expect(routeNames()).toContain(route);
      expect(admittedAudiences(route)).toEqual(['account', 'vault']);
    }
  });

  it('NO UNDECLARED ROUTE admits a non-account audience', () => {
    const declared = new Set<string>(VAULT_AUDIENCE_ROUTES);
    for (const route of routeNames()) {
      if (declared.has(route)) continue;
      expect({ route, admits: admittedAudiences(route) }).toEqual({
        route,
        admits: undefined,
      });
    }
  });

  it('MINTING A HANDOFF is account-only, so a vault session cannot chain one', () => {
    // Stated by name as well as covered by the sweep above: this single fact is
    // what stops the audience from being a speed bump, and a regression in it
    // should fail a test that says so.
    expect(VAULT_AUDIENCE_ROUTES).not.toContain('mintHandoff');
    expect(admittedAudiences('mintHandoff')).toBeUndefined();
  });
});
