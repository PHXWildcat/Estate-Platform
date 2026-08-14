/**
 * WHICH ASSET ROUTES REQUIRE A FRESH SECOND FACTOR — enforced (M19 PR4).
 *
 * ═══ WHY THIS FILE EXISTS ═══
 *
 * `POST /v1/assets/:assetId/retire` shipped from M3 to M19 with class-level
 * `CallerGuard` and nothing else, while `POST /v1/assets/:assetId/beneficiaries`
 * — a REVERSIBLE change to the same asset — carried `StepUpGuard`. Proven live
 * on one non-elevated session: designate answered 403 `stepup_required`, retire
 * answered 200 and really retired the asset. The weaker gate sat on the stronger
 * action, which is the M6 asymmetry backwards.
 *
 * It survived three milestones of review because the only statement of the rule
 * was PROSE — `beneficiaries.controller.ts`'s docstring says its own mutations
 * are gated, and no file anywhere said what the OTHER controller owed. A rule
 * that lives in the docstring of the routes that already obey it cannot fail.
 *
 * ═══ IT DISCOVERS ROUTES, IT DOES NOT LIST THEM ═══
 *
 * The route set comes from Nest's OWN metadata on the real controller
 * prototypes, and so does each route's guard set — which is what the framework
 * resolves at request time. Both halves matter and neither is a source scan:
 *
 *   · a hand-kept list of routes makes a NEW command invisible, which is the
 *     failure being closed here (retire was in nobody's list);
 *   · and a scan for the literal `@UseGuards(StepUpGuard)` is defeated by an
 *     aliased import or a guard applied through `SetMetadata`, the 2026-08-07
 *     and 2026-08-12 lesson — anchor on what the RUNTIME reads.
 *
 * So a route added to either controller arrives with a gate DECISION or this
 * file goes red. There is no default.
 *
 * ═══ SCOPE, STATED ═══
 *
 * This proves which gate DECORATES each route, never whether the gate's own
 * policy is right (`@estate/auth-guard`'s suites own that), and it says nothing
 * about authorization — Cedar's deny-by-default and the uniform 404 are
 * `authz.spec.ts` and the integration suites. A GET is not gated here by design:
 * step-up guards ACTIONS, and reads are bounded by the decrypt budget instead
 * (M18 TB4), which is a different control with a different file.
 */
import 'reflect-metadata';
import { AssetsController } from '../src/assets.controller';
import { BeneficiariesController } from '../src/beneficiaries.controller';

const CONTROLLERS = [AssetsController, BeneficiariesController];

/** Nest's own metadata keys. Imported as literals rather than from
 * `@nestjs/common/constants` (a deep path with no stability promise); the
 * discovery assertion below fails loudly if either ever stops resolving. */
const PATH_METADATA = 'path';
const METHOD_METADATA = 'method';
const GUARDS_METADATA = '__guards__';

/** `RequestMethod` as the decorators store it. */
const METHOD_NAMES: Record<number, string> = {
  0: 'GET',
  1: 'POST',
  2: 'PUT',
  3: 'DELETE',
  4: 'PATCH',
};

type Route = {
  key: string;
  handlerName: string;
  method: string;
  guards: string[];
  mutating: boolean;
};

function guardNames(target: object): string[] {
  const guards = Reflect.getMetadata(GUARDS_METADATA, target) as unknown[] | undefined;
  return (guards ?? []).map((g) =>
    typeof g === 'function'
      ? g.name
      : ((g as { constructor?: { name?: string } })?.constructor?.name ?? String(g)),
  );
}

/** Every decorated route on both controllers, with the guards Nest would
 * actually apply: the class's, then the handler's. */
function discoverRoutes(): Route[] {
  const routes: Route[] = [];
  for (const controller of CONTROLLERS) {
    const classGuards = guardNames(controller);
    for (const handlerName of Object.getOwnPropertyNames(controller.prototype)) {
      if (handlerName === 'constructor') continue;
      const handler = (controller.prototype as unknown as Record<string, object | undefined>)[
        handlerName
      ];
      if (handler === undefined) continue;
      const verb = Reflect.getMetadata(METHOD_METADATA, handler) as number | undefined;
      const path = Reflect.getMetadata(PATH_METADATA, handler) as string | undefined;
      if (verb === undefined || path === undefined) continue;
      const method = METHOD_NAMES[verb] ?? `METHOD_${verb}`;
      routes.push({
        key: `${method} /v1/${path}`,
        handlerName,
        method,
        guards: [...classGuards, ...guardNames(handler)],
        mutating: method !== 'GET',
      });
    }
  }
  return routes.sort((a, b) => a.key.localeCompare(b.key));
}

/**
 * THE DECLARATION. `stepup` means a fresh second factor; `caller` means a
 * verified session is the whole gate, and every one of those carries the reason
 * it is allowed to.
 *
 * The line, taken from docs/01 §5: step-up covers deletion-class and
 * beneficiary changes. Everything else here APPENDS a correction that a later
 * command can correct again, so gating it would make ordinary bookkeeping cost
 * an authenticator without protecting anything — and the M6 rule cuts both
 * ways: a gate on every keystroke is how people learn to keep a code to hand.
 */
const ROUTE_GATES: Record<string, { gate: 'caller' | 'stepup'; because: string }> = {
  'GET /v1/assets': { gate: 'caller', because: 'a read' },
  'GET /v1/assets/:assetId': { gate: 'caller', because: 'a read' },
  'GET /v1/assets/:assetId/beneficiaries': { gate: 'caller', because: 'a read' },
  'GET /v1/assets/:assetId/events': { gate: 'caller', because: 'a read' },
  'GET /v1/estates/:ownerUserId/assets': {
    gate: 'caller',
    because:
      'a read, and the executor path — gated by settlement’s staged ladder on the caller’s own bearer, not by a factor the executor may not hold',
  },
  'GET /v1/net-worth': { gate: 'caller', because: 'a read' },

  'POST /v1/assets': {
    gate: 'caller',
    because: 'adding a record takes nothing away; the M4 upload precedent',
  },
  'PATCH /v1/assets/:assetId': {
    gate: 'caller',
    because: 'a correction the next correction can undo — the ledger keeps both',
  },
  'POST /v1/assets/:assetId/valuations': {
    gate: 'caller',
    because: 'an append; a wrong number is fixed by appending the right one',
  },
  'POST /v1/assets/:assetId/ownership': {
    gate: 'caller',
    because: 'an append; ownership can be restated',
  },

  'POST /v1/assets/:assetId/retire': {
    gate: 'stepup',
    because:
      'THE deletion-class action of this service (docs/01 §5) and the only irreversible one: no un-retire exists in the ledger or the API',
  },
  'POST /v1/assets/:assetId/beneficiaries': {
    gate: 'stepup',
    because: 'docs/01 §5 names beneficiary changes',
  },
  'DELETE /v1/assets/:assetId/beneficiaries/:contactId': {
    gate: 'stepup',
    because:
      'the same change in the other direction — M6 forbids the protective action being HARDER, not equal',
  },
};

describe('asset route gates', () => {
  const routes = discoverRoutes();

  it('discovers the real decorated routes (anti-vacuity)', () => {
    // Without this, a metadata key Nest stopped using would empty the sweep and
    // every assertion below would pass over nothing.
    expect(routes.length).toBeGreaterThanOrEqual(13);
    expect(routes.filter((r) => r.mutating).length).toBeGreaterThanOrEqual(7);
    expect(routes.map((r) => r.key)).toContain('POST /v1/assets/:assetId/retire');
    for (const route of routes) {
      expect(route.guards).toContain('CallerGuard');
    }
  });

  it('every route carries a gate decision, and every decision names a route', () => {
    expect(routes.map((r) => r.key).sort()).toEqual(Object.keys(ROUTE_GATES).sort());
  });

  it.each(Object.entries(ROUTE_GATES))(
    'the decorators on %s match its declared gate',
    (key, { gate }) => {
      const route = routes.find((r) => r.key === key);
      expect(route).toBeDefined();
      expect(route?.guards.includes('StepUpGuard')).toBe(gate === 'stepup');
    },
  );

  /**
   * Named on its own, the `mintHandoff` precedent: a diff of the table above
   * shows a value changing, while this says what was lost.
   */
  it('RETIRING AN ASSET REQUIRES A FRESH SECOND FACTOR', () => {
    const retire = routes.find((r) => r.key === 'POST /v1/assets/:assetId/retire');
    expect(retire?.guards).toContain('StepUpGuard');
  });

  it('no GET is step-up gated (step-up guards actions; reads are budget-bounded)', () => {
    for (const route of routes.filter((r) => !r.mutating)) {
      expect(route.guards).not.toContain('StepUpGuard');
    }
  });
});
