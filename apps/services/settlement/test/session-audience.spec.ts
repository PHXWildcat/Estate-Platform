/**
 * WHICH SETTLEMENT ROUTES THE OPERATOR CONSOLE MAY REACH — enforced (M21 PR3b).
 *
 * `AUDIENCE_ROUTE_ADMITTERS` in @estate/auth-guard is the declaration, and that
 * package's own fence already checks this service's decorators against it in
 * both directions. This suite is the other half, and it earns its place three
 * times over:
 *
 *   · it reads the DECORATED METADATA off the real controller prototypes,
 *     which is what Nest resolves at request time — a source scan can be
 *     defeated by a decorator applied any way a regex does not recognise;
 *   · it NAMES the routes that must never admit an operator session, one at a
 *     time, because a test that fails saying `void` should not admit one tells
 *     the next person WHY, which a diff of a data table does not;
 *   · and it DRIVES A REAL `CallerGuard`, which neither of the others can.
 *     The guard takes `@Optional() reflector`, and `audiencesFor` falls back to
 *     the service-wide list when it is absent — so a perfectly decorated route
 *     on a container where `Reflector` does not resolve is SILENTLY INERT: a
 *     401 with no error, no log and nothing red anywhere. The failure
 *     direction is safe; the silence is the problem, and no spec in this
 *     service constructed a guard before this one.
 *
 * WHAT AN OPERATOR SESSION IS. Minted by the M21 PR3a ceremony on the app
 * origin under step-up, redeemed at `operator.<host>`, 15 minutes, no refresh
 * token. So the question here is not "is this operator trusted" — the
 * allowlist answers that, per request, inside the transaction — but "what does
 * a LEAKED console credential reach". The answer has to stay: the two
 * worklists, the reads that open a case, and the review and post-verification
 * verbs. Never the decedent's own kill switch, never the owner's settings,
 * never the executor's writes.
 */
import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ExecutionContext, RequestMethod } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { Reflector } from '@nestjs/core';
import {
  CallerGuard,
  SESSION_AUDIENCE_METADATA,
  type SessionContext,
  type SessionVerifier,
} from '@estate/auth-guard';
import { SettlementAdminController, SettlementVaultGateController } from '../src/admin.controller';
import { OperatorController } from '../src/operator.controller';
import { SettlementController } from '../src/settlement.controller';

type Ctor = { prototype: object };

const CONTROLLERS: ReadonlyArray<{ name: string; ctor: Ctor }> = [
  { name: 'OperatorController', ctor: OperatorController },
  { name: 'SettlementController', ctor: SettlementController },
  { name: 'SettlementAdminController', ctor: SettlementAdminController },
  // The Zone A gate. ServiceCredentialGuard-ed rather than CallerGuard-ed, so
  // it carries no audience at all — included so the sweep below covers the
  // WHOLE service rather than the user-authenticated part of it.
  { name: 'SettlementVaultGateController', ctor: SettlementVaultGateController },
];

function routeNames(controller: Ctor): string[] {
  return Object.getOwnPropertyNames(controller.prototype)
    .filter((name) => name !== 'constructor')
    .sort();
}

function admittedAudiences(controller: Ctor, route: string): readonly string[] | undefined {
  const handler = (controller.prototype as unknown as Record<string, object | undefined>)[route];
  // A name that does not exist must not read as "declares no audiences" — the
  // same answer a genuinely undecorated handler gives.
  if (handler === undefined) return undefined;
  return Reflect.getMetadata(SESSION_AUDIENCE_METADATA, handler) as readonly string[] | undefined;
}

function admits(controller: Ctor, route: string): boolean {
  return (admittedAudiences(controller, route) ?? []).includes('operator');
}

/** `GET /v1/settlement/cases/:caseId/timeline`, from the same metadata Nest routes on. */
function routeSignature(controller: Ctor, route: string): string {
  const handler = (controller.prototype as unknown as Record<string, object>)[route] as object;
  const prefix = Reflect.getMetadata(PATH_METADATA, controller) as string;
  const path = Reflect.getMetadata(PATH_METADATA, handler) as string;
  const method = Reflect.getMetadata(METHOD_METADATA, handler) as RequestMethod;
  const suffix = path === undefined || path === '' || path === '/' ? '' : `/${path}`;
  return `${RequestMethod[method]} /${prefix}${suffix}`;
}

/** The console's whole reach at this service. */
const OPERATOR_ROUTES: ReadonlyArray<{ controller: Ctor; route: string }> = [
  { controller: OperatorController, route: 'queue' },
  { controller: OperatorController, route: 'administrable' },
  { controller: OperatorController, route: 'startReview' },
  { controller: OperatorController, route: 'decideReview' },
  { controller: OperatorController, route: 'verify' },
  { controller: SettlementController, route: 'getCase' },
  { controller: SettlementAdminController, route: 'timeline' },
  { controller: SettlementAdminController, route: 'listStages' },
  { controller: SettlementAdminController, route: 'listDistributions' },
  { controller: SettlementAdminController, route: 'closeCase' },
  { controller: SettlementAdminController, route: 'decideStage' },
  { controller: SettlementAdminController, route: 'revokeStage' },
  { controller: SettlementAdminController, route: 'approveDistribution' },
  // M23 PR4b: the console needs this one MOST. The operator approving a
  // distribution is the person dual control exists for, and until this route
  // they approved a figure nobody could see.
  { controller: SettlementAdminController, route: 'distributionAmount' },
];

/**
 * Named refusals, with the reason each matters. Not the complete refused set —
 * that is derived below — but the subset where a mistaken grant is worst.
 */
const MUST_REFUSE: ReadonlyArray<{ controller: Ctor; route: string; why: string }> = [
  {
    controller: SettlementAdminController,
    route: 'executorCases',
    why: "the EXECUTOR's own worklist — an operator asking which estates they personally administer is asking in a private capacity, and `administrable` is the console's listing of the same estates",
  },
  {
    controller: SettlementController,
    route: 'void',
    why: "the DECEDENT's own kill switch — §5.1 control 3, and the step-up on it IS the liveness proof",
  },
  {
    controller: SettlementController,
    route: 'updateSettings',
    why: 'the owner shortening their own waiting period is the window a fraudulent case needs',
  },
  {
    controller: SettlementController,
    route: 'getSettings',
    why: "reads the owner's own configuration; an operator has no business in it",
  },
  {
    controller: SettlementController,
    route: 'report',
    why: 'opening a case is a reporter action; operator intake has its own route and its own step-up',
  },
  {
    controller: SettlementController,
    route: 'listMine',
    why: "the caller's OWN cases — a reporter surface (M22), not console work",
  },
  {
    controller: SettlementController,
    route: 'reportableEstates',
    why: 'enumerates the estates the caller could report a death for',
  },
  {
    controller: SettlementController,
    route: 'addEvidence',
    why: 'attaches evidence to a case; the console reads evidence and does not file it',
  },
  {
    controller: OperatorController,
    route: 'reportProvider',
    why: 'operator INTAKE — operator-only, but the console files no signals, and a capability with no caller is what the audience table exists to prevent',
  },
  {
    controller: OperatorController,
    route: 'evidenceRead',
    why: "answers documents' authority question on the operator's own forwarded bearer",
  },
  {
    controller: SettlementAdminController,
    route: 'requestStage',
    why: 'executor-only: it refuses an operator outright (M23)',
  },
  {
    controller: SettlementAdminController,
    route: 'recordDistribution',
    why: 'executor-only, and the one settlement write that encrypts an amount',
  },
  {
    controller: SettlementAdminController,
    route: 'completeTask',
    why: "executor-only: ticks the estate's own checklist (M23)",
  },
  {
    controller: SettlementAdminController,
    route: 'listTasks',
    why: "the executor's checklist — M23, and the reason `tasks` is not on the console",
  },
  {
    controller: SettlementAdminController,
    route: 'setDistributionStatus',
    why: 'post-approval movement of money; operator-or-executor, and M23 owns the surface',
  },
  {
    controller: SettlementAdminController,
    route: 'stageAccess',
    why: "asked by ASSETS on the executor's forwarded bearer, not by a console",
  },
  {
    controller: SettlementVaultGateController,
    route: 'vaultRelease',
    why: 'the docs/03 §6a Zone A gate — service-credential authenticated, never a user session of any audience',
  },
];

describe('settlement route audiences match the declaration', () => {
  it('finds the routes it is meant to be checking', () => {
    // Anti-vacuity. A prototype scan that returned nothing would make every
    // assertion below pass — the credential-graph anti-drop lesson.
    const counts = CONTROLLERS.map((c) => routeNames(c.ctor).length);
    expect(counts.every((n) => n > 0)).toBe(true);
    // 31 across four controllers (M23 PR4b added the amount read). Asserted so
    // the next person MEASURES rather than remembering: the decision log
    // carried a wrong route count for settlement for four milestones
    // (M21 PR2.5). An EXACT number and not a floor — this one is meant to
    // break when a route arrives, because that is when someone has to decide
    // its audience and its guard.
    expect(counts.reduce((a, b) => a + b, 0)).toBe(31);
  });

  it('exactly the console routes admit an operator session', () => {
    const admitting = CONTROLLERS.flatMap(({ ctor }) =>
      routeNames(ctor)
        .filter((route) => admits(ctor, route))
        .map((route) => route),
    ).sort();
    expect(admitting).toEqual([...OPERATOR_ROUTES.map((r) => r.route)].sort());
  });

  it.each(MUST_REFUSE)(
    '$route must never admit an operator session — $why',
    ({ controller, route }) => {
      expect(routeNames(controller)).toContain(route);
      expect(admits(controller, route)).toBe(false);
    },
  );

  it('every route that is not a console route refuses the operator audience', () => {
    // The derived half, so the named list above cannot go stale into a false
    // sense of coverage: a 31st route added tomorrow is refused by default and
    // this notices if it is not. SEVENTEEN refused — a number that lives here,
    // where it is measured, and deliberately not in prose beside it.
    const allowed = new Set(OPERATOR_ROUTES.map((r) => r.route));
    const refused = CONTROLLERS.flatMap(({ ctor }) =>
      routeNames(ctor).filter((route) => !allowed.has(route)),
    );
    expect(refused).toHaveLength(17);
    for (const { ctor } of CONTROLLERS) {
      for (const route of routeNames(ctor)) {
        if (allowed.has(route)) continue;
        expect({ route, admits: admits(ctor, route) }).toEqual({ route, admits: false });
      }
    }
  });

  /**
   * WHICH CONSOLE ROUTES NEED A FRESH FACTOR, declared with the reason and
   * checked against the real `@UseGuards(StepUpGuard)` decorators.
   *
   * The console's step-up ceremony is written against this split, and the
   * number had ALREADY rotted before this was added: `step-up.ts` said eight
   * of thirteen where six carry the guard, having counted on-screen BUTTONS
   * (approve and reject are two of them over one route). A number in prose
   * beside a mechanism that derives one is a second copy free to drift, so it
   * lives here now and the client's comment points at it.
   *
   * `startReview` is the one console verb with no guard, and that is a
   * decision rather than an omission: claiming a case commits to nothing, is
   * undone by rejecting, and the DECISION that follows is gated — so gating
   * the claim would put a factor in front of picking up work, which is the M6
   * rule that the protective action must never be harder than the permissive
   * one. Every route that CHANGES the §5.1 chain's outcome is gated.
   */
  describe('the console verbs that need a fresh factor', () => {
    const UNGATED: Readonly<Record<string, string>> = {
      queue: 'a read',
      administrable: 'a read',
      getCase: 'a read',
      timeline: 'a read',
      listStages: 'a read',
      listDistributions: 'a read',
      distributionAmount:
        'a read, and gating it would put a factor in front of the LAST step of a disclosure ' +
        'whose earlier steps are free — `listDistributions` already says the amount exists. ' +
        'It would also make the operator checking what they approve work harder than the ' +
        'operator approving blind. See this block.',
      startReview:
        'claiming a case commits to nothing and the decision after it is gated — see this block',
    };

    /**
     * ON THE HANDLER FUNCTION, not on `(prototype, key)`. Nest's method-level
     * `@UseGuards` writes to the descriptor's value, which is what
     * `getAllAndOverride([handler, class])` reads at request time — the same
     * place `admittedAudiences` above looks, and the reason this reads the
     * runtime metadata rather than scanning for the decorator's text.
     */
    function stepUpGuarded(controller: Ctor, route: string): boolean {
      const handler = (controller.prototype as unknown as Record<string, object | undefined>)[
        route
      ];
      if (handler === undefined) return false;
      const guards: unknown = Reflect.getMetadata('__guards__', handler);
      return (
        Array.isArray(guards) &&
        guards.some(
          (g) => typeof g === 'function' && (g as { name?: string }).name === 'StepUpGuard',
        )
      );
    }

    it('every console route is either step-up gated or declared ungated with a reason', () => {
      const surprises: string[] = [];
      let gated = 0;
      for (const { ctor } of CONTROLLERS) {
        for (const route of routeNames(ctor)) {
          if (!OPERATOR_ROUTES.some((r) => r.route === route)) continue;
          if (stepUpGuarded(ctor, route)) {
            gated += 1;
            // A declared-ungated route that GAINS the guard is fine for
            // safety and still a drift: the declaration would be describing a
            // world that no longer exists.
            if (route in UNGATED) surprises.push(`${route} is gated but declared ungated`);
          } else if (!(route in UNGATED)) {
            surprises.push(`${route} carries no StepUpGuard and no declared reason`);
          }
        }
      }
      expect(surprises).toEqual([]);
      // Anti-vacuity: a metadata key that stops resolving would report zero
      // gated routes and satisfy every assertion above.
      expect(gated).toBeGreaterThan(0);
      expect(gated).toBe(OPERATOR_ROUTES.filter((r) => r.route in UNGATED === false).length);
    });

    /**
     * THE OTHER HALF OF THE SAME CATEGORY (M23 PR3).
     *
     * The block above walks `OPERATOR_ROUTES` and stops. That left the
     * EXECUTOR's routes on this controller — the ones an operator is refused —
     * with no declaration at all: `requestStage` could have lost its guard and
     * nothing here would have said so. A rule applied to one member of a
     * category is a rule half-applied.
     *
     * The set is DERIVED, not listed: every route on the admin controller that
     * the console cannot reach. A route added to that controller therefore
     * arrives here needing a decision, which is the point.
     */
    const UNGATED_EXECUTOR: Readonly<Record<string, string>> = {
      executorCases: 'a read',
      listStages: 'a read',
      listTasks: 'a read',
      stageAccess: "a read, and asked by ASSETS on the executor's forwarded bearer",
      completeTask:
        'ticking a checklist item moves no access and transfers no value, and the UNTICK is the ' +
        'same route — gating it would put a factor in front of correcting a mis-click, which is ' +
        'the protective action here. See this block.',
    };

    it('every EXECUTOR route is gated or declared ungated with a reason', () => {
      const consoleRoutes = new Set(OPERATOR_ROUTES.map((r) => r.route));
      const executorRoutes = routeNames(SettlementAdminController).filter(
        (route) => !consoleRoutes.has(route),
      );
      // Anti-vacuity, at the LEVEL of the scan and not only its total: a
      // prototype walk that started returning nothing would make the loop below
      // pass with an empty body.
      expect(executorRoutes.length).toBeGreaterThanOrEqual(5);
      // ...and the two halves really are disjoint: an overlap would mean this
      // block was silently re-checking the console's routes.
      expect(executorRoutes.filter((route) => consoleRoutes.has(route))).toEqual([]);

      const surprises: string[] = [];
      let gated = 0;
      for (const route of executorRoutes) {
        if (stepUpGuarded(SettlementAdminController, route)) {
          gated += 1;
          if (route in UNGATED_EXECUTOR) surprises.push(`${route} is gated but declared ungated`);
        } else if (!(route in UNGATED_EXECUTOR)) {
          surprises.push(`${route} carries no StepUpGuard and no declared reason`);
        }
      }
      expect(surprises).toEqual([]);
      expect(gated).toBeGreaterThan(0);
    });

    it('the executor verbs that MOVE something are gated, one at a time', () => {
      // Named as well as derived: asking for a rung opens somebody's estate,
      // and both distribution verbs move money. A failure here should say
      // which, not just that a count changed.
      for (const route of ['requestStage', 'recordDistribution', 'setDistributionStatus']) {
        expect(stepUpGuarded(SettlementAdminController, route)).toBe(true);
      }
      // POSITIVE CONTROL, and it is the whole point of the pair: `completeTask`
      // sits on the same controller and is NOT gated. Without this, a
      // `stepUpGuarded` that had started answering `true` for everything would
      // satisfy every assertion above.
      expect(stepUpGuarded(SettlementAdminController, 'completeTask')).toBe(false);
    });

    it('the destructive verbs are gated, one at a time', () => {
      // Named as well as derived, because a failure saying `verify` must need a
      // factor tells the next person WHY — confirming a verification locks an
      // account and revokes every session a living person holds.
      const must = [
        'decideReview',
        'verify',
        'closeCase',
        'decideStage',
        'revokeStage',
        'approveDistribution',
      ];
      for (const route of must) {
        const owner = CONTROLLERS.find(({ ctor }) => routeNames(ctor).includes(route));
        expect({ route, found: owner !== undefined }).toEqual({ route, found: true });
        expect({ route, gated: stepUpGuarded((owner as { ctor: Ctor }).ctor, route) }).toEqual({
          route,
          gated: true,
        });
      }
    });
  });

  /**
   * THE DECLARATION'S OWN ENUMERATION OF THE ABSENCES IS TOTAL.
   *
   * `AUDIENCE_ROUTE_ADMITTERS.operator` is a list of what IS admitted, and the
   * derived check above proves everything else is refused. Neither says WHY a
   * particular handler is absent, and that reason is the part a reviewer needs
   * — so the declaration's docblock enumerates the refused set with a reason
   * apiece, and this asserts the enumeration has not stopped covering it.
   *
   * IT HAD ALREADY ROTTED WHEN THIS WAS WRITTEN: the docblock named
   * `listMyCases`, which is not a handler in this product (`listMine` is), and
   * omitted four refusals outright. Nothing could see it, because a paragraph
   * of reasons has no mechanism behind it — which is the whole subject of M21
   * PR2.5, committed one PR earlier.
   *
   * BOTH DIRECTIONS. A refused handler missing from the prose is an absence
   * nobody decided; a NAME in the prose that is not a handler is a reason
   * pointing at nothing, which is worse, because it reads as covered.
   */
  describe('the declaration explains every absence', () => {
    const SESSION_SOURCE = join(
      __dirname,
      '..',
      '..',
      '..',
      '..',
      'packages',
      'auth-guard',
      'src',
      'session.ts',
    );

    /**
     * Backticked bare identifiers that are legitimately NOT settlement
     * handlers, declared with the reason each appears. Anything else the prose
     * names has to be a real route.
     */
    const NOT_A_SETTLEMENT_HANDLER: Readonly<Record<string, string>> = {
      vault: 'the audience whose treatment this paragraph is compared against',
      mintHandoff: "identity's handler, absent from every non-account audience",
      assertCaseVisible: 'the service method the four reads authorize through',
    };

    /** The docblock immediately above `operator: [` in the admitters table. */
    function operatorDocblock(): string {
      const source = readFileSync(SESSION_SOURCE, 'utf8');
      const table = source.indexOf('export const AUDIENCE_ROUTE_ADMITTERS');
      expect(table).toBeGreaterThan(-1);
      const list = source.indexOf('operator: [', table);
      expect(list).toBeGreaterThan(-1);
      const open = source.lastIndexOf('/**', list);
      const close = source.indexOf('*/', open);
      expect(open).toBeGreaterThan(table);
      expect(close).toBeGreaterThan(open);
      expect(close).toBeLessThan(list);
      return source.slice(open, close);
    }

    /** Only the absence paragraphs — the admitted groups name handlers too. */
    function absenceProse(): string {
      const doc = operatorDocblock();
      const start = doc.indexOf('ABSENT AND DELIBERATE');
      expect(start).toBeGreaterThan(-1);
      const prose = doc.slice(start);
      // A floor, because two empty strings agree perfectly and a heading that
      // is renamed would otherwise slice to nothing and pass.
      expect(prose.length).toBeGreaterThan(600);
      return prose;
    }

    function namedIdentifiers(prose: string): string[] {
      return [...prose.matchAll(/`([A-Za-z][A-Za-z0-9]*)`/g)].map((m) => m[1] as string);
    }

    it('names every refused handler', () => {
      const allowed = new Set(OPERATOR_ROUTES.map((r) => r.route));
      const refused = CONTROLLERS.flatMap(({ ctor }) =>
        routeNames(ctor).filter((route) => !allowed.has(route)),
      ).sort();
      expect(refused.length).toBeGreaterThan(0);
      const named = new Set(namedIdentifiers(absenceProse()));
      expect(refused.filter((route) => !named.has(route))).toEqual([]);
    });

    it('names nothing that is not a handler', () => {
      const routes = new Set(CONTROLLERS.flatMap(({ ctor }) => routeNames(ctor)));
      const phantom = namedIdentifiers(absenceProse()).filter(
        (name) => !routes.has(name) && !(name in NOT_A_SETTLEMENT_HANDLER),
      );
      expect(phantom).toEqual([]);
    });
  });

  it('NO route admits `vault` or `extension`, and every decoration keeps `account`', () => {
    // Settlement is a callee of the vault (the §6a gate) and has nothing to do
    // with a browser extension. Swept rather than assumed, because the
    // decorator takes a LIST and a second member is one keystroke.
    //
    // `account` is expected on every decorated route and is not a widening:
    // `AllowSessionAudiences` prepends the default unconditionally and its
    // signature (`Exclude<SessionAudience, 'account'>[]`) means a call site
    // cannot even name it. That is what makes the decorator incapable of
    // taking authority away — asserted here rather than trusted, since it is
    // also what keeps an operator working from the main app on an account
    // session.
    for (const { ctor } of CONTROLLERS) {
      for (const route of routeNames(ctor)) {
        const declared = admittedAudiences(ctor, route);
        if (declared === undefined) continue;
        expect({ route, declared: [...declared].sort() }).toEqual({
          route,
          declared: ['account', 'operator'],
        });
      }
    }
  });
});

describe('the guard actually READS the declaration', () => {
  /**
   * The half neither the shared fence nor a prototype scan can reach.
   *
   * `CallerGuard`'s reflector is `@Optional()`, and `audiencesFor` returns the
   * service-wide list when it is absent. Settlement binds no
   * `ALLOWED_SESSION_AUDIENCES`, so that list is `['account']` — and a
   * container where `Reflector` does not resolve would refuse every decorated
   * route with the same generic 401 an invalid token gets. Nothing about that
   * failure is visible: no error, no log, and every source-level fence still
   * green. So this drives the real guard both ways round, and the second case
   * is what proves the first is measuring the reflector rather than the
   * default.
   */
  const OPERATOR_SESSION: SessionContext = {
    userId: '00000000-0000-4000-8000-000000000001',
    sessionId: '00000000-0000-4000-8000-000000000002',
    mfaLevel: 'mfa',
    stepupExpiresAt: null,
    audience: 'operator',
  };

  const verifier: SessionVerifier = {
    verify: () => Promise.resolve(OPERATOR_SESSION),
  };

  function contextFor(controller: Ctor, route: string): ExecutionContext {
    const handler = (controller.prototype as unknown as Record<string, () => unknown>)[route];
    const request: Record<string, unknown> = { headers: { authorization: 'Bearer t' } };
    return {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => handler,
      getClass: () => controller,
    } as unknown as ExecutionContext;
  }

  it('admits an operator session on a decorated route', async () => {
    const guard = new CallerGuard(verifier, undefined, new Reflector());
    await expect(guard.canActivate(contextFor(OperatorController, 'queue'))).resolves.toBe(true);
  });

  it('refuses the same session on an undecorated route, with the generic 401', async () => {
    // The refusal is deliberately indistinguishable from an invalid token: a
    // distinct "wrong audience" would tell whoever holds a stolen console
    // credential that it is real and merely pointed at the wrong door.
    const guard = new CallerGuard(verifier, undefined, new Reflector());
    await expect(guard.canActivate(contextFor(SettlementController, 'void'))).rejects.toMatchObject(
      { response: { error: 'unauthorized' } },
    );
  });

  it('WITHOUT a Reflector the decorated route is refused too — the silent-inertness case', async () => {
    // This is the failure T9 describes, reproduced rather than argued: the
    // decorator is present, the table declares it, every source fence is
    // green, and the route answers 401 forever. Asserting it here means the
    // case above is measuring the reflector and not a default that happens to
    // agree.
    const guard = new CallerGuard(verifier, undefined, undefined);
    await expect(guard.canActivate(contextFor(OperatorController, 'queue'))).rejects.toMatchObject({
      response: { error: 'unauthorized' },
    });
  });

  it('an ACCOUNT session still reaches the console routes', async () => {
    // The union, not a replacement: decorating a route must never take
    // authority away. An operator working from the main app (an account
    // session) is the interim path M21 PR3a shipped, and it must keep working.
    const accountVerifier: SessionVerifier = {
      verify: () => Promise.resolve({ ...OPERATOR_SESSION, audience: 'account' }),
    };
    const guard = new CallerGuard(accountVerifier, undefined, new Reflector());
    await expect(guard.canActivate(contextFor(OperatorController, 'queue'))).resolves.toBe(true);
    await expect(guard.canActivate(contextFor(SettlementController, 'void'))).resolves.toBe(true);
  });
});

describe('the operator edge proxies exactly what this service admits', () => {
  /**
   * THE SET, NOT A COUNT, AND FROM THE RUNTIME RATHER THAN FROM TEXT.
   *
   * `apps/operator-web/src/server.ts` decides which settlement routes an
   * operator console can address at all; this file decides which ones a
   * `operator`-audience session is admitted to. They are two tables in two
   * packages and nothing compared them, which is the drift class this repo
   * keeps finding — the `GQL_ERROR_CODES` shape, one hop over.
   *
   * IT LIVES HERE, in the service, because only here is the answer available
   * as METADATA rather than as source text: the same `PATH_METADATA` and
   * `METHOD_METADATA` Nest routes on, read off the real controller
   * prototypes. The auth-guard fence checks the DECLARATION against the
   * decorators; this checks the EDGE against the runtime. The edge's own file
   * is read as text, which is the compose-parity mechanism — an app cannot
   * import a NestJS package, and this service has no business importing an
   * app.
   *
   * BOTH DIRECTIONS, deliberately. An edge row with no admission is a route
   * the console would call and be refused on — a console that looks broken for
   * a reason no error names. An admission with no edge row is the zero-callers
   * shape this milestone exists to close: a capability granted ahead of
   * anything reaching it. Neither is a vulnerability; both are the two tables
   * disagreeing, and the point of the fence is that they cannot.
   */
  const EDGE_SERVER = join(
    __dirname,
    '..',
    '..',
    '..',
    '..',
    'apps',
    'operator-web',
    'src',
    'server.ts',
  );

  function edgeSettlementRows(): string[] {
    const source = readFileSync(EDGE_SERVER, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/[^\n]*/g, '');
    const rows: string[] = [];
    for (const block of source.matchAll(/\{[^{}]*\}/g)) {
      const text = block[0];
      if (!/\bupstream:\s*'settlement'/.test(text)) continue;
      const method = /\bmethod:\s*'([A-Z]+)'/.exec(text)?.[1];
      const to = /\brewriteTo:\s*'([^']+)'/.exec(text)?.[1];
      // A row this scan can SEE but cannot READ must fail rather than be
      // skipped: a silently-narrowed corpus is the failure both halves of this
      // suite are written against. OVER-DETERMINED with the count below, and
      // kept for the MESSAGE rather than for the coverage — this one names the
      // offending row, where the count says only that two numbers differ.
      expect({ text, readable: method !== undefined && to !== undefined }).toEqual({
        text,
        readable: true,
      });
      rows.push(`${method as string} ${to as string}`);
    }
    /*
     * …AND A ROW THE SCAN CANNOT SEE AT ALL, which the assertion above cannot
     * reach and which a pair probe found before this shipped. `{[^{}]*}` does
     * not span a NESTED brace, so a row written with an object spread is not
     * "unreadable" to it — it is invisible, and an invisible EXTRA row leaves
     * the set comparison below passing while the edge proxies a route this
     * service refuses. (A missing row is caught by the comparison itself; only
     * an extra one hides.)
     *
     * The count is a second, deliberately dumber reading of the same file —
     * the compose-parity mechanism. Two readings that must agree.
     */
    const declared = (source.match(/\bupstream:\s*'settlement'/g) ?? []).length;
    expect({ declared, parsed: rows.length }).toEqual({ declared, parsed: declared });
    return rows.sort();
  }

  it('finds the edge table it is meant to be checking (anti-vacuity)', () => {
    const rows = edgeSettlementRows();
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row).toMatch(/^(GET|POST) \/v1\/settlement\//);
    }
  });

  it('the edge’s settlement rows are EXACTLY the routes that admit an operator', () => {
    const admitted = OPERATOR_ROUTES.map(({ controller, route }) =>
      routeSignature(controller, route),
    ).sort();
    expect(edgeSettlementRows()).toEqual(admitted);
  });

  it('and every one of those routes really carries the decorator', () => {
    // Without this the equality above could hold between two lists that agree
    // with each other and with nothing the guard reads.
    for (const { controller, route } of OPERATOR_ROUTES) {
      expect({ route, admits: admits(controller, route) }).toEqual({ route, admits: true });
    }
  });
});
