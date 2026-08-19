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
];

/**
 * Named refusals, with the reason each matters. Not the complete refused set —
 * that is derived below — but the subset where a mistaken grant is worst.
 */
const MUST_REFUSE: ReadonlyArray<{ controller: Ctor; route: string; why: string }> = [
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
    // 29 across four controllers. Asserted so the next person MEASURES rather
    // than remembering: the decision log carried a wrong route count for
    // settlement for four milestones (M21 PR2.5).
    expect(counts.reduce((a, b) => a + b, 0)).toBe(29);
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
    // sense of coverage: a 30th route added tomorrow is refused by default and
    // this notices if it is not. SIXTEEN refused — a number that lives here,
    // where it is measured, and deliberately not in prose beside it.
    const allowed = new Set(OPERATOR_ROUTES.map((r) => r.route));
    const refused = CONTROLLERS.flatMap(({ ctor }) =>
      routeNames(ctor).filter((route) => !allowed.has(route)),
    );
    expect(refused).toHaveLength(16);
    for (const { ctor } of CONTROLLERS) {
      for (const route of routeNames(ctor)) {
        if (allowed.has(route)) continue;
        expect({ route, admits: admits(ctor, route) }).toEqual({ route, admits: false });
      }
    }
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
