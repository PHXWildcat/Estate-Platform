import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { INestApplication } from '@nestjs/common';
import { ACCESS_STAGES } from '@estate/settlement-client';
import { ACCESS_COOKIE } from '../src/cookies';
import { bffError } from '../src/identity-client';
import {
  FakeAssetsClient,
  FakeIdentityClient,
  FakeProfileClient,
  FakeSettlementClient,
  TOKENS,
  gql,
  gqlBody,
  makeApp,
} from './helpers';

/**
 * THE EXECUTOR SURFACE'S BFF HALF (M23 PR2).
 *
 * Three properties carry this file.
 *
 * The FIRST is that no `decedentUserId` reaches the browser while the estate
 * inventory — a route keyed on exactly that id — still works. The resolver
 * turns a case id back into an estate against settlement's OWN list, so the
 * handle the browser holds is checked rather than trusted, and a case id with
 * no authority behind it never reaches assets at all.
 *
 * The SECOND is that the estate inventory is not the caller's own asset list.
 * They are two service routes with two authorization models, and serving one
 * where the other was asked would show an executor their own assets under a
 * dead person's name — a defect that reads as working software.
 *
 * The THIRD is that profile DECORATES and never gates. An executor whose
 * estates cannot be named must still reach every one of them; a `Promise.all`
 * would render a profile outage as "you are settling nothing", which is a
 * failed read wearing the face of a real empty answer.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;

const CASES_QUERY = 'query ExecutorCases { executorCases { caseId ownerName status verifiedAt } }';
const STAGES_QUERY = `query EstateStages($caseId: ID!) {
  estateStages(caseId: $caseId) { stage status requestedAt decidedAt }
}`;
const INVENTORY_QUERY = `query EstateInventory($caseId: ID!) {
  estateInventory(caseId: $caseId) { assetId title estValue }
}`;
const REQUEST_MUTATION = `mutation RequestEstateAccess($caseId: ID!, $stage: AccessStage!) {
  requestEstateAccess(caseId: $caseId, stage: $stage) { stage status decidedAt }
}`;
const CONTACTS_QUERY = `query EstateContacts($caseId: ID!) {
  estateContacts(caseId: $caseId) { id name relationship professionalKind hasEmail linked }
}`;
const TASKS_QUERY = `query EstateTasks($caseId: ID!) {
  estateTasks(caseId: $caseId) { taskId title category assignedRole dueAt completedAt }
}`;
const TICK_MUTATION = `mutation SetEstateTaskCompletion($taskId: ID!, $completed: Boolean!) {
  setEstateTaskCompletion(taskId: $taskId, completed: $completed) { taskId completedAt }
}`;

/**
 * THE ENUM IS DERIVED, NOT RESTATED.
 *
 * `ACCESS_STAGES` in `@estate/settlement-client` is what the settlement
 * service's own ladder reads — `assertPredecessorApproved` walks it — and the
 * SDL declares the same vocabulary a second time because apps/bff cannot ship
 * a runtime import into a GraphQL string. A hand-maintained list beside a
 * thing that grows is this repo's most repeated defect, so the list is read
 * from the package and the SDL is compared to it.
 *
 * BOTH DIRECTIONS, because they fail differently: a stage the SDL is missing
 * is an action nobody can request, and a stage the SDL invents is an argument
 * the service will reject at the last moment with a parse error.
 */
describe('the AccessStage enum mirrors the runtime ladder', () => {
  const SCHEMA = join(__dirname, '..', 'src', 'schema.ts');

  function sdlEnumMembers(name: string): string[] {
    const source = readFileSync(SCHEMA, 'utf8');
    const sdl = /export const typeDefs = \/\* GraphQL \*\/ `([\s\S]*?)\n`;/.exec(source);
    // Anti-vacuity: an anchor that stopped matching would slice to nothing and
    // make every assertion below compare two empty lists.
    expect(sdl?.[1]?.length ?? 0).toBeGreaterThan(1000);
    const block = new RegExp(`enum ${name} \\{([^}]*)\\}`).exec(sdl?.[1] ?? '');
    expect(block?.[1]).toBeTruthy();
    return (block?.[1] ?? '')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => /^[A-Z_]+$/.test(line));
  }

  it('declares exactly the stages the ladder walks, in the ladder’s order', () => {
    expect(ACCESS_STAGES.length).toBeGreaterThan(0);
    expect(sdlEnumMembers('AccessStage')).toEqual(ACCESS_STAGES.map((s) => s.toUpperCase()));
  });

  it('keeps VAULT last — Zone A is never released alongside the inventory', () => {
    // A property the ORDER decides, asserted where the order lives. Sorting
    // this enum alphabetically would put DOCUMENTS first and read as tidying.
    expect(ACCESS_STAGES.at(-1)).toBe('vault');
  });
});

describe('executor resolvers', () => {
  let app: INestApplication;
  let settlement: FakeSettlementClient;
  let identity: FakeIdentityClient;
  let profile: FakeProfileClient;
  let assets: FakeAssetsClient;

  beforeEach(async () => {
    settlement = new FakeSettlementClient();
    identity = new FakeIdentityClient();
    profile = new FakeProfileClient();
    assets = new FakeAssetsClient();
    identity.sessionResult = {
      userId: TOKENS.userId,
      sessionId: TOKENS.sessionId,
      mfaLevel: 'stepup',
      stepupExpiresAt: '2099-01-01T00:00:00.000Z',
      audience: 'account',
    };
    app = await makeApp({ settlement, identity, profile, assets });
  });

  afterEach(async () => {
    await app.close();
  });

  function rows(
    res: Awaited<ReturnType<typeof gql>>,
    field: string,
  ): Array<Record<string, unknown>> {
    return gqlBody(res).data?.[field] as Array<Record<string, unknown>>;
  }

  describe('the estates you are settling', () => {
    it('names each one and exposes NO user id', async () => {
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      const list = rows(res, 'executorCases');
      expect(list).toHaveLength(2);
      // The decedent's user id is on the wire from settlement and must not
      // survive the projection — asserted on the SERIALISED body, because a
      // field absent from the query's selection set proves nothing about
      // whether the type could carry it.
      expect(JSON.stringify(list)).not.toContain('user-1');
      expect(JSON.stringify(list)).not.toContain('user-9');
      expect(list[0]).toMatchObject({ caseId: 'case-1', status: 'verified' });
    });

    it('joins the decedent’s name on the CONTACT id both services agree on', async () => {
      profile.linkedEstatesResult = [
        { ownerUserId: 'user-1', contactId: 'contact-1', ownerName: 'Ada Lovelace', roles: [] },
      ];
      const list = rows(
        await gql(app, { query: CASES_QUERY }, { cookie: COOKIE }),
        'executorCases',
      );
      expect(list[0]).toMatchObject({ ownerName: 'Ada Lovelace' });
      // The estate with no profile row KEEPS ITS PLACE and loses only its
      // name. Dropping it would hide an estate this caller is genuinely
      // settling behind somebody else's unfilled profile.
      expect(list[1]).toMatchObject({ caseId: 'case-9', ownerName: null });
    });

    it('a failed PROFILE read still lists the estates, unnamed', async () => {
      profile.profileError = new Error('profile unreachable');
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      expect(gqlBody(res).errors).toBeUndefined();
      const list = rows(res, 'executorCases');
      expect(list.map((r) => r['caseId'])).toEqual(['case-1', 'case-9']);
      expect(list.every((r) => r['ownerName'] === null)).toBe(true);
    });

    it('settling NOTHING costs no cross-user disclosure at all', async () => {
      /*
       * THE FINDING THIS PINS (M24 PR4 review). Since M24 PR3 the dashboard is
       * the home page, and it mounts the self-hiding panel this resolver backs
       * on EVERY landing. The resolver read profile unconditionally, so every
       * person who had ever redeemed a contact link — an executor-designate, a
       * named beneficiary, a spouse, with the estate's owner alive and well —
       * spent one `contact.link.estates_read` plus one audited decrypt of that
       * owner's `legal_name`, ON THE OWNER'S TRAIL, naming the reader as the
       * actor, every time they opened the home page, to decorate a list that
       * was empty. Settlement is the spine: no case, no name, no disclosure.
       */
      settlement.executorCasesResult = [];
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      expect(rows(res, 'executorCases')).toEqual([]);
      expect(profile.linkedEstatesCalls).toEqual([]);
    });

    it('POSITIVE CONTROL: an estate that IS being settled still gets its name', async () => {
      // Paired with the test above so that "profile was never called" cannot
      // be satisfied by a resolver that stopped naming anything.
      profile.linkedEstatesResult = [
        { ownerUserId: 'user-1', contactId: 'contact-1', ownerName: 'Ada Lovelace', roles: [] },
      ];
      const list = rows(
        await gql(app, { query: CASES_QUERY }, { cookie: COOKIE }),
        'executorCases',
      );
      expect(list[0]).toMatchObject({ ownerName: 'Ada Lovelace' });
      expect(profile.linkedEstatesCalls).toHaveLength(1);
    });

    it('a failed SETTLEMENT read is an error, never an empty list', async () => {
      // The opposite direction from the test above, and the reason they are
      // not the same rule: settlement is the AUTHORITY on this list, so an
      // unreadable one is not knowledge that there is nothing to settle.
      settlement.settlementError = new Error('settlement unreachable');
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      expect(gqlBody(res).errors).toBeDefined();
      expect(gqlBody(res).data?.['executorCases']).toBeFalsy();
    });
  });

  describe('the staged-access ladder', () => {
    it('forwards the case id and the caller’s own bearer, and drops actor ids', async () => {
      const res = await gql(
        app,
        { query: STAGES_QUERY, variables: { caseId: 'case-1' } },
        { cookie: COOKIE },
      );
      expect(settlement.stagesCalls).toEqual([
        { accessToken: TOKENS.accessToken, caseId: 'case-1' },
      ]);
      const list = rows(res, 'estateStages');
      expect(list).toEqual([
        {
          stage: 'INVENTORY',
          status: 'approved',
          requestedAt: '2026-08-19T00:00:00.000Z',
          decidedAt: '2026-08-19T01:00:00.000Z',
        },
      ]);
    });

    it('does NOT resolve the case id first — settlement owns who may read stages', async () => {
      // `assertCaseVisible` admits the decedent, a still-linked reporter (M48),
      // the executor and an operator. A resolve-first check here would refuse three of the four
      // on a route they are admitted to by design, and could only ever
      // DISAGREE with the authoritative answer.
      await gql(app, { query: STAGES_QUERY, variables: { caseId: 'case-1' } }, { cookie: COOKIE });
      expect(settlement.executorCasesCalls).toEqual([]);
    });

    it('sends the service’s own lowercase vocabulary, not the enum member name', async () => {
      // GraphQL serialises an enum as its NAME. Sending `INVENTORY` downstream
      // would earn a 400 from a service whose ladder is spelled in lowercase —
      // the M20 PR1 `MfaLevel` defect, one layer down.
      const res = await gql(
        app,
        { query: REQUEST_MUTATION, variables: { caseId: 'case-1', stage: 'INVENTORY' } },
        { cookie: COOKIE },
      );
      expect(settlement.requestStageCalls).toEqual([
        { accessToken: TOKENS.accessToken, caseId: 'case-1', stage: 'inventory' },
      ]);
      // ...and comes back UP to the member name, or serialisation fails.
      expect(gqlBody(res).data?.['requestEstateAccess']).toMatchObject({
        stage: 'INVENTORY',
        status: 'requested',
        decidedAt: null,
      });
    });

    it('refuses a stage the ladder does not have, before any call is made', async () => {
      const res = await gql(
        app,
        { query: REQUEST_MUTATION, variables: { caseId: 'case-1', stage: 'EVERYTHING' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeDefined();
      expect(settlement.requestStageCalls).toEqual([]);
    });
  });

  describe('the estate inventory', () => {
    it('reads the ESTATE route with the decedent the case names', async () => {
      const res = await gql(
        app,
        { query: INVENTORY_QUERY, variables: { caseId: 'case-9' } },
        { cookie: COOKIE },
      );
      // `case-9` names `user-9`, and the FIRST row of the list names `user-1`.
      // A resolver that took the head instead of the match would pass a test
      // whose fixture had one estate on it.
      expect(assets.listEstateCalls).toEqual([
        { accessToken: TOKENS.accessToken, ownerUserId: 'user-9' },
      ]);
      // The owner's own list is never touched — two routes, two authorization
      // models, and serving one for the other is a cross-user disclosure that
      // reads as working software.
      expect(assets.listCalls).toEqual([]);
      expect(rows(res, 'estateInventory')[0]).toMatchObject({ assetId: 'estate-asset-1' });
    });

    it('answers NOT_FOUND for a case this caller does not administer, without calling assets', async () => {
      const res = await gql(
        app,
        { query: INVENTORY_QUERY, variables: { caseId: 'someone-elses-case' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('NOT_FOUND');
      // The refusal happens HERE, so an id with no authority behind it never
      // becomes a user id and never reaches another service.
      expect(assets.listEstateCalls).toEqual([]);
    });
  });

  /**
   * THE CHECKLIST (M23 PR3).
   *
   * Two properties. The first is that a task is PROCEDURAL state, not access:
   * it is forwarded like the ladder, because settlement's `assertCaseVisible`
   * decides who may read it, and it needs no approved stage at all. The second
   * is that the tick is reversible by the same call that made it — a checklist
   * an executor can complete but not correct turns an honest mistake into a
   * permanent one.
   */
  describe('the estate checklist', () => {
    it('forwards the case id and exposes no actor id or court-document id', async () => {
      const res = await gql(
        app,
        { query: TASKS_QUERY, variables: { caseId: 'case-1' } },
        { cookie: COOKIE },
      );
      expect(settlement.tasksCalls).toEqual([
        { accessToken: TOKENS.accessToken, caseId: 'case-1' },
      ]);
      const list = rows(res, 'estateTasks');
      expect(list).toHaveLength(2);
      expect(list[0]).toMatchObject({ taskId: 'task-1', assignedRole: 'attorney' });
      // A step aimed at somebody else is still SHOWN — the executor is the
      // person who has to know it is the attorney's move.
      expect(list.map((r) => r['assignedRole'])).toEqual(['attorney', 'executor']);
      expect(JSON.stringify(list)).not.toContain('completedBy');
      expect(JSON.stringify(list)).not.toContain('courtDocVersionId');
    });

    it('does NOT resolve the case id first — settlement owns who may read tasks', async () => {
      // Same argument as the ladder: `assertCaseVisible` admits the decedent's
      // reader, the reporter, the executor and an operator, and a resolve-first
      // check here would refuse three of the four.
      await gql(app, { query: TASKS_QUERY, variables: { caseId: 'case-1' } }, { cookie: COOKIE });
      expect(settlement.executorCasesCalls).toEqual([]);
    });

    it('reports a task that is already done as done, not as a fresh one', async () => {
      const list = rows(
        await gql(app, { query: TASKS_QUERY, variables: { caseId: 'case-1' } }, { cookie: COOKIE }),
        'estateTasks',
      );
      expect(list[0]?.['completedAt']).toBeNull();
      expect(list[1]?.['completedAt']).toBe('2026-08-20T00:00:00.000Z');
    });

    it('ticks and UNTICKS through the one mutation', async () => {
      const done = gqlBody(
        await gql(
          app,
          { query: TICK_MUTATION, variables: { taskId: 'task-1', completed: true } },
          { cookie: COOKIE },
        ),
      ).data?.['setEstateTaskCompletion'];
      expect(done).toMatchObject({ taskId: 'task-1' });
      expect((done as Record<string, unknown>)['completedAt']).not.toBeNull();

      const undone = gqlBody(
        await gql(
          app,
          { query: TICK_MUTATION, variables: { taskId: 'task-2', completed: false } },
          { cookie: COOKIE },
        ),
      ).data?.['setEstateTaskCompletion'];
      // `task-2` arrives ALREADY COMPLETED in the fixture, so this is a real
      // reversal rather than a no-op on a task that was never ticked.
      expect(undone).toMatchObject({ taskId: 'task-2', completedAt: null });

      expect(settlement.completeTaskCalls).toEqual([
        { accessToken: TOKENS.accessToken, taskId: 'task-1', completed: true },
        { accessToken: TOKENS.accessToken, taskId: 'task-2', completed: false },
      ]);
    });

    it('serves an UNELEVATED session — this layer adds no freshness of its own', async () => {
      /*
       * WHICH LAYER THIS PROVES. The BFF evaluates no step-up anywhere; it
       * forwards the caller's bearer and maps a downstream 403. So the half
       * provable here is that the checklist resolvers do not invent a
       * freshness requirement the services never asked for — a session with no
       * second factor at all reads and ticks.
       *
       * The other half — that settlement's own two task routes carry no
       * `StepUpGuard` — is a claim about decorators, and is asserted against
       * the real metadata in `settlement/test/session-audience.spec.ts`.
       *
       * The property both halves are for: a tick moves no access and no money,
       * and an executor days after a death should not meet an MFA prompt to
       * say they have found the will.
       */
      identity.sessionResult = {
        userId: TOKENS.userId,
        sessionId: TOKENS.sessionId,
        mfaLevel: 'none',
        stepupExpiresAt: null,
        audience: 'account',
      };
      const read = await gql(
        app,
        { query: TASKS_QUERY, variables: { caseId: 'case-1' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(read).errors).toBeUndefined();
      const tick = await gql(
        app,
        { query: TICK_MUTATION, variables: { taskId: 'task-1', completed: true } },
        { cookie: COOKIE },
      );
      expect(gqlBody(tick).errors).toBeUndefined();
      expect(settlement.completeTaskCalls).toHaveLength(1);
    });
  });

  /**
   * THE ESTATE'S CONTACTS (M23 PR4a) — docs/03 §5.4's control against
   * grief-window phishing, and §5.1 control 5's ladder deciding when it opens.
   *
   * Two properties. The first is that this resolver RESOLVES rather than
   * forwards: profile keys the route on `ownerUserId`, so the case id has to
   * become a user id somewhere, and doing it against settlement's own list is
   * what keeps a `decedentUserId` out of the browser and stops a case id with
   * no authority behind it from ever reaching profile.
   *
   * The second is that a shut rung is not a missing estate. Profile collapses
   * every other 403 to the uniform not-found; here that would tell an executor
   * the case they are looking at does not exist.
   */
  describe('the estate’s contacts', () => {
    it('reads PROFILE with the decedent the case names, never the caller’s own list', async () => {
      const res = await gql(
        app,
        { query: CONTACTS_QUERY, variables: { caseId: 'case-9' } },
        { cookie: COOKIE },
      );
      // `case-9` names `user-9` and the FIRST row of the list names `user-1`, so
      // a resolver that took the head would pass a one-estate fixture.
      expect(profile.estateContactsCalls).toEqual([
        { accessToken: TOKENS.accessToken, ownerUserId: 'user-9' },
      ]);
      // The caller's OWN contacts route is never touched — two routes, two
      // authorization models, and serving one for the other would show an
      // executor their own address book under a dead person's name.
      expect(profile.contactsCalls).toEqual([]);
      const list = rows(res, 'estateContacts');
      expect(list).toHaveLength(2);
      expect(list[0]).toMatchObject({ name: 'Grace Hopper', professionalKind: 'attorney' });
    });

    it('exposes no user id — not the decedent’s, not the contacts’', async () => {
      const res = await gql(
        app,
        { query: CONTACTS_QUERY, variables: { caseId: 'case-9' } },
        { cookie: COOKIE },
      );
      // On the SERIALISED body: `ContactSummary` has no `ownerUserId` field to
      // select, which is the property, and asserting it on the wire is what
      // proves the type could not carry one even if a query asked.
      const body = JSON.stringify(rows(res, 'estateContacts'));
      expect(body).not.toContain('user-9');
      expect(body).not.toContain('user-1');
    });

    it('answers NOT_FOUND for a case this caller does not administer, without calling profile', async () => {
      const res = await gql(
        app,
        { query: CONTACTS_QUERY, variables: { caseId: 'someone-elses-case' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('NOT_FOUND');
      expect(profile.estateContactsCalls).toEqual([]);
    });

    it('lets the client’s own refusal through unchanged', async () => {
      /*
       * WHICH LAYER THIS PROVES. That a shut rung becomes
       * `STAGE_NOT_APPROVED` rather than the uniform not-found is the profile
       * CLIENT's mapping, and a fake client cannot demonstrate it — that
       * assertion lives in `profile-client.spec.ts` against a real 403.
       *
       * What this layer decides is that the resolver ADDS NOTHING: whatever
       * code the client raises is the code the browser sees, so the resolver
       * cannot quietly re-collapse a distinction the edge went to trouble to
       * preserve.
       */
      profile.profileError = bffError('STAGE_NOT_APPROVED');
      const res = await gql(
        app,
        { query: CONTACTS_QUERY, variables: { caseId: 'case-9' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('STAGE_NOT_APPROVED');
    });
  });
});
