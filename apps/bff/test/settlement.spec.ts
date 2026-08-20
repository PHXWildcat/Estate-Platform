import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { INestApplication } from '@nestjs/common';
import { ACCESS_COOKIE } from '../src/cookies';
import {
  FakeIdentityClient,
  FakeProfileClient,
  FakeSettlementClient,
  SETTLEMENT_CASE,
  TOKENS,
  gql,
  gqlBody,
  makeApp,
} from './helpers';

/**
 * The settlement resolvers (M22 PR3) — the BFF's first edge to settlement.
 *
 * Most of this layer forwards. What it DECIDES is small and load-bearing, and
 * that is what is asserted here:
 *
 *  - the PROJECTION: two raw user UUIDs become one boolean, evidence becomes a
 *    count, and neither id reaches the browser;
 *  - `voidable`, which decides whether a person is offered the only control
 *    they have against a fraudulent case naming them;
 *  - that an unidentifiable caller is REFUSED rather than silently treated as
 *    nobody — the failure mode that would hide the kill switch;
 *  - that `resolution` survives, because the surface renders the outcome from
 *    it rather than from a status the DDL forces to spell `rejected_fraud`.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;

const CASES_QUERY = `query SettlementCases {
  settlementCases {
    caseId status reportSource evidenceCount waitingPeriodEnds
    resolution resolvedAt createdAt aboutMe voidable
  }
}`;
const SETTINGS_QUERY = 'query SettlementSettings { settlementSettings { waitingPeriodDays } }';
const VOID_MUTATION = `mutation VoidSettlementCase($caseId: ID!) {
  voidSettlementCase(caseId: $caseId) { caseId status resolution aboutMe voidable }
}`;
const SET_PERIOD = `mutation SetSettlementWaitingPeriod($days: Int!) {
  setSettlementWaitingPeriod(days: $days) { waitingPeriodDays }
}`;
const REPORTABLE_QUERY =
  'query ReportableEstates { reportableEstates { contactId ownerName roles } }';
const REPORT_MUTATION = `mutation ReportDeath($contactId: ID!, $documentId: ID, $documentVersion: Int) {
  reportDeath(contactId: $contactId, documentId: $documentId, documentVersion: $documentVersion) {
    caseId status aboutMe evidenceCount
  }
}`;
const ATTACH_MUTATION = `mutation AttachCaseEvidence($caseId: ID!, $documentId: ID!, $version: Int!) {
  attachCaseEvidence(caseId: $caseId, documentId: $documentId, version: $version) {
    caseId evidenceCount
  }
}`;

describe('settlement resolvers', () => {
  let app: INestApplication;
  let settlement: FakeSettlementClient;
  let identity: FakeIdentityClient;
  let profile: FakeProfileClient;

  beforeEach(async () => {
    settlement = new FakeSettlementClient();
    identity = new FakeIdentityClient();
    profile = new FakeProfileClient();
    identity.sessionResult = {
      userId: TOKENS.userId,
      sessionId: TOKENS.sessionId,
      mfaLevel: 'stepup',
      stepupExpiresAt: '2099-01-01T00:00:00.000Z',
      audience: 'account',
    };
    app = await makeApp({ settlement, identity, profile });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards the caller’s own bearer to every settlement route', async () => {
    await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
    await gql(app, { query: SETTINGS_QUERY }, { cookie: COOKIE });
    await gql(
      app,
      { query: VOID_MUTATION, variables: { caseId: SETTLEMENT_CASE.caseId } },
      { cookie: COOKIE },
    );
    await gql(app, { query: SET_PERIOD, variables: { days: 30 } }, { cookie: COOKIE });

    expect(settlement.listCalls).toEqual([TOKENS.accessToken]);
    expect(settlement.getSettingsCalls).toEqual([TOKENS.accessToken]);
    expect(settlement.voidCalls).toEqual([
      { accessToken: TOKENS.accessToken, caseId: SETTLEMENT_CASE.caseId },
    ]);
    expect(settlement.updateSettingsCalls).toEqual([
      { accessToken: TOKENS.accessToken, waitingPeriodDays: 30 },
    ]);
  });

  describe('the projection', () => {
    it('answers aboutMe TRUE for the subject and offers them the kill switch', async () => {
      settlement.listResult = [{ ...SETTLEMENT_CASE, decedentUserId: TOKENS.userId }];
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      const [row] = gqlBody(res).data?.['settlementCases'] as Array<Record<string, unknown>>;
      expect(row).toMatchObject({ aboutMe: true, voidable: true });
    });

    it('answers aboutMe FALSE for the reporter and offers them NOTHING to press', async () => {
      // The same list carries both. A reporter looking at a case they filed
      // must not see a void button: the kill switch belongs to the subject,
      // Cedar says so (`resource.decedent == principal`), and offering it here
      // would be an action the server refuses.
      settlement.listResult = [
        { ...SETTLEMENT_CASE, decedentUserId: 'someone-else', reportedBy: TOKENS.userId },
      ];
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      const [row] = gqlBody(res).data?.['settlementCases'] as Array<Record<string, unknown>>;
      expect(row).toMatchObject({ aboutMe: false, voidable: false });
    });

    it('counts evidence and carries none of it', async () => {
      settlement.listResult = [
        {
          ...SETTLEMENT_CASE,
          decedentUserId: TOKENS.userId,
          evidence: [
            { type: 'document', documentId: 'doc-secret-1', version: 2, addedBy: 'user-9' },
            { type: 'provider_match', matchId: 'lexisnexis-abc' },
          ],
        },
      ];
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      const body = JSON.stringify(gqlBody(res));
      expect((gqlBody(res).data?.['settlementCases'] as unknown[])[0]).toMatchObject({
        evidenceCount: 2,
      });
      expect(body).not.toMatch(/doc-secret-1|lexisnexis-abc|user-9/);
    });

    it('never ships decedentUserId or reportedBy to the browser', async () => {
      settlement.listResult = [
        {
          ...SETTLEMENT_CASE,
          decedentUserId: 'decedent-uuid-aaa',
          reportedBy: 'reporter-uuid-bbb',
        },
      ];
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      expect(JSON.stringify(gqlBody(res))).not.toMatch(/decedent-uuid-aaa|reporter-uuid-bbb/);
    });

    it('rejects an operation that even NAMES the dropped ids', async () => {
      // The absence is in the SDL, not in a resolver's discretion — so asking
      // for the field is a validation error, not an empty value.
      const res = await gql(
        app,
        { query: 'query Bad { settlementCases { caseId decedentUserId } }' },
        { cookie: COOKIE },
      );
      expect(JSON.stringify(gqlBody(res).errors)).toMatch(/decedentUserId/);
      expect(gqlBody(res).data).toBeFalsy();
    });
  });

  describe('voidable', () => {
    const OPEN = ['reported', 'verifying', 'waiting_period'];
    const CLOSED = ['verified', 'active', 'rejected_fraud'];

    it.each(OPEN)('offers the kill switch while a case is %s', async (status) => {
      settlement.listResult = [{ ...SETTLEMENT_CASE, decedentUserId: TOKENS.userId, status }];
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      const [row] = gqlBody(res).data?.['settlementCases'] as Array<Record<string, unknown>>;
      expect(row?.['voidable']).toBe(true);
    });

    it.each(CLOSED)('withdraws it once a case is %s', async (status) => {
      settlement.listResult = [{ ...SETTLEMENT_CASE, decedentUserId: TOKENS.userId, status }];
      const res = await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      const [row] = gqlBody(res).data?.['settlementCases'] as Array<Record<string, unknown>>;
      expect(row?.['voidable']).toBe(false);
    });

    it('covered both directions', () => {
      // Anti-vacuity: two `it.each` tables, and a suite where either had gone
      // empty would still be green.
      expect(OPEN).toHaveLength(3);
      expect(CLOSED).toHaveLength(3);
    });

    /**
     * THE COPY IS PINNED TO THE SERVICE. `VOIDABLE_STATUSES` in schema.ts
     * restates the three statuses `settlement.service.ts#void` accepts, because
     * apps/bff cannot import from a Nest service package. Nothing else compares
     * them — so if the service adds or removes a voidable status, this is what
     * says so, in the direction that matters: a status the service accepts and
     * this list omits HIDES A LIVE KILL SWITCH from the person it protects.
     *
     * Read the file, do not import it — the `error-codes.test.ts` mechanism.
     */
    it('matches the statuses the service itself accepts', () => {
      const service = readFileSync(
        join(__dirname, '..', '..', 'services', 'settlement', 'src', 'settlement.service.ts'),
        'utf8',
      );
      // Anchored on the void method's own guard, not on a loose status grep:
      // the file names these statuses in several places.
      const guard = /async void\([\s\S]*?markResolved\(\s*tx,\s*caseId,\s*\[([^\]]*)\]/.exec(
        service,
      );
      expect(guard).toBeTruthy();
      const serviceStatuses = [...(guard?.[1] ?? '').matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
      expect(serviceStatuses.length).toBeGreaterThan(0); // anti-vacuity
      expect(new Set(serviceStatuses)).toEqual(new Set(OPEN));

      const schema = readFileSync(join(__dirname, '..', 'src', 'schema.ts'), 'utf8');
      const declared = /const VOIDABLE_STATUSES: readonly string\[\] = \[([^\]]*)\]/.exec(schema);
      expect(declared).toBeTruthy();
      const bffStatuses = [...(declared?.[1] ?? '').matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
      expect(new Set(bffStatuses)).toEqual(new Set(serviceStatuses));
    });
  });

  describe('the void', () => {
    it('returns the resolved case with its resolution intact', async () => {
      // `resolution` is what the surface renders. The DDL forces a voided case
      // to carry status `rejected_fraud`, so dropping this field would leave
      // the UI announcing "fraud" to the person who just protected themselves.
      settlement.voidResult = {
        ...SETTLEMENT_CASE,
        decedentUserId: TOKENS.userId,
        status: 'rejected_fraud',
        resolution: 'owner_voided',
        resolvedAt: '2026-08-20T01:00:00.000Z',
      };
      const res = await gql(
        app,
        { query: VOID_MUTATION, variables: { caseId: SETTLEMENT_CASE.caseId } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).data?.['voidSettlementCase']).toMatchObject({
        status: 'rejected_fraud',
        resolution: 'owner_voided',
        voidable: false,
      });
    });

    it('surfaces the step-up refusal as a code the app can act on', async () => {
      const { bffError } = await import('../src/identity-client');
      settlement.settlementError = bffError('STEPUP_REQUIRED');
      const res = await gql(
        app,
        { query: VOID_MUTATION, variables: { caseId: SETTLEMENT_CASE.caseId } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('STEPUP_REQUIRED');
    });
  });

  describe('the caller must be identifiable', () => {
    /**
     * A dead-but-present access token makes `identity.session` answer null.
     * Carrying on would compare `undefined` against every `decedentUserId`,
     * decide no case is about the caller, and render an empty, reassuring page
     * to someone who may have a live case against them. Refusing is the only
     * safe answer.
     */
    it.each([
      ['the case list', CASES_QUERY, undefined],
      ['the kill switch', VOID_MUTATION, { caseId: SETTLEMENT_CASE.caseId }],
    ])('refuses %s when the session cannot be resolved', async (_name, query, variables) => {
      identity.sessionResult = null;
      const res = await gql(app, { query, variables }, { cookie: COOKIE });
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    });

    it('spends nothing downstream when the session is already dead', async () => {
      identity.sessionResult = null;
      await gql(app, { query: CASES_QUERY }, { cookie: COOKIE });
      expect(settlement.listCalls).toEqual([]);
    });
  });

  describe('settings', () => {
    it('reads and writes the waiting period', async () => {
      settlement.settingsResult = { waitingPeriodDays: 14 };
      const read = await gql(app, { query: SETTINGS_QUERY }, { cookie: COOKIE });
      expect(gqlBody(read).data?.['settlementSettings']).toEqual({ waitingPeriodDays: 14 });

      const write = await gql(
        app,
        { query: SET_PERIOD, variables: { days: 30 } },
        { cookie: COOKIE },
      );
      expect(gqlBody(write).data?.['setSettlementWaitingPeriod']).toEqual({
        waitingPeriodDays: 30,
      });
    });

    it('forwards an out-of-range value rather than second-guessing the service', async () => {
      // One validator, never two: settlement's zod restates the DDL's 5–60
      // CHECK. A range duplicated here is a range that drifts.
      await gql(app, { query: SET_PERIOD, variables: { days: 1 } }, { cookie: COOKIE });
      expect(settlement.updateSettingsCalls).toEqual([
        { accessToken: TOKENS.accessToken, waitingPeriodDays: 1 },
      ]);
    });

    it('keeps the frozen-window refusal distinct from bad input', async () => {
      const { bffError } = await import('../src/identity-client');
      settlement.settlementError = bffError('CASE_OPEN');
      const res = await gql(
        app,
        { query: SET_PERIOD, variables: { days: 30 } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('CASE_OPEN');
    });
  });

  /**
   * THE REPORTER'S SURFACE (M22 PR4c).
   *
   * Two services answer one query here and the join is where this goes wrong
   * quietly, so the assertions are about the SET rather than about a happy
   * row: settlement decides who may be reported on, profile only supplies a
   * name, and an estate must never disappear because the second one had
   * nothing to say about it.
   */
  describe('reportable estates', () => {
    beforeEach(() => {
      // Settlement's two rows; profile names only the FIRST. The fixture is
      // built to disagree, because two lists that agree cannot show which one
      // is the spine.
      profile.linkedEstatesResult = [
        {
          ownerUserId: 'user-1',
          contactId: 'contact-1',
          ownerName: 'Ada Lovelace',
          roles: ['executor', 'viewer'],
        },
      ];
    });

    it('takes the SET from settlement and the NAME from profile', async () => {
      const res = await gql(app, { query: REPORTABLE_QUERY }, { cookie: COOKIE });
      expect(gqlBody(res).data?.['reportableEstates']).toEqual([
        { contactId: 'contact-1', ownerName: 'Ada Lovelace', roles: ['executor', 'viewer'] },
        // Reportable, and nameless. Dropping it would hide an estate this
        // caller may genuinely report on because ITS OWNER never saved a
        // profile — somebody else's blank form deciding what this person sees.
        { contactId: 'contact-9', ownerName: null, roles: [] },
      ]);
    });

    it('carries no user id, on a list whose whole job is naming people', async () => {
      const res = await gql(app, { query: REPORTABLE_QUERY }, { cookie: COOKIE });
      const body = JSON.stringify(gqlBody(res).data);
      expect(body).not.toMatch(/user-1|user-9/);
      // Anti-vacuity: the ids ARE in the fixtures the resolver read, so their
      // absence is the projection working and not an empty answer.
      expect(settlement.reportableResult.map((e) => e.decedentUserId)).toEqual([
        'user-1',
        'user-9',
      ]);
      expect(body).toMatch(/contact-1/);
    });

    it('a failed profile read fails the query — a picker is not a place to guess', async () => {
      // A plain Error, because that is what an unreachable profile service
      // actually produces here — not a mapped BFF code.
      profile.profileError = new Error('profile unreachable');
      const res = await gql(app, { query: REPORTABLE_QUERY }, { cookie: COOKIE });
      expect(gqlBody(res).data?.['reportableEstates']).toBeFalsy();
      expect(gqlBody(res).errors).toBeDefined();
    });
  });

  describe('filing a report', () => {
    it('resolves the contact id to an estate and derives trusted_contact', async () => {
      const res = await gql(
        app,
        { query: REPORT_MUTATION, variables: { contactId: 'contact-9' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeUndefined();
      expect(settlement.reportCalls).toEqual([
        {
          accessToken: TOKENS.accessToken,
          decedentUserId: 'user-9',
          source: 'trusted_contact',
          evidence: [],
        },
      ]);
    });

    it('derives death_certificate_upload from the presence of a document', async () => {
      /*
       * The source is NOT a parameter. Settlement refuses
       * `death_certificate_upload` with no document, so the two facts imply
       * each other and deriving one from the other means they cannot
       * disagree — an argument that could only ever be wrong, removed.
       */
      await gql(
        app,
        {
          query: REPORT_MUTATION,
          variables: { contactId: 'contact-1', documentId: 'doc-1', documentVersion: 2 },
        },
        { cookie: COOKIE },
      );
      expect(settlement.reportCalls[0]).toMatchObject({
        decedentUserId: 'user-1',
        source: 'death_certificate_upload',
        evidence: [{ documentId: 'doc-1', version: 2 }],
      });
    });

    it('refuses a contact id that is not on the caller’s own list, with the uniform 404', async () => {
      const res = await gql(
        app,
        { query: REPORT_MUTATION, variables: { contactId: 'contact-nobody' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('NOT_FOUND');
      // AND IT NEVER REACHED SETTLEMENT. The check is the resolve-first
      // pattern, not a filter applied to an answer.
      expect(settlement.reportCalls).toEqual([]);
    });

    it('refuses a document id with no version rather than guessing version 1', async () => {
      const res = await gql(
        app,
        {
          query: REPORT_MUTATION,
          variables: { contactId: 'contact-1', documentId: 'doc-1' },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('INVALID_REQUEST');
      expect(settlement.reportCalls).toEqual([]);
    });

    it('is NOT step-up gated — the whole ordering of this milestone', async () => {
      /*
       * Filing ADDS scrutiny rather than authority: the case locks nothing,
       * the owner is notified on every channel and voids with one ungated
       * click. A gate here would fall on a grieving contact on a borrowed
       * device and stop nothing a token thief wants. Asserted with a session
       * that is authenticated and NOT step-up fresh, which is the state a
       * gate would refuse.
       */
      identity.sessionResult = {
        userId: TOKENS.userId,
        sessionId: TOKENS.sessionId,
        mfaLevel: 'mfa',
        stepupExpiresAt: null,
        audience: 'account',
      };
      const res = await gql(
        app,
        { query: REPORT_MUTATION, variables: { contactId: 'contact-1' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors).toBeUndefined();
      expect(settlement.reportCalls).toHaveLength(1);
    });
  });

  describe('attaching evidence', () => {
    it('sends the document and returns the case with the count grown', async () => {
      const res = await gql(
        app,
        {
          query: ATTACH_MUTATION,
          variables: { caseId: SETTLEMENT_CASE.caseId, documentId: 'doc-1', version: 2 },
        },
        { cookie: COOKIE },
      );
      expect(settlement.evidenceCalls).toEqual([
        {
          accessToken: TOKENS.accessToken,
          caseId: SETTLEMENT_CASE.caseId,
          evidence: { documentId: 'doc-1', version: 2 },
        },
      ]);
      expect(gqlBody(res).data?.['attachCaseEvidence']).toMatchObject({ evidenceCount: 1 });
    });

    it('surfaces the closed window as its own code, not as the kill switch’s', async () => {
      const { bffError } = await import('../src/identity-client');
      settlement.settlementError = bffError('EVIDENCE_WINDOW_CLOSED');
      const res = await gql(
        app,
        {
          query: ATTACH_MUTATION,
          variables: { caseId: SETTLEMENT_CASE.caseId, documentId: 'doc-1', version: 2 },
        },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('EVIDENCE_WINDOW_CLOSED');
    });
  });
});
