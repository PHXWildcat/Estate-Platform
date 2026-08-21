import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { INestApplication } from '@nestjs/common';
import { ACCESS_COOKIE } from '../src/cookies';
import { bffError } from '../src/identity-client';
import { FakeIdentityClient, FakeSettlementClient, TOKENS, gql, gqlBody, makeApp } from './helpers';

/**
 * THE DISTRIBUTIONS EDGE (M23 PR4b).
 *
 * Three properties carry this file.
 *
 * The FIRST is that NO ACTOR ID reaches the browser. The service's shape
 * carries `createdBy` (the recorder) and `approvedBy` (the operator who
 * cleared the payment), and this is the type where dropping them is most
 * tempting to undo — "who approved it" reads like a reasonable thing to show.
 * It would put a staff member's id in a grieving family member's browser.
 *
 * The SECOND is that AN AMOUNT IS NEVER A LIST FIELD. Revealing one is an
 * audited decrypt on the decedent's own DEK and emits an event on their trail,
 * so it is a per-row act behind its own query. A field on `EstateDistribution`
 * would make every page load spend one per row for a question nobody asked.
 *
 * The THIRD is that the schema OFFERS ONLY WHAT THE SERVER WOULD ALLOW.
 * `approved` is an operator's act under dual control and `planned` is where a
 * distribution starts; neither is in the status enum, so the browser cannot
 * ask for a transition that would be refused — the absence-over-filter rule
 * applied to a vocabulary.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;

const LIST_QUERY = `query EstateDistributions($caseId: ID!) {
  estateDistributions(caseId: $caseId) {
    distributionId beneficiaryContactId assetId status approvedAt hasAmount createdAt
  }
}`;
const AMOUNT_QUERY = `query EstateDistributionAmount($distributionId: ID!) {
  estateDistributionAmount(distributionId: $distributionId) { distributionId amount }
}`;
const RECORD_MUTATION = `mutation RecordEstateDistribution(
  $caseId: ID!, $beneficiaryContactId: ID!, $assetId: ID, $amount: String
) {
  recordEstateDistribution(
    caseId: $caseId
    beneficiaryContactId: $beneficiaryContactId
    assetId: $assetId
    amount: $amount
  ) { distributionId status hasAmount assetId }
}`;
const STATUS_MUTATION = `mutation SetEstateDistributionStatus(
  $distributionId: ID!, $status: EstateDistributionStatusChange!
) {
  setEstateDistributionStatus(distributionId: $distributionId, status: $status) {
    distributionId status
  }
}`;

/**
 * THE STATUS VOCABULARY IS DERIVED FROM THE DDL, NOT RESTATED.
 *
 * The migration's CHECK constraint is what the RUNTIME reads — a status the
 * database refuses is a status no service-layer list can make legal — so it is
 * the anchor rather than `DistributionStatus` in the repo, which is a TypeScript
 * type a rename could quietly desynchronise.
 *
 * AND THE CLAIM IS ABOUT THE WHOLE VOCABULARY, not about the three members the
 * SDL happens to declare. Every status the DDL allows is accounted for as
 * either executor-reachable or not; a sixth added to the CHECK turns this red
 * and forces somebody to say which side it lands on. Asserting only that the
 * SDL's three exist would stay green through exactly that change, which is the
 * hand-maintained-list defect wearing a fence's clothes.
 */
describe('the EstateDistributionStatusChange enum accounts for the DDL’s whole vocabulary', () => {
  const SCHEMA = join(__dirname, '..', 'src', 'schema.ts');
  const MIGRATION = join(
    __dirname,
    '..',
    '..',
    'services',
    'settlement',
    'migrations',
    '002_settlement_admin.sql',
  );

  /** Every status the `distributions` CHECK constraint admits. */
  function ddlStatuses(): string[] {
    const sql = readFileSync(MIGRATION, 'utf8');
    const table = /CREATE TABLE distributions \(([\s\S]*?)\n\);/.exec(sql);
    // Anti-vacuity: an anchor that stopped matching would slice to nothing and
    // make every comparison below compare two empty lists.
    expect(table?.[1]?.length ?? 0).toBeGreaterThan(200);
    const check =
      /status TEXT NOT NULL DEFAULT 'planned'\s*\n?\s*CHECK \(status IN \(([^)]*)\)\)/.exec(
        table?.[1] ?? '',
      );
    expect(check?.[1]).toBeTruthy();
    return [...(check?.[1] ?? '').matchAll(/'([a-z_]+)'/g)].map((m) => m[1] as string);
  }

  function sdlEnumMembers(name: string): string[] {
    const source = readFileSync(SCHEMA, 'utf8');
    const sdl = /export const typeDefs = \/\* GraphQL \*\/ `([\s\S]*?)\n`;/.exec(source);
    expect(sdl?.[1]?.length ?? 0).toBeGreaterThan(1000);
    const block = new RegExp(`enum ${name} \\{([^}]*)\\}`).exec(sdl?.[1] ?? '');
    expect(block?.[1]).toBeTruthy();
    return (block?.[1] ?? '')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => /^[A-Z_]+$/.test(line));
  }

  /**
   * The two the EXECUTOR may never set, and why each is here:
   *  - 'planned' is where every distribution STARTS. It is a default, not a
   *    move, and offering it would let a screen try to un-approve one.
   *  - 'approved' is the OPERATOR's act under dual control (docs/02 §7), and a
   *    DDL CHECK forbids the approver being the recorder. An executor asking
   *    for it is asking to approve their own payment.
   */
  const NOT_THE_EXECUTORS = ['planned', 'approved'];

  it('splits the DDL’s statuses into what an executor may set and what they may not', () => {
    const ddl = ddlStatuses();
    expect(ddl).toContain('planned');
    expect(ddl.length).toBeGreaterThanOrEqual(5);

    const offered = sdlEnumMembers('EstateDistributionStatusChange').map((m) => m.toLowerCase());
    // SETS, not counts: a member mis-attributed from one side to the other
    // preserves both lengths.
    expect([...offered, ...NOT_THE_EXECUTORS].sort()).toEqual([...ddl].sort());
    // ...and the two halves are disjoint, so nothing is counted twice into an
    // accidental agreement.
    expect(offered.filter((s) => NOT_THE_EXECUTORS.includes(s))).toEqual([]);
  });

  it('never offers the operator’s own act', () => {
    // The property the split exists for, asserted directly: dual control is
    // not something the browser can ask for.
    expect(sdlEnumMembers('EstateDistributionStatusChange')).not.toContain('APPROVED');
  });
});

describe('distribution resolvers', () => {
  let app: INestApplication;
  let settlement: FakeSettlementClient;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    settlement = new FakeSettlementClient();
    identity = new FakeIdentityClient();
    identity.sessionResult = {
      userId: TOKENS.userId,
      sessionId: TOKENS.sessionId,
      mfaLevel: 'stepup',
      stepupExpiresAt: '2099-01-01T00:00:00.000Z',
      audience: 'account',
    };
    app = await makeApp({ settlement, identity });
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

  describe('the list', () => {
    it('is scoped to the case, and carries NO actor id and NO amount', async () => {
      const res = await gql(
        app,
        { query: LIST_QUERY, variables: { caseId: 'case-1' } },
        { cookie: COOKIE },
      );
      expect(settlement.distributionsCalls).toEqual([
        { accessToken: TOKENS.accessToken, caseId: 'case-1' },
      ]);
      const list = rows(res, 'estateDistributions');
      expect(list.map((r) => r['distributionId'])).toEqual(['dist-1', 'dist-2']);

      /*
       * ASSERTED ON THE SERIALISED BODY, because a field absent from the
       * query's selection set proves nothing about whether the type could
       * carry it — the distinction this repo's projections turn on.
       */
      const body = JSON.stringify(list);
      expect(body).not.toContain('createdBy');
      expect(body).not.toContain('approvedBy');
      expect(body).not.toContain('amount');
      // ...and no amount was READ to produce the list.
      expect(settlement.amountCalls).toEqual([]);
    });

    it('says an unapproved row is unapproved, and a row with no sum has none', async () => {
      const list = rows(
        await gql(app, { query: LIST_QUERY, variables: { caseId: 'case-1' } }, { cookie: COOKIE }),
        'estateDistributions',
      );
      // Two arms a surface is likely to flatten: 'planned' is the dual-control
      // gate still shut, and `hasAmount: false` is a real state rather than a
      // missing field.
      expect(list[0]).toMatchObject({ status: 'planned', approvedAt: null, hasAmount: true });
      expect(list[1]).toMatchObject({ status: 'approved', hasAmount: false, assetId: 'asset-1' });
    });

    it('does NOT resolve the case id first — settlement owns who may read them', async () => {
      // `assertCaseVisible` admits the decedent's own reader, the reporter, the
      // executor and an operator. A resolve-first check here would refuse three
      // of the four, the same argument the ladder and the checklist make.
      await gql(app, { query: LIST_QUERY, variables: { caseId: 'case-1' } }, { cookie: COOKIE });
      expect(settlement.executorCasesCalls).toEqual([]);
    });
  });

  describe('one revealed amount', () => {
    it('is its OWN query, and returns the decimal as a string', async () => {
      const res = await gql(
        app,
        { query: AMOUNT_QUERY, variables: { distributionId: 'dist-1' } },
        { cookie: COOKIE },
      );
      expect(settlement.amountCalls).toEqual([
        { accessToken: TOKENS.accessToken, distributionId: 'dist-1' },
      ]);
      // EXACTLY, and as a string. A Float on this path returns
      // '1000000000000000' — a cent light and rounded to a figure nobody
      // recorded.
      expect(gqlBody(res).data?.['estateDistributionAmount']).toEqual({
        distributionId: 'dist-1',
        amount: '999999999999999.99',
      });
    });

    it('answers null for a distribution that names an asset rather than a sum', async () => {
      const res = await gql(
        app,
        { query: AMOUNT_QUERY, variables: { distributionId: 'dist-2' } },
        { cookie: COOKIE },
      );
      // An ANSWER, not a refusal — and it arrives without an error, which is
      // the whole distinction.
      expect(gqlBody(res).errors).toBeUndefined();
      expect(gqlBody(res).data?.['estateDistributionAmount']).toEqual({
        distributionId: 'dist-2',
        amount: null,
      });
    });

    it('renders a crypto-shredded estate as PERMANENT, never as a retry', async () => {
      settlement.settlementError = bffError('CONTENT_ERASED');
      const res = await gql(
        app,
        { query: AMOUNT_QUERY, variables: { distributionId: 'dist-1' } },
        { cookie: COOKIE },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('CONTENT_ERASED');
    });

    it('spends nothing until it is asked — no amount is read while listing', async () => {
      await gql(app, { query: LIST_QUERY, variables: { caseId: 'case-1' } }, { cookie: COOKIE });
      expect(settlement.amountCalls).toEqual([]);
      // Positive control: the amount query DOES reach settlement, so the
      // assertion above is about the list and not about a silent double.
      await gql(
        app,
        { query: AMOUNT_QUERY, variables: { distributionId: 'dist-1' } },
        { cookie: COOKIE },
      );
      expect(settlement.amountCalls).toHaveLength(1);
    });
  });

  describe('recording one', () => {
    it('forwards the amount as the STRING it arrived as', async () => {
      const res = await gql(
        app,
        {
          query: RECORD_MUTATION,
          variables: {
            caseId: 'case-1',
            beneficiaryContactId: 'contact-1',
            amount: '999999999999999.99',
          },
        },
        { cookie: COOKIE },
      );
      expect(settlement.recordDistributionCalls).toEqual([
        {
          accessToken: TOKENS.accessToken,
          caseId: 'case-1',
          input: { beneficiaryContactId: 'contact-1', amount: '999999999999999.99' },
        },
      ]);
      // A new distribution is PLANNED. The mutation records; it never approves.
      expect(gqlBody(res).data?.['recordEstateDistribution']).toMatchObject({
        status: 'planned',
        hasAmount: true,
      });
    });

    /**
     * NULL AND OMITTED ARE THE SAME REQUEST.
     *
     * GraphQL hands an omitted nullable argument through as `undefined` and an
     * explicit `null` as `null`. Settlement parses this body with `.strict()`
     * against `assetId: z.string().uuid().optional()`, which REFUSES an
     * explicit null — so forwarding one would turn "no asset named", the
     * commonest case there is, into INVALID_REQUEST.
     */
    it('drops a null assetId rather than forwarding it into a strict parser', async () => {
      await gql(
        app,
        {
          query: RECORD_MUTATION,
          variables: {
            caseId: 'case-1',
            beneficiaryContactId: 'contact-1',
            assetId: null,
            amount: null,
          },
        },
        { cookie: COOKIE },
      );
      const input = settlement.recordDistributionCalls[0]?.input;
      expect(input).toEqual({ beneficiaryContactId: 'contact-1' });
      expect(Object.keys(input ?? {})).not.toContain('assetId');
      expect(Object.keys(input ?? {})).not.toContain('amount');
    });

    it('passes an asset id through when one IS named', async () => {
      // Positive control for the test above: the key is dropped because it was
      // null, not because this resolver never sends it.
      await gql(
        app,
        {
          query: RECORD_MUTATION,
          variables: {
            caseId: 'case-1',
            beneficiaryContactId: 'contact-1',
            assetId: 'asset-7',
          },
        },
        { cookie: COOKIE },
      );
      expect(settlement.recordDistributionCalls[0]?.input).toEqual({
        beneficiaryContactId: 'contact-1',
        assetId: 'asset-7',
      });
    });
  });

  describe('moving one on', () => {
    /**
     * THE ENUM GOES DOWN TO THE SERVICE'S OWN SPELLING.
     *
     * GraphQL serialises an enum as its member NAME, so this argument arrives
     * as 'IN_PROGRESS' and the DDL's value is 'in_progress'. Sending the name
     * through unchanged would be refused by the service's `z.enum` at the last
     * moment — the M20 PR1 `MfaLevel` defect, one layer down.
     */
    it('sends the DDL’s value, not the enum member name', async () => {
      await gql(
        app,
        {
          query: STATUS_MUTATION,
          variables: { distributionId: 'dist-2', status: 'IN_PROGRESS' },
        },
        { cookie: COOKIE },
      );
      expect(settlement.distributionStatusCalls).toEqual([
        { accessToken: TOKENS.accessToken, distributionId: 'dist-2', status: 'in_progress' },
      ]);
    });

    it('refuses a status the executor may not set, before it reaches settlement', async () => {
      const res = await gql(
        app,
        { query: STATUS_MUTATION, variables: { distributionId: 'dist-1', status: 'APPROVED' } },
        { cookie: COOKIE },
      );
      // The schema itself is the refusal — dual control is not reachable from a
      // browser, so the call never happens rather than being rejected later.
      expect(gqlBody(res).errors?.length).toBeGreaterThan(0);
      expect(settlement.distributionStatusCalls).toEqual([]);
    });

    it('surfaces the dual-control refusal as its own code', async () => {
      settlement.settlementError = bffError('DISTRIBUTION_NOT_APPROVED');
      const res = await gql(
        app,
        {
          query: STATUS_MUTATION,
          variables: { distributionId: 'dist-1', status: 'COMPLETED' },
        },
        { cookie: COOKIE },
      );
      // NOT a generic conflict: the remedy is a second person, and "reload and
      // try again" would send an executor round a loop with no exit.
      expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('DISTRIBUTION_NOT_APPROVED');
    });
  });
});
