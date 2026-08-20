/**
 * The distinct-estate counter against REAL POSTGRES.
 *
 * WHY THIS FILE EXISTS. The unit double in `support.ts` keeps a real per-
 * operator Set, so it proves the DECISIONS — which actions are counted, that
 * the warning is a warning — and can prove nothing about the statement. Three
 * things live only in the SQL and only Postgres can refuse them:
 *
 *   - `COUNT(DISTINCT case_id)`, not `COUNT(*)`. The whole bound is breadth,
 *     and a mutation to `COUNT(*)` leaves every unit test green while turning
 *     the control into a rate limit on doing one's job thoroughly.
 *   - The window predicate. An operator's work last month must not count
 *     against them today, and `>` versus `>=` on a boundary row is invisible
 *     to a fake that never carries a clock.
 *   - Per-operator scoping. A missing `operator_id = $1` would make every
 *     operator share one budget — the failure that looks exactly like the
 *     control working.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Client } from 'pg';
import { Migrator } from '@estate/db';
import { Db } from '../src/db';
import { OperatorActionsRepo } from '../src/operator-actions.repo';
import { OPERATOR_BREADTH_WINDOW_MS } from '../src/operator-breadth';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('the operator breadth counter, against Postgres', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `opbreadth_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  const actions = new OperatorActionsRepo();

  const NOW = new Date('2026-08-20T12:00:00.000Z');
  const OPERATOR = randomUUID();
  const OTHER_OPERATOR = randomUUID();

  const ago = (ms: number): Date => new Date(NOW.getTime() - ms);

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.query(`SET search_path = ${schema}`);
    const client = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await client.connect();
    try {
      await new Migrator(client, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await client.end();
    }
    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
  }, 120_000);

  afterAll(async () => {
    if (db) await db.onModuleDestroy();
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  beforeEach(async () => {
    await admin.query(`TRUNCATE ${schema}.settlement_operator_actions`);
  });

  const record = (operator: string, caseId: string, at: Date): Promise<void> =>
    db.withTransaction(operator, (tx) =>
      actions.record(tx, operator, caseId, 'stage.approved', at),
    );

  const count = (operator: string): Promise<number> =>
    actions.distinctCasesSince(db, operator, NOW);

  it('counts ESTATES, not actions', async () => {
    const oneCase = randomUUID();
    for (let i = 0; i < 5; i += 1) await record(OPERATOR, oneCase, ago(i * 1_000));
    // Five rows exist — the anti-vacuity floor for the assertion below, which
    // would also read 1 if nothing had been written at all.
    const rows = await db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n FROM settlement_operator_actions`,
    );
    expect(rows[0]?.n).toEqual('5');
    expect(await count(OPERATOR)).toEqual(1);
  });

  it('counts each distinct estate once', async () => {
    for (let i = 0; i < 4; i += 1) await record(OPERATOR, randomUUID(), ago(i * 1_000));
    expect(await count(OPERATOR)).toEqual(4);
  });

  it('gives every operator their OWN budget', async () => {
    for (let i = 0; i < 3; i += 1) await record(OTHER_OPERATOR, randomUUID(), ago(i * 1_000));
    await record(OPERATOR, randomUUID(), ago(1_000));
    // A dropped `operator_id = $1` reads as 4 here and as a working control
    // everywhere else.
    expect(await count(OPERATOR)).toEqual(1);
    expect(await count(OTHER_OPERATOR)).toEqual(3);
  });

  it('forgets work older than the window, and keeps work inside it', async () => {
    await record(OPERATOR, randomUUID(), ago(OPERATOR_BREADTH_WINDOW_MS + 1_000));
    expect(await count(OPERATOR)).toEqual(0);
    await record(OPERATOR, randomUUID(), ago(OPERATOR_BREADTH_WINDOW_MS - 1_000));
    expect(await count(OPERATOR)).toEqual(1);
  });

  it('answers 0 for an operator who has done nothing', async () => {
    expect(await count(randomUUID())).toEqual(0);
  });
});
