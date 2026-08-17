/**
 * The operator grant ceremony against REAL POSTGRES.
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM `operator-cli.spec.ts`. That one fakes
 * the repo, so it proves the ceremony's DECISIONS and can prove nothing about
 * the SQL: `grant`'s idempotence rides `ux_settlement_operators_active`, a
 * PARTIAL unique index, and a fake repo has no index to violate. This repo's
 * own record is that a defect living in a statement is only pinned by a test
 * that runs statements — the M13 contact-link fix passed its unit test with
 * the defect reintroduced, because a fake repo cannot see SQL.
 *
 * `settlement.int.spec.ts` seeds an operator with a raw INSERT and says in a
 * comment that the INSERT "is the ops-CLI write path". It never was. Nothing in
 * this repository had ever executed the CLI before M21 PR1.
 */
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { Client, type QueryResultRow } from 'pg';
import { Migrator } from '@estate/db';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AuditEmitter } from '@estate/audit-emitter';
import type { AuditEvent } from '@estate/contracts';
import { Db } from '../src/db';
import { OperatorsRepo } from '../src/operators.repo';
import { runOperatorCommand } from '../src/operator-cli';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

function migrationsDirOf(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'migrations');
}

describeIfPg('the operator ceremony against Postgres', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `operatorcli_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let producer: InMemoryAuditProducer;
  let emitter: AuditEmitter;
  const operators = new OperatorsRepo();
  const NOW = new Date('2026-08-17T12:00:00.000Z');

  const SUBJECT = randomUUID();
  const OTHER = randomUUID();
  const BY = randomUUID();

  /**
   * A POOLED handle, which is NOT how the CLI calls this — see `inTransaction`.
   * Kept for the cases where the transaction is irrelevant, and named so the
   * difference is visible rather than assumed away.
   */
  const deps = (): Parameters<typeof runOperatorCommand>[1] => ({
    db,
    operators,
    emitter,
    now: () => NOW,
  });

  /**
   * Run a command the way `main()` really does — inside one `BEGIN`/`COMMIT` on
   * a single connection.
   *
   * THIS EXISTS BECAUSE ITS ABSENCE HID A DEFECT. Every spec in this file
   * originally used the pooled handle above, where each statement gets its own
   * implicit transaction; the CLI wraps the whole command in one. Postgres
   * aborts a transaction on a failed statement and refuses everything after it,
   * so `grant`'s old catch-the-unique-violation recovery worked against a pool
   * and could not work inside the CLI — and a repeat grant died with `current
   * transaction is aborted` on the live stack while three green specs called it
   * a clean no-op. A harness more permissive than the production path is a
   * harness that agrees with itself, which is the shape this repo keeps finding
   * one layer beneath its fixtures.
   */
  async function inTransaction(command: Parameters<typeof runOperatorCommand>[0]): Promise<string> {
    const client = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await client.connect();
    try {
      await client.query('BEGIN');
      const line = await runOperatorCommand(command, {
        db: {
          query: async <T extends QueryResultRow>(text: string, values: unknown[] = []) =>
            (await client.query<T>(text, values)).rows,
        },
        operators,
        emitter,
        now: () => NOW,
      });
      await client.query('COMMIT');
      return line;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      await client.end();
    }
  }

  const events = (): AuditEvent[] =>
    producer.messages.map((m) => JSON.parse(m.value) as AuditEvent);

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // The admin connection's search_path is pinned so anything the DATABASE
    // resolves on its own behalf — a trigger body, a default expression —
    // stays inside the scratch schema. A schema prefix only scopes the
    // statements we write; the M20 PR4 lesson, applied from birth.
    await admin.query(`SET search_path = ${schema}`);

    for (const dir of [
      migrationsDirOf('@estate/service-profile'),
      join(__dirname, '..', 'migrations'),
    ]) {
      const client = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
      await client.connect();
      try {
        await new Migrator(client, dir).migrate();
      } finally {
        await client.end();
      }
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
    // TRUNCATE, not DELETE: it fires no row triggers, so a reset cannot write
    // anywhere the scratch schema does not reach.
    await admin.query(`TRUNCATE ${schema}.settlement_operators`);
    producer = new InMemoryAuditProducer();
    emitter = new AuditEmitter(producer, () => NOW);
  });

  it('THE ALLOWLIST HAS NO deleted_at, and is deliberately not an append-only table', async () => {
    // Two shape facts nothing pinned before M21 PR1, both load-bearing for what
    // "revoked" means. `settlement_cases`' equivalent absence IS hand-asserted
    // (a case is evidence, §5.1 c6) and this one was not, so a later edit
    // giving the allowlist soft-delete semantics would have passed every gate
    // while quietly creating a second way for a grant to stop existing.
    const { rows } = await admin.query(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = 'settlement_operators'
          AND column_name = 'deleted_at'`,
      [schema],
    );
    expect(rows).toHaveLength(0);

    // And the reason it is absent from `checkConventions`' appendOnlyTables,
    // recorded where somebody would go to "fix" that: revocation is an UPDATE
    // by design (the `permission_grants` shape), so the table is append+revoke
    // rather than append-only, and asserting PUBLIC holds no UPDATE grant would
    // be asserting a property it does not have.
    const revoke = await admin.query<{ id: string }>(
      `UPDATE ${schema}.settlement_operators SET revoked_at = now()
        WHERE user_id = $1 AND revoked_at IS NULL RETURNING id`,
      [randomUUID()],
    );
    expect(revoke.rows).toHaveLength(0);
  });

  it('GRANTS, and the row records WHO authorized it', async () => {
    // `granted_by` has been declared since M7 and written by nothing. This is
    // the assertion that stops being true if the ceremony is bypassed.
    const line = await runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, deps());
    expect(line).toBe(`granted: ${SUBJECT}\n`);

    const rows = await admin.query<{
      user_id: string;
      granted_by: string;
      revoked_at: Date | null;
    }>(`SELECT user_id, granted_by, revoked_at FROM ${schema}.settlement_operators`);
    expect(rows.rows).toEqual([{ user_id: SUBJECT, granted_by: BY, revoked_at: null }]);
    expect(await operators.isOperator(db, SUBJECT)).toBe(true);
  });

  it('EMITS a grant event naming the authorizer, whose resourceId is the real row', async () => {
    await runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, deps());
    const { rows } = await admin.query<{ id: string }>(
      `SELECT id FROM ${schema}.settlement_operators WHERE user_id = $1`,
      [SUBJECT],
    );

    expect(events()).toHaveLength(1);
    expect(events()[0]).toMatchObject({
      action: 'settlement.operator.granted',
      actorId: BY,
      actorType: 'operator',
      resourceType: 'settlement_operator',
      resourceId: (rows[0] as { id: string }).id,
      detail: { subject: SUBJECT, outcome: 'granted' },
    });
  });

  it('IS IDEMPOTENT AGAINST THE PARTIAL UNIQUE INDEX — a repeat is not a second grant', async () => {
    // The half a fake repo cannot reach: `ux_settlement_operators_active` is
    // what makes the second call a no-op, and the recovery path re-reads the
    // existing row so the event still names a resource.
    await inTransaction({ kind: 'grant', userId: SUBJECT, by: BY });
    const line = await inTransaction({ kind: 'grant', userId: SUBJECT, by: OTHER });

    expect(line).toBe(`already granted: ${SUBJECT}\n`);
    const { rows } = await admin.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM ${schema}.settlement_operators WHERE user_id = $1`,
      [SUBJECT],
    );
    expect((rows[0] as { count: string }).count).toBe('1');

    // Attribution is NOT overwritten by the second attempt: the original grant
    // stands, and the repeat is recorded as a repeat.
    const attributed = await admin.query<{ granted_by: string }>(
      `SELECT granted_by FROM ${schema}.settlement_operators WHERE user_id = $1`,
      [SUBJECT],
    );
    expect((attributed.rows[0] as { granted_by: string }).granted_by).toBe(BY);
    expect(events().map((e) => e.detail['outcome'])).toEqual(['granted', 'already_granted']);
  });

  it('REVOKES, and the revoked row stays as history rather than disappearing', async () => {
    // Append + revoke, no soft delete and no _versions table: the rows ARE the
    // history (the permission_grants precedent).
    await runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, deps());
    const line = await runOperatorCommand({ kind: 'revoke', userId: SUBJECT, by: BY }, deps());

    expect(line).toBe(`revoked: ${SUBJECT}\n`);
    expect(await operators.isOperator(db, SUBJECT)).toBe(false);
    const { rows } = await admin.query<{ revoked_at: Date | null }>(
      `SELECT revoked_at FROM ${schema}.settlement_operators WHERE user_id = $1`,
      [SUBJECT],
    );
    expect(rows).toHaveLength(1);
    expect((rows[0] as { revoked_at: Date | null }).revoked_at).toEqual(NOW);
  });

  it('A REVOKED USER CAN BE GRANTED AGAIN, because the index is partial', async () => {
    // If the index were unconditional this would fail, and an operator who
    // left and came back could never be re-granted.
    await runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, deps());
    await runOperatorCommand({ kind: 'revoke', userId: SUBJECT, by: BY }, deps());
    const line = await runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, deps());

    expect(line).toBe(`granted: ${SUBJECT}\n`);
    expect(await operators.isOperator(db, SUBJECT)).toBe(true);
    const { rows } = await admin.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM ${schema}.settlement_operators WHERE user_id = $1`,
      [SUBJECT],
    );
    expect((rows[0] as { count: string }).count).toBe('2');
  });

  it('revoking a user who is not an operator changes nothing and says so', async () => {
    const line = await runOperatorCommand({ kind: 'revoke', userId: OTHER, by: BY }, deps());
    expect(line).toBe(`no active grant: ${OTHER}\n`);
    expect(events()[0]).toMatchObject({
      action: 'settlement.operator.revoked',
      resourceId: null,
      detail: { outcome: 'no_active_grant' },
    });
  });

  it('lists active operators with their attribution, and a pre-ceremony row as unattributed', async () => {
    // A row written before M21 PR1 — or by anybody bypassing the ceremony —
    // carries granted_by NULL, and the listing must show that rather than
    // render it as blank.
    await runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, deps());
    await admin.query(
      `INSERT INTO ${schema}.settlement_operators (user_id, created_at) VALUES ($1, now() + interval '1 second')`,
      [OTHER],
    );

    // The grant above emitted, so "list emits nothing" is a statement about
    // the DELTA. Asserting an empty array here would pass only by accident of
    // ordering and would stop meaning anything the moment a case is reordered.
    const before = events().length;
    const line = await runOperatorCommand({ kind: 'list' }, deps());
    expect(line).toContain(`${SUBJECT}`);
    expect(line).toContain(`by ${BY}`);
    expect(line).toContain(`${OTHER}`);
    expect(line).toContain('by (unattributed)');
    expect(line).toContain('2 active operator(s)');
    expect(events()).toHaveLength(before);
  });
});
