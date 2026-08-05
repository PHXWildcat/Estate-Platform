/**
 * Postgres-backed integration spec for the AI assistant service (M10 PR1).
 *
 * Gated exactly like every other integration suite: set PG_TEST_URL to run
 * (CI service container; locally e.g. postgres://estate:estate_dev@localhost:5541/core).
 * `test/ci-guard.spec.ts` is what stops that gate degrading into a silent skip
 * in CI.
 *
 * The suite runs THIS service's real migrations into a per-suite scratch schema
 * and drives the REAL repositories and the REAL @estate/crypto envelope stack
 * over them. Nothing here is a fake: every claim the migration and the repos
 * make about the database is settled by the database.
 *
 * Two conventions inherited from earlier milestones govern the queries below:
 *
 *  * EVERY catalog query filters on the scratch schema — `table_schema = $1`
 *    for information_schema, `pg_namespace.nspname = $1` when joining
 *    pg_trigger/pg_class. All suites share ONE database, so an unqualified
 *    catalog query happily reports another suite's identically-named table (the
 *    M6 lesson, restated in settlement.int.spec.ts). Here it would also see the
 *    `public`-schema copy of these very tables left by a manual migration run.
 *
 *  * DML goes through `db` (search_path pinned to the scratch schema), never
 *    through `admin`. The version-capture trigger inserts into
 *    `assistant_conversations_versions` unqualified, so an admin client sitting
 *    on `public` would resolve it to the wrong schema's shadow table — or 42P01
 *    inside the trigger before the constraint under test ever fires.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { FieldCrypto, LocalKmsProvider } from '@estate/crypto';
import { checkConventions, Migrator } from '@estate/db';
import { Client } from 'pg';
// Value imports, not `import type`: these are constructed here, and an
// `import type` erases at runtime (the consents.repo.ts note about Nest's
// design:paramtypes is the same rule seen from the other side).
import { ConsentsRepo } from '../src/consents.repo';
import { ConversationsRepo } from '../src/conversations.repo';
import { Db } from '../src/db';
import { PgAssistantDekRepository } from '../src/dek.repository';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

/**
 * The tables whose rows ARE the history: append-only turn log, append-only
 * tool-call record, and the conversations shadow table. PUBLIC must hold no
 * write grant on any of them (CLAUDE.md append-only audit rule; docs/02
 * conventions).
 */
const APPEND_ONLY = [
  'assistant_conversations_versions',
  'assistant_messages',
  'assistant_tool_calls',
] as const;

/**
 * Guard a single-row read. `noUncheckedIndexedAccess` makes `rows[0]`
 * `T | undefined`, and a thrown error here fails the test that asked for the
 * row — which is the honest outcome, since an empty result means the assertion
 * below it would have been vacuous.
 */
function only<T>(rows: readonly T[], what: string): T {
  const row = rows[0];
  if (row === undefined) {
    throw new Error(`expected a ${what} row, got none`);
  }
  return row;
}

describeIfPg('ai-assistant service against Postgres (core-cluster co-tenant)', () => {
  jest.setTimeout(120_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `aiassistantsvc_test_${Date.now()}`;
  const migrationsDir = join(__dirname, '..', 'migrations');

  let admin: Client;
  let db: Db;
  let fieldCrypto: FieldCrypto;
  let consents: ConsentsRepo;
  let conversations: ConversationsRepo;

  const OWNER = randomUUID();
  /** The owner's active DEK, minted through the real envelope path. */
  let ownerDekId: string;

  /** Column names of a table IN THIS SCHEMA. */
  const columnsOf = async (table: string): Promise<string[]> => {
    const { rows } = await admin.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        ORDER BY column_name`,
      [schema, table],
    );
    return rows.map((r) => r.column_name);
  };

  /** Non-internal trigger names on a table IN THIS SCHEMA (FK triggers excluded). */
  const triggersOn = async (table: string): Promise<string[]> => {
    const { rows } = await admin.query<{ tgname: string }>(
      `SELECT t.tgname FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relname = $2 AND NOT t.tgisinternal
        ORDER BY t.tgname`,
      [schema, table],
    );
    return rows.map((r) => r.tgname);
  };

  /** Table names from a candidate list that actually exist IN THIS SCHEMA. */
  const tablesPresent = async (candidates: readonly string[]): Promise<string[]> => {
    const { rows } = await admin.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables
        WHERE table_schema = $1 AND table_name = ANY($2)
        ORDER BY table_name`,
      [schema, [...candidates]],
    );
    return rows.map((r) => r.table_name);
  };

  /** A fresh live conversation owned by OWNER, through the real repository. */
  const newConversation = async (): Promise<string> => {
    const id = randomUUID();
    await conversations.create(db, id, OWNER);
    return id;
  };

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);

    // Migrations run on their OWN client whose search_path is the scratch
    // schema, so the DDL (and the CREATE OR REPLACE of the shared
    // set_updated_at function, which the three core co-tenants also define)
    // lands here and never touches public.
    const migrClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrClient.connect();
    try {
      const { applied } = await new Migrator(migrClient, migrationsDir).migrate();
      expect(applied).toEqual(['001_ai_assistant_schema.sql']);
    } finally {
      await migrClient.end();
    }

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    consents = new ConsentsRepo(db);
    conversations = new ConversationsRepo();
    fieldCrypto = new FieldCrypto(
      new LocalKmsProvider(randomBytes(32)),
      new PgAssistantDekRepository(db),
      () => {
        // Decrypt-audit sink. The unit suites assert its payload; what matters
        // here is that the envelope path works against real rows.
      },
      { kekAlias: 'ai-assistant/kek' },
    );

    ownerDekId = await fieldCrypto.getOrCreateDek(OWNER);
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  it('applies its migrations idempotently — a second run applies nothing', async () => {
    const client = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await client.connect();
    try {
      const { applied } = await new Migrator(client, migrationsDir).migrate();
      expect(applied).toEqual([]);
    } finally {
      await client.end();
    }
  });

  it('meets the docs/02 conventions for its business table and append-only stores', async () => {
    // assistant_conversations is the ONLY mutable business table this service
    // owns, so it is the only one that must carry the full soft-delete shape:
    // id/created_at/updated_at/deleted_at, both triggers, and a _versions
    // shadow with no PUBLIC write grant. assistant_consents and assistant_deks
    // are deliberately exempt and are asserted by hand in the two specs below —
    // an exemption that nothing checks is indistinguishable from an omission.
    const violations = await checkConventions(admin, {
      schema,
      businessTables: ['assistant_conversations'],
      appendOnlyTables: ['assistant_messages', 'assistant_tool_calls'],
    });
    expect(violations).toEqual([]);
  });

  it('exempts assistant_consents from soft delete and versioning, as permission_grants is', async () => {
    // profile's `permission_grants` precedent: a consent is an access record
    // that is REVOKED, never deleted, and the rows themselves are the history.
    // So: no deleted_at (revocation is revoked_at + revoked_by), no updated_at
    // (nothing about a grant is edited), no shadow table, and therefore neither
    // trigger — trg_assistant_consents_updated_at and
    // trg_assistant_consents_versions must both be absent.
    const columns = await columnsOf('assistant_consents');
    expect(columns).not.toContain('deleted_at');
    expect(columns).not.toContain('updated_at');
    // Anti-vacuity: a typo'd table name yields an empty column list, which
    // would pass every `not.toContain` above without checking anything.
    expect(columns).toContain('revoked_at');
    expect(columns).toContain('revoked_by');

    expect(await tablesPresent(['assistant_consents_versions'])).toEqual([]);
    expect(await triggersOn('assistant_consents')).toEqual([]);
  });

  it('exempts assistant_deks from soft delete and versioning, as every DEK table is', async () => {
    // Key metadata, not a business row: retirement is `destroyed_at` (the
    // crypto-shred), and a version shadow of a DEK table would preserve a
    // retired wrapping — exactly the attack asset the M6 review removed from
    // vault_keysets' captured image. No deleted_at, no updated_at, no shadow,
    // no triggers.
    const columns = await columnsOf('assistant_deks');
    expect(columns).not.toContain('deleted_at');
    expect(columns).not.toContain('updated_at');
    expect(columns).toContain('destroyed_at');
    expect(columns).toContain('wrapped_key');

    expect(await tablesPresent(['assistant_deks_versions'])).toEqual([]);
    expect(await triggersOn('assistant_deks')).toEqual([]);
  });

  it('grants PUBLIC no UPDATE or DELETE on the append-only and versions tables', async () => {
    // Append-only is enforced by the DATABASE, not by the absence of an update
    // method on a repository class (CLAUDE.md: audit tables REVOKE
    // UPDATE/DELETE). has_table_privilege cannot evaluate the PUBLIC
    // pseudo-role, so read the grants catalog directly — schema-filtered, or it
    // would answer about another suite's tables.
    expect(await tablesPresent(APPEND_ONLY)).toEqual([...APPEND_ONLY].sort());

    const { rows } = await admin.query<{ table_name: string; privilege_type: string }>(
      `SELECT table_name, privilege_type FROM information_schema.role_table_grants
        WHERE table_schema = $1 AND table_name = ANY($2)
          AND grantee = 'PUBLIC' AND privilege_type IN ('UPDATE','DELETE')
        ORDER BY table_name, privilege_type`,
      [schema, [...APPEND_ONLY]],
    );
    expect(rows).toEqual([]);
  });

  it('refuses a second active consent for the same scope', async () => {
    // ux_assistant_consents_user_scope_active is what makes "is this scope
    // granted?" a single unambiguous row: without it a revoke could leave a
    // shadow grant behind and the deny-by-default reading would be wrong.
    const user = randomUUID();
    await db.query(
      `INSERT INTO assistant_consents (user_id, scope, granted_by)
       VALUES ($1, 'assistant.assets', $1)`,
      [user],
    );
    await expect(
      db.query(
        `INSERT INTO assistant_consents (user_id, scope, granted_by)
         VALUES ($1, 'assistant.assets', $1)`,
        [user],
      ),
    ).rejects.toMatchObject({
      code: '23505',
      constraint: 'ux_assistant_consents_user_scope_active',
    });
  });

  it('refuses a revocation that names no revoker', async () => {
    // assistant_consents_revocation_pair: a revoked grant with no revoked_by is
    // an access record nobody is accountable for. The two columns travel
    // together or the row does not exist.
    const user = randomUUID();
    await db.query(
      `INSERT INTO assistant_consents (user_id, scope, granted_by)
       VALUES ($1, 'assistant.profile', $1)`,
      [user],
    );
    await expect(
      db.query(
        `UPDATE assistant_consents SET revoked_at = now()
          WHERE user_id = $1 AND scope = 'assistant.profile'`,
        [user],
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'assistant_consents_revocation_pair' });
  });

  it('refuses a scope outside the closed vocabulary', async () => {
    // The scope CHECK mirrors CONSENT_SCOPES in src/consent.ts. Each scope is a
    // distinct grant of a distinct slice of estate data to a third-party model
    // provider, so widening the set has to be a migration AND a code change —
    // the database refusing an unknown scope is the half a code review cannot
    // forget to do.
    await expect(
      db.query(
        `INSERT INTO assistant_consents (user_id, scope, granted_by)
         VALUES ($1, 'assistant.everything', $1)`,
        [randomUUID()],
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'assistant_consents_scope_check' });
  });

  it('accepts a re-grant once the previous grant is revoked', async () => {
    // The unique index is PARTIAL (WHERE revoked_at IS NULL) precisely so the
    // history accumulates: a user who revokes and later re-grants must end up
    // with two rows, one live, not with an index that refuses the second grant.
    const user = randomUUID();
    await db.query(
      `INSERT INTO assistant_consents (user_id, scope, granted_by)
       VALUES ($1, 'assistant.enabled', $1)`,
      [user],
    );
    await db.query(
      `UPDATE assistant_consents SET revoked_at = now(), revoked_by = $1
        WHERE user_id = $1 AND scope = 'assistant.enabled'`,
      [user],
    );
    await db.query(
      `INSERT INTO assistant_consents (user_id, scope, granted_by)
       VALUES ($1, 'assistant.enabled', $1)`,
      [user],
    );

    const { rows } = await admin.query<{ total: number; live: number }>(
      `SELECT count(*)::int AS total,
              count(*) FILTER (WHERE revoked_at IS NULL)::int AS live
         FROM ${schema}.assistant_consents WHERE user_id = $1`,
      [user],
    );
    expect(only(rows, 'consent count')).toEqual({ total: 2, live: 1 });
  });

  it('refuses a duplicate turn number within one conversation', async () => {
    // ux_assistant_messages_conversation_seq: seq is the transcript's spine, and
    // UNIQUE is what makes an interrupted retry idempotent — a re-sent turn
    // loses the insert race instead of duplicating itself into the model's
    // context.
    const conversationId = await newConversation();
    const insertTurn = (): Promise<unknown[]> =>
      db.query(
        `INSERT INTO assistant_messages (conversation_id, seq, role, content_ct, dek_id)
         VALUES ($1, 1, 'user', $2, $3)`,
        [conversationId, Buffer.from('ciphertext'), ownerDekId],
      );

    await insertTurn();
    await expect(insertTurn()).rejects.toMatchObject({
      code: '23505',
      constraint: 'ux_assistant_messages_conversation_seq',
    });
  });

  it('refuses a message role outside user and assistant', async () => {
    // The role CHECK mirrors MessageRole in src/messages.repo.ts. A row
    // labelled anything else would be a turn whose provenance the transcript
    // cannot state, and the transcript is the only record of what the assistant
    // was asked and what it answered.
    const conversationId = await newConversation();
    await expect(
      db.query(
        `INSERT INTO assistant_messages (conversation_id, seq, role, content_ct, dek_id)
         VALUES ($1, 1, 'system', $2, $3)`,
        [conversationId, Buffer.from('ciphertext'), ownerDekId],
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'assistant_messages_role_check' });
  });

  it('refuses a denied tool call that still carries a result', async () => {
    // assistant_tool_calls_refusal_is_empty. Without it a refusal could still
    // ship retrieved content: the outcome column would say the consent control
    // fired while the row itself proved it had not. dek_id is supplied here so
    // the result-pair CHECK is satisfied and this assertion can only be failing
    // for the reason it names.
    const conversationId = await newConversation();
    await expect(
      db.query(
        `INSERT INTO assistant_tool_calls
           (conversation_id, tool_name, scope, outcome, result_ct, dek_id)
         VALUES ($1, 'estate.net_worth', 'assistant.assets', 'denied_no_consent', $2, $3)`,
        [conversationId, Buffer.from('retrieved-estate-content'), ownerDekId],
      ),
    ).rejects.toMatchObject({
      code: '23514',
      constraint: 'assistant_tool_calls_refusal_is_empty',
    });
  });

  it('refuses a tool result whose key reference is missing', async () => {
    // assistant_tool_calls_result_pair: ciphertext and the dek_id that can open
    // it travel together, or the crypto-shred sweep has bytes it cannot account
    // for. outcome is 'ok' here so the refusal-is-empty CHECK is satisfied and
    // only the pair CHECK can fire.
    const conversationId = await newConversation();
    await expect(
      db.query(
        `INSERT INTO assistant_tool_calls (conversation_id, tool_name, scope, outcome, result_ct)
         VALUES ($1, 'estate.net_worth', 'assistant.assets', 'ok', $2)`,
        [conversationId, Buffer.from('retrieved-estate-content')],
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'assistant_tool_calls_result_pair' });
  });

  it('accepts a refusal recorded with no ciphertext at all', async () => {
    // The positive half of the two CHECKs above: a control firing must be
    // RECORDABLE as loudly as a success (the M9 rule that a refused request
    // audits its refusal), so a denial with a null result and a null dek_id has
    // to land.
    const conversationId = await newConversation();
    await db.query(
      `INSERT INTO assistant_tool_calls (conversation_id, tool_name, scope, outcome)
       VALUES ($1, 'documents.content', 'assistant.documents.content', 'denied_no_consent')`,
      [conversationId],
    );

    const { rows } = await admin.query<{ outcome: string; result_ct: Buffer | null }>(
      `SELECT outcome, result_ct FROM ${schema}.assistant_tool_calls WHERE conversation_id = $1`,
      [conversationId],
    );
    expect(only(rows, 'tool call')).toEqual({ outcome: 'denied_no_consent', result_ct: null });
  });

  it('converges on one DEK when concurrent first-writes race the insert', async () => {
    // The M6 DEK-race rule, end to end against the REAL partial unique index:
    // several first-writes for a user with no key all read "no active DEK",
    // all mint one, and exactly one INSERT wins. The losers see 23505,
    // PgAssistantDekRepository translates it to DekConflictError, and
    // @estate/crypto adopts the winner rather than leaving the user with two
    // active keys — which would mean ciphertext readable only under whichever
    // key happened to be picked at write time.
    //
    // THE POOL MUST BE WARMED FIRST, or this test proves nothing. `pool.query`
    // dispatches instantly on an idle connection but has to complete a TCP +
    // auth handshake when it opens a new one, so from a cold pool the first
    // caller finishes its INSERT while the others are still connecting; they
    // then read the winner and the assertions below pass with the unique index
    // deleted. Measured: cold ⇒ 1 row either way, warmed ⇒ 6 rows once the
    // index is removed. Warming makes every racer start from an idle client, so
    // all six SELECTs are in flight before any INSERT and the index is the only
    // thing standing between them and six active keys.
    const RACERS = 6;
    await Promise.all(Array.from({ length: RACERS }, () => db.query('SELECT 1')));

    const racer = randomUUID();
    const dekIds = await Promise.all(
      Array.from({ length: RACERS }, () => fieldCrypto.getOrCreateDek(racer)),
    );

    expect(new Set(dekIds).size).toBe(1);
    const { rows } = await admin.query<{ dek_id: string }>(
      `SELECT dek_id FROM ${schema}.assistant_deks
        WHERE user_id = $1 AND destroyed_at IS NULL`,
      [racer],
    );
    expect(rows).toHaveLength(1);
    expect(only(rows, 'active dek').dek_id).toBe(dekIds[0]);

    // And it is wrapped under this service's OWN alias: a core-cluster
    // co-tenant with SELECT on this table still holds no KMS grant that can
    // unwrap what it reads (docs/03 §5.3).
    const { rows: aliases } = await admin.query<{ kek_alias: string }>(
      `SELECT kek_alias FROM ${schema}.assistant_deks WHERE user_id = $1`,
      [racer],
    );
    expect(only(aliases, 'dek alias').kek_alias).toBe('ai-assistant/kek');
  });

  it('round-trips a grant, an idempotent re-grant and a revoke through ConsentsRepo', async () => {
    const user = randomUUID();

    const granted = await db.withTransaction(user, (tx) =>
      consents.grant(tx, user, 'assistant.enabled', user),
    );
    expect(granted).toBe(true);
    await expect(consents.grantedScopes(user)).resolves.toEqual(new Set(['assistant.enabled']));

    // ON CONFLICT ... DO NOTHING over the partial unique index: a re-grant of a
    // live scope creates no second row and reports false, because a no-op is
    // not a consent change and must not be audited as one.
    const again = await db.withTransaction(user, (tx) =>
      consents.grant(tx, user, 'assistant.enabled', user),
    );
    expect(again).toBe(false);
    const { rows: counts } = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM ${schema}.assistant_consents WHERE user_id = $1`,
      [user],
    );
    expect(only(counts, 'consent count').n).toBe(1);

    // Revocation removes the scope from the answer entirely — a revoked row and
    // a row that never existed are the same empty set (deny by default is the
    // shape of the query, not a flag on top of it).
    const revoked = await db.withTransaction(user, (tx) =>
      consents.revoke(tx, user, 'assistant.enabled', user),
    );
    expect(revoked).toBe(true);
    await expect(consents.grantedScopes(user)).resolves.toEqual(new Set());
    await expect(
      db.withTransaction(user, (tx) => consents.revoke(tx, user, 'assistant.enabled', user)),
    ).resolves.toBe(false);
  });

  it('captures a soft delete in the versions table, attributed to the GUC actor', async () => {
    // No hard deletes anywhere (CLAUDE.md): retiring a conversation is an
    // UPDATE, the row survives, and the BEFORE UPDATE trigger captures the
    // PRIOR image. `withTransaction` is the only place app.actor_id is set, so
    // this also proves attribution flows from the service's one transaction
    // chokepoint into the trigger — a version row with a null actor is a change
    // nobody is accountable for.
    const conversationId = await newConversation();
    const removed = await db.withTransaction(OWNER, (tx) =>
      conversations.softDelete(tx, conversationId, OWNER),
    );
    expect(removed).toBe(true);

    const { rows } = await admin.query<{
      operation: string;
      actor_id: string | null;
      row_data: { deleted_at: string | null; user_id: string };
    }>(
      `SELECT operation, actor_id, row_data FROM ${schema}.assistant_conversations_versions
        WHERE row_id = $1 ORDER BY version_seq`,
      [conversationId],
    );
    expect(rows).toHaveLength(1);
    const captured = only(rows, 'captured version');
    expect(captured.operation).toBe('UPDATE');
    expect(captured.actor_id).toBe(OWNER);
    // The captured image is the row BEFORE the change: still live.
    expect(captured.row_data.deleted_at).toBeNull();
    expect(captured.row_data.user_id).toBe(OWNER);

    // The live row is soft-deleted, not gone — the ciphertext survives, and
    // only crypto-shredding the owner's DEK actually erases a transcript.
    const { rows: live } = await admin.query<{ deleted_at: Date | null }>(
      `SELECT deleted_at FROM ${schema}.assistant_conversations WHERE id = $1`,
      [conversationId],
    );
    expect(only(live, 'conversation').deleted_at).not.toBeNull();
  });
});
