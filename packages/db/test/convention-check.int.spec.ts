/**
 * Integration tests for the schema-convention checker, using the same
 * widgets fixture as the migrator tests. Gated on PG_TEST_URL.
 */
import { Client } from 'pg';
import {
  softDeleteUniqueIndexSql,
  updatedAtFunctionSql,
  updatedAtTriggerSql,
  versionsTableSql,
} from '../src/conventions';
import { checkConventions } from '../src/convention-check';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('checkConventions against Postgres', () => {
  let client: Client;
  const schema = `conv_test_${Date.now()}`;

  beforeAll(async () => {
    client = new Client({ connectionString: process.env['PG_TEST_URL'] });
    await client.connect();
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`SET search_path TO ${schema}`);
    await client.query(`
      ${updatedAtFunctionSql()}
      CREATE TABLE widgets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL, email_bidx BYTEA,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        deleted_at TIMESTAMPTZ
      );
      ${updatedAtTriggerSql('widgets')}
      ${versionsTableSql('widgets')}
      ${softDeleteUniqueIndexSql('widgets', ['email_bidx'])}
      CREATE TABLE naked (id UUID PRIMARY KEY, name TEXT);
    `);
  });

  afterAll(async () => {
    await client.query(`DROP SCHEMA ${schema} CASCADE`);
    await client.end();
  });

  it('passes a table built with the convention generators', async () => {
    await expect(
      checkConventions(client, { schema, businessTables: ['widgets'] }),
    ).resolves.toEqual([]);
  });

  it('reports every missing convention on a bare table', async () => {
    const violations = await checkConventions(client, { schema, businessTables: ['naked'] });
    expect(violations).toEqual(
      expect.arrayContaining([
        expect.stringContaining("missing convention column 'created_at'"),
        expect.stringContaining("missing convention column 'updated_at'"),
        expect.stringContaining("missing convention column 'deleted_at'"),
        expect.stringContaining('missing versions shadow table'),
        expect.stringContaining('trg_naked_updated_at'),
        expect.stringContaining('trg_naked_versions'),
      ]),
    );
  });

  it('flags PUBLIC write grants on append-only tables', async () => {
    await client.query(`CREATE TABLE eventsish (seq BIGINT); GRANT UPDATE ON eventsish TO PUBLIC`);
    const violations = await checkConventions(client, { schema, appendOnlyTables: ['eventsish'] });
    expect(violations).toEqual([expect.stringContaining('PUBLIC holds UPDATE grant')]);
  });
});
