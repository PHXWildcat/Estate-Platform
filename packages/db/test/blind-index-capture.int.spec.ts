/**
 * THE BLIND-INDEX REDACTION, PROVED BY EXECUTION (M25 PR1).
 *
 * Everything under test here lives in a plpgsql trigger body, so a faked client
 * could not get it wrong and therefore could not prove it right — the M13 rule.
 * Three properties, each a way this could be present and wrong:
 *
 *  1. THE CAPTURE DROPS THE BLIND INDEX. A real UPDATE, and the row image that
 *     lands in the shadow table carries no `*_bidx` key.
 *  2. IT DROPS NOTHING ELSE. A redaction that swallowed the ciphertext or the
 *     actor would satisfy (1) and destroy the reason the trigger exists. This
 *     is the assertion that fails if the key-subtraction is over-broad.
 *  3. THE DETECTOR DISCRIMINATES. `blindIndexCaptureGaps` reports nothing on a
 *     redacting schema — which is also what it reports on a schema it cannot
 *     see. So the same detector is pointed at a table deliberately left with
 *     the OLD capture body, and must NAME it.
 */
import { randomUUID } from 'node:crypto';
import { Client } from 'pg';
import { blindIndexCaptureCorpus, blindIndexCaptureGaps } from '../src/blind-index-capture';
import { updatedAtFunctionSql, updatedAtTriggerSql, versionsTableSql } from '../src/conventions';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('version captures drop blind indexes', () => {
  let client: Client;
  const schema = `bidxcap_test_${Date.now()}`;

  beforeAll(async () => {
    client = new Client({ connectionString: process.env['PG_TEST_URL'] });
    await client.connect();
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`SET search_path TO ${schema}`);
    await client.query(`
      ${updatedAtFunctionSql()}
      CREATE TABLE widgets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        secret_ct BYTEA,
        email_bidx BYTEA,
        phone_bidx BYTEA,
        dek_id UUID,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        deleted_at TIMESTAMPTZ
      );
      ${updatedAtTriggerSql('widgets')}
      ${versionsTableSql('widgets')}
    `);

    // THE NEGATIVE CONTROL, deliberately left on the pre-M25 capture body: a
    // blind index, a shadow that captures it, and no redaction. The detector
    // must name this table while passing every other.
    await client.query(`
      CREATE TABLE legacy (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email_bidx BYTEA
      );
      ${versionsTableSql('legacy')}
      CREATE OR REPLACE FUNCTION legacy_capture_version() RETURNS trigger AS $$
      BEGIN
        INSERT INTO legacy_versions (row_id, operation, row_data, actor_id, reason)
        VALUES (OLD.id, TG_OP, to_jsonb(OLD), NULL, NULL);
        RETURN COALESCE(NEW, OLD);
      END;
      $$ LANGUAGE plpgsql;
    `);
  });

  afterAll(async () => {
    await client.query(`DROP SCHEMA ${schema} CASCADE`);
    await client.end();
  });

  it('drops every blind index from the captured image, and nothing else', async () => {
    const id = randomUUID();
    const dek = randomUUID();
    await client.query(
      `INSERT INTO widgets (id, title, secret_ct, email_bidx, phone_bidx, dek_id)
       VALUES ($1, 'before', $2, $3, $4, $5)`,
      [id, Buffer.from('ciphertext'), Buffer.from('EMAIL-HMAC'), Buffer.from('PHONE-HMAC'), dek],
    );
    await client.query(`SELECT set_config('app.actor_id', $1, false)`, [id]);
    await client.query(`SELECT set_config('app.change_reason', 'probe', false)`);
    await client.query(`UPDATE widgets SET title = 'after' WHERE id = $1`, [id]);

    const { rows } = await client.query<{
      row_data: Record<string, unknown>;
      actor_id: string | null;
      reason: string | null;
    }>(`SELECT row_data, actor_id, reason FROM widgets_versions ORDER BY version_seq`);
    expect(rows).toHaveLength(1);
    const image = rows[0]?.row_data ?? {};

    // (1) BOTH blind indexes are gone — derived redaction, not one named column.
    expect(image).not.toHaveProperty('email_bidx');
    expect(image).not.toHaveProperty('phone_bidx');
    expect(Object.keys(image).filter((k) => k.endsWith('_bidx'))).toEqual([]);

    // (2) Everything the capture exists FOR survives. `secret_ct` and `dek_id`
    // are deliberately kept: they are under the envelope, so the shred reaches
    // them, and they carry the audit value.
    expect(image['title']).toBe('before');
    expect(image).toHaveProperty('secret_ct');
    expect(image['dek_id']).toBe(dek);
    expect(rows[0]?.actor_id).toBe(id);
    expect(rows[0]?.reason).toBe('probe');
  });

  it('the corpus is non-empty, so an empty gap list means something', async () => {
    const corpus = await blindIndexCaptureCorpus(client, schema);
    expect([...corpus.keys()].sort()).toEqual(['legacy', 'widgets']);
    expect(corpus.get('widgets')?.sort()).toEqual(['email_bidx', 'phone_bidx']);
  });

  it('the detector NAMES an unredacted capture and clears a redacted one', async () => {
    const gaps = await blindIndexCaptureGaps(client, schema);
    expect(gaps.map((g) => g.table)).toEqual(['legacy']);
    expect(gaps[0]?.reason).toBe('no_redaction');
    expect(gaps[0]?.columns).toEqual(['email_bidx']);
  });
});
