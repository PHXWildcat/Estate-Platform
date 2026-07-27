import { Client } from 'pg';
import { z } from 'zod';

/**
 * The ONLY write path to the settlement_operators allowlist (decision log:
 * no runtime grant API — a compromised operator session must not be able to
 * mint operators; the template-publish-cli precedent). Run against the core
 * cluster with DATABASE_URL set:
 *
 *   node dist/operator-cli.js grant  <userId>
 *   node dist/operator-cli.js revoke <userId>
 *   node dist/operator-cli.js list
 *
 * Interim until the TB7 operator platform (JIT elevation, peer approval);
 * grants performed here carry granted_by NULL, and the rows themselves are
 * the history (append + revoke, never delete).
 */

const UuidSchema = z.string().uuid();

async function main(): Promise<void> {
  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    process.stderr.write('DATABASE_URL is required\n');
    process.exitCode = 1;
    return;
  }
  const [command, rawUserId] = process.argv.slice(2);
  if (command !== 'grant' && command !== 'revoke' && command !== 'list') {
    process.stderr.write('usage: operator-cli <grant|revoke> <userId> | operator-cli list\n');
    process.exitCode = 1;
    return;
  }

  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    if (command === 'list') {
      const result = await client.query<{ user_id: string; created_at: Date }>(
        `SELECT user_id, created_at
           FROM settlement_operators
          WHERE revoked_at IS NULL
          ORDER BY created_at`,
      );
      for (const row of result.rows) {
        process.stdout.write(`${row.user_id}  since ${row.created_at.toISOString()}\n`);
      }
      process.stdout.write(`${result.rows.length} active operator(s)\n`);
      return;
    }

    const parsed = UuidSchema.safeParse(rawUserId);
    if (!parsed.success) {
      process.stderr.write('userId must be a UUID\n');
      process.exitCode = 1;
      return;
    }
    const userId = parsed.data;

    if (command === 'grant') {
      try {
        await client.query(`INSERT INTO settlement_operators (user_id) VALUES ($1)`, [userId]);
        process.stdout.write(`granted: ${userId}\n`);
      } catch (err) {
        const isUnique =
          typeof err === 'object' && err !== null && (err as { code?: unknown }).code === '23505';
        if (!isUnique) {
          throw err;
        }
        process.stdout.write(`already granted: ${userId}\n`);
      }
      return;
    }

    const result = await client.query(
      `UPDATE settlement_operators SET revoked_at = now()
        WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId],
    );
    process.stdout.write(
      result.rowCount && result.rowCount > 0
        ? `revoked: ${userId}\n`
        : `no active grant: ${userId}\n`,
    );
  } finally {
    await client.end();
  }
}

void main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? err.message : 'operator-cli failed'}\n`);
  process.exitCode = 1;
});
