import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';

/**
 * Migration entry point: `node dist/migrate-cli.js` with DATABASE_URL set.
 * Migrations are deliberately NOT run at service boot — schema changes are a
 * deploy step with their own review/rollback story, not a side effect of
 * starting an API process. Uses a dedicated pg Client because the migrator's
 * advisory lock is session-scoped.
 */
async function main(): Promise<void> {
  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    process.stderr.write('DATABASE_URL is required\n');
    process.exitCode = 1;
    return;
  }
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    const migrator = new Migrator(client, join(__dirname, '..', 'migrations'));
    const { applied } = await migrator.migrate();
    process.stdout.write(
      applied.length > 0 ? `applied: ${applied.join(', ')}\n` : 'schema up to date\n',
    );
  } finally {
    await client.end();
  }
}

void main().catch((err: unknown) => {
  // Migration errors are operational, not user-facing; message contains SQL
  // identifiers at most, never data.
  process.stderr.write(`${err instanceof Error ? err.message : 'migration failed'}\n`);
  process.exitCode = 1;
});
