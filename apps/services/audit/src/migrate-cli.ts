import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { loadDbConfig } from './config';
import { log } from './logger';

/** Applies migrations/*.sql to the audit cluster. Usage: node dist/migrate-cli.js */
async function main(): Promise<void> {
  const { databaseUrl } = loadDbConfig();
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    const migrator = new Migrator(client, join(__dirname, '..', 'migrations'));
    const { applied } = await migrator.migrate();
    log({ level: 'info', msg: 'audit_migrations_applied', count: applied.length });
  } finally {
    await client.end();
  }
}

main().catch((err: unknown) => {
  log({
    level: 'error',
    msg: 'audit_migrations_failed',
    error: err instanceof Error ? `${err.name}: ${err.message}` : 'unknown',
  });
  process.exitCode = 1;
});
