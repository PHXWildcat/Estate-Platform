import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { loadConfig } from './config';
import { RebuildService } from './rebuild.service';

/**
 * Projection rebuild entry point (docs/02 §8 DR integrity check):
 *   node dist/rebuild-cli.js            — replay, diff, report; exit 1 on divergence
 *   node dist/rebuild-cli.js --repair   — additionally rewrite diverged rows
 *
 * Runs under the full application context: rebuild decryptions are audited
 * (actorType 'system'), and the audit producer follows the same
 * production-requires-Kafka rules as the API — a rebuild whose audit trail
 * cannot be emitted fails closed.
 */
async function main(): Promise<void> {
  loadConfig(); // fail fast before Nest wiring
  const repair = process.argv.includes('--repair');
  const app = await NestFactory.createApplicationContext(AppModule, {
    logger: ['error', 'warn'],
  });
  try {
    const report = await app.get(RebuildService).rebuild({ repair });
    // Counts and entity IDs/column names only — never values.
    process.stdout.write(
      `assets=${report.assets} events=${report.events} skipped=${report.skippedAssets} ` +
        `diffs=${report.diffs.length} repaired=${report.repaired}\n`,
    );
    for (const d of report.diffs) {
      process.stdout.write(
        `diff asset=${d.assetId} kind=${d.kind}` +
          `${d.field ? ` field=${d.field}` : ''}` +
          `${d.contactId ? ` contact=${d.contactId} designation=${d.designation ?? ''}` : ''}\n`,
      );
    }
    if (report.diffs.length > 0 && !repair) {
      process.exitCode = 1;
    }
  } finally {
    await app.close();
  }
}

void main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? err.name : 'rebuild failed'}\n`);
  process.exitCode = 1;
});
