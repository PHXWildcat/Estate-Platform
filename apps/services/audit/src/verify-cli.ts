import { Client } from 'pg';
import { loadDbConfig } from './config';
import { log } from './logger';
import { ChainVerifier } from './verifier';

/**
 * Full chain verification from genesis. Exit code 0 = chain intact,
 * 1 = tampering/corruption detected (or verification could not run).
 * Usage: node dist/verify-cli.js
 */
async function main(): Promise<void> {
  const { databaseUrl } = loadDbConfig();
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    const result = await new ChainVerifier(client).verify();
    if (result.ok) {
      log({ level: 'info', msg: 'audit_chain_verified', count: result.count });
    } else {
      log({
        level: 'error',
        msg: 'audit_chain_verification_failed',
        firstBadSeq: result.firstBadSeq,
        reason: result.reason,
      });
      process.exitCode = 1;
    }
  } finally {
    await client.end();
  }
}

main().catch((err: unknown) => {
  log({
    level: 'error',
    msg: 'audit_chain_verify_error',
    error: err instanceof Error ? `${err.name}: ${err.message}` : 'unknown',
  });
  process.exitCode = 1;
});
