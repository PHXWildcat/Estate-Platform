import { existsSync, readFileSync } from 'node:fs';
import { diagnose, parseEnvFile, summarize } from './doctor';

/**
 * Preflight the stack's environment.
 *
 *   node dist/doctor-cli.js [path]
 *
 * Exits non-zero on any error-severity finding, so it can gate `compose up`.
 * Wiring only — the checks live in `diagnose`, where they are tested.
 */
function main(argv: readonly string[]): number {
  const target = argv[0] ?? process.env['STACK_ENV_FILE'] ?? '.env.stack';
  if (!existsSync(target)) {
    process.stderr.write(`${target} not found — run \`pnpm stack:env\` first.\n`);
    return 1;
  }

  const findings = diagnose(parseEnvFile(readFileSync(target, 'utf8')));
  const { errorCount, lines } = summarize(findings);
  for (const line of lines) {
    (line.startsWith('error') ? process.stderr : process.stdout).write(`${line}\n`);
  }

  if (errorCount > 0) {
    process.stderr.write(`\n${errorCount} error(s) — refusing to start the stack.\n`);
    return 1;
  }
  process.stdout.write(`${target}: ok${lines.length > 0 ? ` (${lines.length} warning(s))` : ''}\n`);
  return 0;
}

process.exitCode = main(process.argv.slice(2));
