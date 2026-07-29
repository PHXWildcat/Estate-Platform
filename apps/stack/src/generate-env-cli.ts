import { existsSync, writeFileSync } from 'node:fs';
import { writeStackEnv } from './generate-env';

/**
 * Write the stack's environment file.
 *
 *   node dist/generate-env-cli.js [--mode development|production] [--force]
 *
 * Wiring only — the decision to write, and the refusal to clobber, live in
 * `writeStackEnv` where they are tested.
 */
function main(argv: readonly string[]): number {
  const modeArg = argv.indexOf('--mode');
  const mode = modeArg === -1 ? 'development' : argv[modeArg + 1];
  if (mode !== 'development' && mode !== 'production') {
    process.stderr.write(`unknown --mode "${String(mode)}" (development|production)\n`);
    return 1;
  }

  const outcome = writeStackEnv(
    {
      mode,
      target: process.env['STACK_ENV_FILE'] ?? '.env.stack',
      force: argv.includes('--force'),
    },
    { exists: existsSync, write: (path, contents) => writeFileSync(path, contents, 'utf8') },
  );

  if (outcome.status === 'refused') {
    process.stderr.write(`${outcome.message}\n`);
    return 1;
  }
  process.stdout.write(`wrote ${outcome.path} (mode: ${mode})\n`);
  return 0;
}

process.exitCode = main(process.argv.slice(2));
