import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { writeStackEnv } from './generate-env';

/**
 * Write the stack's environment file.
 *
 *   node dist/generate-env-cli.js [--mode development|production]
 *                                 [--addressing compose|host]
 *                                 [--from <env-file>] [--force]
 *
 * `--from` RE-ADDRESSES an existing environment rather than minting a new one:
 * two addressings are two views of the same volumes, so the second must carry
 * the first's keys or the search index and every wrapped DEK belong to a
 * different stack than the rows referencing them.
 *
 * Wiring only — the decision to write, the refusal to clobber, and the
 * derivation live in `writeStackEnv`/`deriveEnv` where they are tested.
 */
function main(argv: readonly string[]): number {
  const modeArg = argv.indexOf('--mode');
  const mode = modeArg === -1 ? 'development' : argv[modeArg + 1];
  if (mode !== 'development' && mode !== 'production') {
    process.stderr.write(`unknown --mode "${String(mode)}" (development|production)\n`);
    return 1;
  }
  const addressingArg = argv.indexOf('--addressing');
  const addressing = addressingArg === -1 ? 'compose' : argv[addressingArg + 1];
  if (addressing !== 'compose' && addressing !== 'host') {
    process.stderr.write(`unknown --addressing "${String(addressing)}" (compose|host)\n`);
    return 1;
  }

  const fromArg = argv.indexOf('--from');
  if (fromArg !== -1 && argv[fromArg + 1] === undefined) {
    process.stderr.write('--from expects a path to an existing env file\n');
    return 1;
  }
  const from = fromArg === -1 ? undefined : (argv[fromArg + 1] as string);

  const outcome = writeStackEnv(
    {
      mode,
      addressing,
      target: process.env['STACK_ENV_FILE'] ?? '.env.stack',
      force: argv.includes('--force'),
      ...(from === undefined ? {} : { from }),
    },
    {
      exists: existsSync,
      read: (path) => readFileSync(path, 'utf8'),
      write: (path, contents) => writeFileSync(path, contents, 'utf8'),
    },
  );

  if (outcome.status === 'refused') {
    process.stderr.write(`${outcome.message}\n`);
    return 1;
  }
  process.stdout.write(`wrote ${outcome.path} (mode: ${mode})\n`);
  return 0;
}

process.exitCode = main(process.argv.slice(2));
