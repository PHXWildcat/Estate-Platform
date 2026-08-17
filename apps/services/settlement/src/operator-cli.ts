import { Client, type QueryResultRow } from 'pg';
import { z } from 'zod';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import { KafkaAuditProducer } from '@estate/kafka';
import { OperatorsRepo } from './operators.repo';
import type { Queryable } from './db';

/**
 * The operator grant ceremony — the ONLY sanctioned write path to
 * `settlement_operators`.
 *
 *   node dist/operator-cli.js grant  <userId> --by <authorizingUserId>
 *   node dist/operator-cli.js revoke <userId> --by <authorizingUserId>
 *   node dist/operator-cli.js list
 *
 * WHY IT IS A CLI AND NOT A ROUTE, restated because it is the whole safety
 * argument: no runtime session may mint an operator. A route would mean a
 * compromised operator session could create another operator, and the
 * allowlist stands in for the TB7 platform precisely because it cannot.
 *
 * THREE THINGS M21 PR1 CHANGED, each closing something that was claimed and
 * not true:
 *
 * 1. IT AUDITS, AND REFUSES TO WRITE WHEN IT CANNOT. Granting the authority to
 *    approve a death case was the only privileged act in the product with no
 *    entry in the append-only trail. The template-publish CLI's precedent —
 *    fall back to an in-memory producer when no broker is configured — is
 *    right for a template and wrong here: it would make an UNAUDITED grant the
 *    quiet default on any machine without `KAFKA_BROKERS`, which is the state
 *    every developer laptop is in. So a broker is REQUIRED for a write, and
 *    `list` (which changes nothing) does not need one.
 *
 * 2. IT DEMANDS ATTRIBUTION. `granted_by` has existed since M7 and nothing has
 *    ever written it. `--by` is not authentication — whoever runs this already
 *    holds the database and could write the row by hand. What it buys is that
 *    the sanctioned path produces a record naming a human, so a row with
 *    `granted_by IS NULL` is visibly one that did not come through here.
 *
 * 3. IT USES `OperatorsRepo`. The previous version reimplemented grant and
 *    revoke in raw SQL while the repo's own methods — documented as "the
 *    CLI-only write path" — had no caller at all.
 *
 * ORDER INSIDE THE TRANSACTION: the row is written first and the audit event
 * emitted second, because the emit is the step that cannot be undone (Kafka is
 * append-only; the INSERT rolls back). A failed emit therefore rolls back the
 * grant, and the residual is the ordinary one every emit-inside-a-transaction
 * carries here: an event may land for a commit that then fails. That direction
 * is the safe one — a phantom grant record is investigable, a silent real
 * grant is not.
 */

const UuidSchema = z.string().uuid();

/** Parsed argv, or the usage error to print. */
export type OperatorCommand =
  | { readonly kind: 'list' }
  | { readonly kind: 'grant' | 'revoke'; readonly userId: string; readonly by: string }
  | { readonly kind: 'usage'; readonly message: string };

const USAGE =
  'usage: operator-cli grant <userId> --by <authorizingUserId>\n' +
  '       operator-cli revoke <userId> --by <authorizingUserId>\n' +
  '       operator-cli list\n';

/**
 * Pure argv parsing, exported so the contract is testable without a database.
 * `--by` is required for both writes and rejected for `list`, because a
 * read that accepts an attribution flag invites the belief that it recorded
 * one.
 */
export function parseOperatorArgv(argv: readonly string[]): OperatorCommand {
  const [command, ...rest] = argv;
  if (command === 'list') {
    return rest.length === 0
      ? { kind: 'list' }
      : { kind: 'usage', message: 'list takes no arguments\n' };
  }
  if (command !== 'grant' && command !== 'revoke') {
    return { kind: 'usage', message: USAGE };
  }

  const [rawUserId, ...flags] = rest;
  const byIndex = flags.indexOf('--by');
  if (byIndex === -1) {
    return {
      kind: 'usage',
      message: `--by <authorizingUserId> is required: a grant nobody is named for is a grant nobody can be asked about\n`,
    };
  }
  if (flags.length !== 2) {
    return { kind: 'usage', message: USAGE };
  }

  const userId = UuidSchema.safeParse(rawUserId);
  if (!userId.success) {
    return { kind: 'usage', message: 'userId must be a UUID\n' };
  }
  const by = UuidSchema.safeParse(flags[byIndex + 1]);
  if (!by.success) {
    return { kind: 'usage', message: '--by must be a UUID\n' };
  }
  return { kind: command, userId: userId.data, by: by.data };
}

/** See its one use site: an assertion that the read path emits nothing. */
const REFUSING_PRODUCER: AuditProducer = {
  send: () => Promise.reject(new Error('the operator read path must not emit audit events')),
};

/** The brokers a write requires, or `[]` when none are configured. */
export function brokersFrom(env: NodeJS.ProcessEnv): string[] {
  return (env['KAFKA_BROKERS'] ?? '')
    .split(',')
    .map((b) => b.trim())
    .filter((b) => b.length > 0);
}

export interface CommandDeps {
  readonly db: Queryable;
  readonly operators: OperatorsRepo;
  readonly emitter: AuditEmitter;
  readonly now: () => Date;
}

/** The outcome line a command prints, exported so tests read what a human reads. */
export async function runOperatorCommand(
  command: Exclude<OperatorCommand, { kind: 'usage' }>,
  deps: CommandDeps,
): Promise<string> {
  if (command.kind === 'list') {
    const rows = await deps.operators.listActive(deps.db);
    const lines = rows.map(
      (r) =>
        `${r.user_id}  since ${r.created_at.toISOString()}  by ${r.granted_by ?? '(unattributed)'}`,
    );
    return `${lines.join('\n')}${lines.length > 0 ? '\n' : ''}${rows.length} active operator(s)\n`;
  }

  if (command.kind === 'grant') {
    const outcome = await deps.operators.grant(deps.db, command.userId, command.by);
    await deps.emitter.emit({
      action: 'settlement.operator.granted',
      actorId: command.by,
      actorType: 'operator',
      onBehalfOf: null,
      resourceType: 'settlement_operator',
      resourceId: outcome.id,
      sessionId: null,
      detail: { subject: command.userId, outcome: outcome.result },
    });
    return `${outcome.result === 'granted' ? 'granted' : 'already granted'}: ${command.userId}\n`;
  }

  const outcome = await deps.operators.revoke(deps.db, command.userId, deps.now());
  await deps.emitter.emit({
    action: 'settlement.operator.revoked',
    actorId: command.by,
    actorType: 'operator',
    onBehalfOf: null,
    resourceType: 'settlement_operator',
    resourceId: outcome.id,
    sessionId: null,
    detail: { subject: command.userId, outcome: outcome.result },
  });
  return `${outcome.result === 'revoked' ? 'revoked' : 'no active grant'}: ${command.userId}\n`;
}

async function main(): Promise<void> {
  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    process.stderr.write('DATABASE_URL is required\n');
    process.exitCode = 1;
    return;
  }

  const command = parseOperatorArgv(process.argv.slice(2));
  if (command.kind === 'usage') {
    process.stderr.write(command.message);
    process.exitCode = 1;
    return;
  }

  const brokers = brokersFrom(process.env);
  const writes = command.kind !== 'list';
  if (writes && brokers.length === 0) {
    // Fail closed. An unauditable grant of the authority to approve a death
    // case is exactly what the append-only trail exists to make impossible.
    process.stderr.write(
      'KAFKA_BROKERS is required to grant or revoke: this ceremony refuses to make a change it cannot record\n',
    );
    process.exitCode = 1;
    return;
  }

  const producer = writes
    ? new KafkaAuditProducer({ clientId: 'settlement-operator-cli', brokers })
    : // `list` changes nothing and emits nothing, so it needs no broker. This
      // is an ASSERTION of that rather than a stub for it: should the read
      // path ever start emitting, it fails loudly here instead of quietly
      // dropping an event into a producer connected to nowhere.
      REFUSING_PRODUCER;
  const emitter = new AuditEmitter(producer, () => new Date());
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    await client.query('BEGIN');
    const db: Queryable = {
      query: async <T extends QueryResultRow>(text: string, values: unknown[] = []): Promise<T[]> =>
        (await client.query<T>(text, values)).rows,
    };
    const line = await runOperatorCommand(command, {
      db,
      operators: new OperatorsRepo(),
      emitter,
      now: () => new Date(),
    });
    await client.query('COMMIT');
    process.stdout.write(line);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    await client.end();
    if (producer instanceof KafkaAuditProducer) {
      await producer.disconnect();
    }
  }
}

if (require.main === module) {
  void main().catch((err: unknown) => {
    // Operational errors only: labels and identifiers, never user data.
    process.stderr.write(`${err instanceof Error ? err.message : 'operator-cli failed'}\n`);
    process.exitCode = 1;
  });
}
