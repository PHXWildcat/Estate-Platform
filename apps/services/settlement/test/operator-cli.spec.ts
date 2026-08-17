/**
 * The operator grant ceremony's DECISIONS, with the database faked.
 *
 * What this proves is the argv contract, the attribution requirement, the
 * broker gate and what each branch emits. What it deliberately does NOT prove
 * is the SQL — `grant`'s idempotence rides a partial unique index, and a fake
 * repo has no index to violate. That half is `operator-cli.int.spec.ts`, which
 * runs against real Postgres, and the split is stated because this repo's own
 * record is that a fix whose defect lived in SQL must be pinned by a test that
 * runs SQL.
 */
import type { AuditEvent } from '@estate/contracts';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import {
  brokersFrom,
  parseOperatorArgv,
  runOperatorCommand,
  type CommandDeps,
} from '../src/operator-cli';
import type { GrantOutcome, OperatorsRepo, RevokeOutcome } from '../src/operators.repo';

const SUBJECT = '11111111-1111-4111-8111-111111111111';
const BY = '22222222-2222-4222-8222-222222222222';
const ROW = '33333333-3333-4333-8333-333333333333';
const EXISTING = '44444444-4444-4444-8444-444444444444';

class RecordingProducer implements AuditProducer {
  readonly sent: AuditEvent[] = [];
  send(message: { topic: string; key: string; value: string }): Promise<void> {
    this.sent.push(JSON.parse(message.value) as AuditEvent);
    return Promise.resolve();
  }
}

function deps(
  overrides: Partial<{
    grant: GrantOutcome;
    revoke: RevokeOutcome;
    active: Array<{ user_id: string; created_at: Date; granted_by: string | null }>;
  }> = {},
): { deps: CommandDeps; producer: RecordingProducer; calls: string[] } {
  const producer = new RecordingProducer();
  const calls: string[] = [];
  const operators = {
    grant: (_q: unknown, userId: string, grantedBy: string) => {
      calls.push(`grant:${userId}:${grantedBy}`);
      return Promise.resolve(overrides.grant ?? { result: 'granted', id: ROW });
    },
    revoke: (_q: unknown, userId: string) => {
      calls.push(`revoke:${userId}`);
      return Promise.resolve(overrides.revoke ?? { result: 'revoked', id: ROW });
    },
    listActive: () => Promise.resolve(overrides.active ?? []),
  } as unknown as OperatorsRepo;
  return {
    producer,
    calls,
    deps: {
      // No cast: `CommandDeps.db` is `Queryable`, so this double is CHECKED
      // against the port rather than asserted into it. A cast on the outer
      // object would leave the method's return type inferred and never
      // compared — the M20 PR0 shape, one layer beneath the fixtures.
      db: { query: () => Promise.resolve([]) },
      operators,
      emitter: new AuditEmitter(producer, () => new Date('2026-08-17T00:00:00.000Z')),
      now: () => new Date('2026-08-17T00:00:00.000Z'),
    },
  };
}

describe('parseOperatorArgv', () => {
  it('accepts a grant with attribution', () => {
    expect(parseOperatorArgv(['grant', SUBJECT, '--by', BY])).toEqual({
      kind: 'grant',
      userId: SUBJECT,
      by: BY,
    });
  });

  it('accepts a revoke with attribution', () => {
    expect(parseOperatorArgv(['revoke', SUBJECT, '--by', BY])).toEqual({
      kind: 'revoke',
      userId: SUBJECT,
      by: BY,
    });
  });

  it('REFUSES a write with no --by, and says why', () => {
    // The whole point of the flag: `granted_by` existed since M7 and nothing
    // wrote it, so every row said only that somebody with the database made a
    // grant. Accepting the old argv shape would leave that true.
    const parsed = parseOperatorArgv(['grant', SUBJECT]);
    expect(parsed.kind).toBe('usage');
    expect((parsed as { message: string }).message).toContain('--by');
  });

  it.each([
    ['a non-uuid subject', ['grant', 'not-a-uuid', '--by', BY]],
    ['a non-uuid authorizer', ['grant', SUBJECT, '--by', 'not-a-uuid']],
    ['a dangling --by', ['grant', SUBJECT, '--by']],
    ['an unknown verb', ['promote', SUBJECT, '--by', BY]],
    ['no arguments at all', []],
  ])('refuses %s', (_label, argv) => {
    expect(parseOperatorArgv(argv).kind).toBe('usage');
  });

  it('accepts list, and refuses a list that carries an attribution flag', () => {
    // A read that accepts --by invites the belief that it recorded one.
    expect(parseOperatorArgv(['list'])).toEqual({ kind: 'list' });
    expect(parseOperatorArgv(['list', '--by', BY]).kind).toBe('usage');
  });
});

describe('brokersFrom', () => {
  it('reads a comma list and drops blanks', () => {
    expect(brokersFrom({ KAFKA_BROKERS: ' a:9092 , , b:9092 ' })).toEqual(['a:9092', 'b:9092']);
  });

  it.each([[undefined], [''], ['  '], [',']])('treats %p as no brokers', (value) => {
    expect(brokersFrom({ KAFKA_BROKERS: value })).toEqual([]);
  });
});

describe('runOperatorCommand', () => {
  it('grants, and the audit event names the authorizer as the actor', async () => {
    const { deps: d, producer, calls } = deps();
    const line = await runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, d);

    expect(calls).toEqual([`grant:${SUBJECT}:${BY}`]);
    expect(line).toBe(`granted: ${SUBJECT}\n`);
    expect(producer.sent).toHaveLength(1);
    expect(producer.sent[0]).toMatchObject({
      action: 'settlement.operator.granted',
      actorId: BY,
      actorType: 'operator',
      resourceType: 'settlement_operator',
      resourceId: ROW,
      detail: { subject: SUBJECT, outcome: 'granted' },
    });
  });

  it('records the idempotent no-op as its own outcome rather than as a grant', async () => {
    // A repeat is not a second grant and must not read as one in the trail.
    const { deps: d, producer } = deps({ grant: { result: 'already_granted', id: EXISTING } });
    const line = await runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, d);

    expect(line).toBe(`already granted: ${SUBJECT}\n`);
    expect(producer.sent[0]).toMatchObject({
      detail: { outcome: 'already_granted' },
      resourceId: EXISTING,
    });
  });

  it('revokes, and records a revoke that found nothing as its own outcome', async () => {
    const { deps: d, producer } = deps();
    expect(await runOperatorCommand({ kind: 'revoke', userId: SUBJECT, by: BY }, d)).toBe(
      `revoked: ${SUBJECT}\n`,
    );
    expect(producer.sent[0]).toMatchObject({
      action: 'settlement.operator.revoked',
      actorId: BY,
      detail: { subject: SUBJECT, outcome: 'revoked' },
    });

    const miss = deps({ revoke: { result: 'no_active_grant', id: null } });
    expect(await runOperatorCommand({ kind: 'revoke', userId: SUBJECT, by: BY }, miss.deps)).toBe(
      `no active grant: ${SUBJECT}\n`,
    );
    expect(miss.producer.sent[0]).toMatchObject({
      detail: { outcome: 'no_active_grant' },
      resourceId: null,
    });
  });

  it('A FAILED EMIT PROPAGATES, so the caller can roll the write back', async () => {
    // The ordering decision the CLI documents: the INSERT is reversible and
    // the emit is not, so the emit runs last and a failure must reach main()'s
    // catch. Swallowing it here would be an unaudited grant, which is the one
    // outcome this ceremony exists to prevent.
    const { deps: d } = deps();
    const failing = new AuditEmitter({
      send: () => Promise.reject(new Error('broker down')),
    });
    await expect(
      runOperatorCommand({ kind: 'grant', userId: SUBJECT, by: BY }, { ...d, emitter: failing }),
    ).rejects.toThrow('broker down');
  });

  it('lists, showing an unattributed row as such, and emits NOTHING', async () => {
    // Every row written before M21 PR1 carries granted_by NULL. Rendering that
    // as blank would hide the distinction the ceremony exists to create.
    const { deps: d, producer } = deps({
      active: [
        { user_id: SUBJECT, created_at: new Date('2026-01-01T00:00:00.000Z'), granted_by: BY },
        { user_id: BY, created_at: new Date('2026-01-02T00:00:00.000Z'), granted_by: null },
      ],
    });
    const line = await runOperatorCommand({ kind: 'list' }, d);

    expect(line).toContain(`${SUBJECT}  since 2026-01-01T00:00:00.000Z  by ${BY}`);
    expect(line).toContain(`${BY}  since 2026-01-02T00:00:00.000Z  by (unattributed)`);
    expect(line).toContain('2 active operator(s)');
    expect(producer.sent).toEqual([]);
  });

  it('says "0 active operator(s)" rather than printing nothing', async () => {
    const { deps: d } = deps({ active: [] });
    expect(await runOperatorCommand({ kind: 'list' }, d)).toBe('0 active operator(s)\n');
  });
});
