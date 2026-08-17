/**
 * The unified operator gate's OWN tests.
 *
 * WHY THIS FILE HAD TO EXIST BEFORE THE UNIFICATION WAS SAFE. This repo's rule
 * is that unifying N copies of a guard is only safe if the unified one is
 * tested harder than the copies were, because the blast radius becomes every
 * caller: making `assertIn` return without throwing now opens FOUR admission
 * paths at once rather than one. The four copies M21 PR2 replaced had no direct
 * test of their own — they were exercised only incidentally, through whichever
 * route happened to call them.
 *
 * What is proven here is the DECISION. That the SQL predicate is right is
 * `operator-cli.int.spec.ts`'s and `settlement.int.spec.ts`' job, against real
 * Postgres — a fake repo has no table to be wrong about.
 */
import { ForbiddenException } from '@nestjs/common';
import { OperatorGate } from '../src/operator-gate';
import type { OperatorsRepo } from '../src/operators.repo';
import type { Queryable } from '../src/db';

const USER = '11111111-1111-4111-8111-111111111111';

/** Records WHICH handle each call was made on — the parameter under test. */
function repoAnswering(answer: boolean): {
  repo: OperatorsRepo;
  handles: unknown[];
  users: string[];
} {
  const handles: unknown[] = [];
  const users: string[] = [];
  return {
    handles,
    users,
    repo: {
      isOperator: (q: unknown, userId: string) => {
        handles.push(q);
        users.push(userId);
        return Promise.resolve(answer);
      },
    } as unknown as OperatorsRepo,
  };
}

const POOL = { query: () => Promise.resolve([]) } as unknown as Queryable;
const TX = { query: () => Promise.resolve([]) } as unknown as Queryable;

describe('OperatorGate.is', () => {
  it('answers the allowlist, and asks on the handle it was given', async () => {
    const { repo, handles, users } = repoAnswering(true);
    expect(await new OperatorGate(repo).is(TX, USER)).toBe(true);
    // The handle is the security parameter: a write must be able to ask inside
    // its own transaction, so the gate may never substitute one of its own.
    expect(handles).toEqual([TX]);
    expect(users).toEqual([USER]);
  });

  it('answers false for a non-operator rather than throwing', async () => {
    // `evidenceReadAuthority` and `assertCaseVisible` both need the ANSWER, not
    // a refusal: one returns a 200 carrying `allowed: false`, the other falls
    // through to an executor check. A gate that only threw would force those
    // two back into reading the repo directly, which is what the fence forbids.
    const { repo } = repoAnswering(false);
    await expect(new OperatorGate(repo).is(POOL, USER)).resolves.toBe(false);
  });
});

describe('OperatorGate.assertIn', () => {
  it('REFUSES a non-operator with a bare forbidden', async () => {
    const { repo } = repoAnswering(false);
    await expect(new OperatorGate(repo).assertIn(TX, USER)).rejects.toThrow(ForbiddenException);
    await expect(new OperatorGate(repo).assertIn(TX, USER)).rejects.toMatchObject({
      response: { error: 'forbidden' },
    });
  });

  it('RETURNS the measured answer, which is what Cedar is handed', async () => {
    // The return value is the whole reason this method is not `Promise<void>`.
    // Three call sites used to pass a hardcoded `true` to `assertCan`, correct
    // only because a check had run above them; binding the result makes the
    // dependency structural instead of positional.
    const { repo } = repoAnswering(true);
    await expect(new OperatorGate(repo).assertIn(TX, USER)).resolves.toBe(true);
  });

  it('asks exactly once per assertion, on the given handle', async () => {
    // Two reads would be two chances to disagree, and the second would be the
    // one nobody audits.
    const { repo, handles } = repoAnswering(true);
    await new OperatorGate(repo).assertIn(TX, USER);
    expect(handles).toEqual([TX]);
  });

  it('propagates a repo failure rather than reading it as a refusal', async () => {
    // Fail closed, but as an ERROR: a database outage answering `forbidden`
    // would tell an operator they are not one, which is a different and
    // actionable fact (the M9 rule — a control firing must not read as an
    // outage, here pointed the other way).
    const repo = {
      isOperator: () => Promise.reject(new Error('connection terminated')),
    } as unknown as OperatorsRepo;
    await expect(new OperatorGate(repo).assertIn(TX, USER)).rejects.toThrow(
      'connection terminated',
    );
  });
});
