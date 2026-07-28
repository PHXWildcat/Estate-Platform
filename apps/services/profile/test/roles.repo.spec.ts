import { randomUUID } from 'node:crypto';
import type { Db } from '../src/db';
import { RolesRepo } from '../src/roles.repo';

/**
 * Records every statement and answers `to_regclass` from a settable flag, so a
 * test can move the co-tenant settlement table from absent to present exactly
 * the way a real deployment does.
 */
class RecordingDb {
  readonly statements: string[] = [];
  settlementDeployed = false;

  query<T>(sql: string, _params?: unknown[]): Promise<T[]> {
    this.statements.push(sql);
    if (sql.includes('to_regclass')) {
      const present = this.settlementDeployed ? 'settlement_cases' : null;
      return Promise.resolve([{ present }] as unknown as T[]);
    }
    return Promise.resolve([]);
  }
}

function repoWith(db: RecordingDb): RolesRepo {
  return new RolesRepo(db as unknown as Db);
}

/** Statements that actually resolve grants (i.e. not the existence probe). */
function grantQueries(db: RecordingDb): string[] {
  return db.statements.filter((s) => s.includes('role_assignments'));
}

describe('grant freeze during settlement (docs/03 §5.1 control 4)', () => {
  const owner = randomUUID();
  const caller = randomUUID();
  const now = new Date('2026-07-28T00:00:00Z');

  it('omits the freeze while settlement has never been deployed here', async () => {
    // Profile must keep serving against a core cluster where settlement's
    // migrations have not run — including its own scratch-schema test suites.
    const db = new RecordingDb();
    await repoWith(db).effectiveContactReadGrants(owner, caller, now);
    expect(grantQueries(db)[0]).not.toContain('settlement_cases sc');
  });

  it('RE-PROBES after a negative: a process that predates settlement still freezes', async () => {
    // The M7 security review's second confirmed finding. The probe used to
    // memoise `false` for the process lifetime, so any profile instance that
    // started before settlement's migration ran had this control compiled out
    // of its SQL permanently and silently — role-holders would keep reading a
    // possibly-deceased owner's contacts through a case's entire waiting
    // period, and the only symptom would be its absence. Fail-open is not an
    // acceptable resting state for a §5.1 control, and docs/04's
    // "deploy-order independence" claim depends on this.
    const db = new RecordingDb();
    const repo = repoWith(db);

    await repo.effectiveContactReadGrants(owner, caller, now);
    expect(grantQueries(db)[0]).not.toContain('settlement_cases sc');

    // Settlement deploys. No profile restart.
    db.settlementDeployed = true;
    await repo.effectiveContactReadGrants(owner, caller, now);
    const second = grantQueries(db)[1] as string;
    expect(second).toContain('settlement_cases sc');
    // ...and it freezes on exactly the post-review statuses: an unreviewed
    // report must never strip a LIVING owner's contacts of their access.
    expect(second).toContain("'waiting_period','verified','active','distributing'");
    expect(second).not.toContain("'reported'");
    expect(second).not.toContain("'verifying'");
  });

  it('caches the POSITIVE — the table cannot un-exist, so stop asking', async () => {
    const db = new RecordingDb();
    const repo = repoWith(db);
    db.settlementDeployed = true;

    await repo.effectiveContactReadGrants(owner, caller, now);
    await repo.effectiveContactReadGrants(owner, caller, now);
    await repo.effectiveContactReadGrants(owner, caller, now);

    expect(db.statements.filter((s) => s.includes('to_regclass'))).toHaveLength(1);
    expect(grantQueries(db)).toHaveLength(3);
    for (const sql of grantQueries(db)) {
      expect(sql).toContain('settlement_cases sc');
    }
  });
});
