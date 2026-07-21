import {
  appendOnlySql,
  softDeleteUniqueIndexSql,
  updatedAtFunctionSql,
  updatedAtTriggerSql,
  versionsTableSql,
} from '../src/conventions';

describe('convention SQL generators', () => {
  it('generates the updated_at trigger pair', () => {
    expect(updatedAtFunctionSql()).toContain('CREATE OR REPLACE FUNCTION set_updated_at()');
    const trigger = updatedAtTriggerSql('profiles');
    expect(trigger).toContain('CREATE TRIGGER trg_profiles_updated_at');
    expect(trigger).toContain('BEFORE UPDATE ON profiles');
  });

  it('generates an INSERT-only versions shadow table with actor/reason capture', () => {
    const sql = versionsTableSql('contacts');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS contacts_versions');
    expect(sql).toContain("CHECK (operation IN ('UPDATE','DELETE'))");
    expect(sql).toContain('REVOKE UPDATE, DELETE ON contacts_versions FROM PUBLIC;');
    expect(sql).toContain('to_jsonb(OLD)');
    expect(sql).toContain("current_setting('app.actor_id', true)");
    expect(sql).toContain('BEFORE UPDATE OR DELETE ON contacts');
  });

  it('generates append-only REVOKEs', () => {
    expect(appendOnlySql('asset_events')).toBe(
      'REVOKE UPDATE, DELETE ON asset_events FROM PUBLIC;',
    );
  });

  it('generates soft-delete-aware unique indexes', () => {
    const sql = softDeleteUniqueIndexSql('users', ['email_bidx']);
    expect(sql).toContain('CREATE UNIQUE INDEX ux_users_email_bidx ON users (email_bidx)');
    expect(sql).toContain('WHERE deleted_at IS NULL');
    expect(softDeleteUniqueIndexSql('t', ['a', 'b'], 'ux_custom')).toContain(
      'CREATE UNIQUE INDEX ux_custom ON t (a, b)',
    );
  });

  it('rejects malicious or invalid identifiers (SQL injection guard)', () => {
    expect(() => updatedAtTriggerSql('users; DROP TABLE users')).toThrow(/invalid SQL identifier/);
    expect(() => versionsTableSql('Users')).toThrow(/invalid SQL identifier/);
    expect(() => appendOnlySql('')).toThrow(/invalid SQL identifier/);
    expect(() => softDeleteUniqueIndexSql('users', ['email"; --'])).toThrow(
      /invalid SQL identifier/,
    );
    expect(() => softDeleteUniqueIndexSql('users', [])).toThrow(/at least one column/);
  });
});
