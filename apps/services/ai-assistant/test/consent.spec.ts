import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CONSENT_SCOPES, isConsentScope, permits, type ConsentScope } from '../src/consent';

describe('consent scopes', () => {
  it('rejects a value that is not a scope', () => {
    expect(isConsentScope('assistant.vault')).toBe(false);
    expect(isConsentScope('')).toBe(false);
    expect(isConsentScope('assistant.assets')).toBe(true);
  });

  it('agrees with the CHECK constraint in the migration', () => {
    // The vocabulary lives in two places by necessity — a TypeScript union and
    // a SQL CHECK — and the two drifting apart is the whole failure mode: code
    // that offers a scope the database refuses, or a database that admits a
    // scope no code enforces. Pin them to each other rather than to a comment.
    const sql = readFileSync(
      join(__dirname, '..', 'migrations', '001_ai_assistant_schema.sql'),
      'utf8',
    );
    const check = /CHECK \(scope IN \(([\s\S]*?)\)\)/.exec(sql);
    expect(check).not.toBeNull();
    const inSql = [...(check?.[1] ?? '').matchAll(/'([^']+)'/g)].map((m) => m[1]);
    expect(inSql.sort()).toEqual([...CONSENT_SCOPES].sort());
  });
});

describe('permits — deny by default', () => {
  const all = (...scopes: ConsentScope[]): ReadonlySet<ConsentScope> => new Set(scopes);

  it('denies every scope to a user who has granted nothing', () => {
    for (const scope of CONSENT_SCOPES) {
      expect(permits(all(), scope)).toBe(false);
    }
  });

  it('denies a granted scope while the master switch is off', () => {
    // The load-bearing case: revoking `assistant.enabled` alone must turn the
    // assistant off, without the user having to revoke each capability and
    // without every call site remembering to check two things.
    expect(permits(all('assistant.assets'), 'assistant.assets')).toBe(false);
    expect(permits(all('assistant.documents.content'), 'assistant.documents.content')).toBe(false);
  });

  it('denies a scope the user never granted, even with the master switch on', () => {
    expect(
      permits(all('assistant.enabled', 'assistant.assets'), 'assistant.documents.content'),
    ).toBe(false);
  });

  it('allows only when the master switch and the specific scope are both granted', () => {
    expect(permits(all('assistant.enabled', 'assistant.assets'), 'assistant.assets')).toBe(true);
  });

  it('treats the master switch as sufficient only for itself', () => {
    expect(permits(all('assistant.enabled'), 'assistant.enabled')).toBe(true);
    expect(permits(all('assistant.enabled'), 'assistant.profile')).toBe(false);
  });
});
