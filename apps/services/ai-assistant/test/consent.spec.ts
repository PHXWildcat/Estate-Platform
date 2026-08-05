import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  CONSENT_SCOPES,
  isConsentScope,
  missingScopes,
  permits,
  type ConsentScope,
} from '../src/consent';

/** A grant set, as `ConsentsRepo.grantedScopes` returns one. */
const all = (...scopes: ConsentScope[]): ReadonlySet<ConsentScope> => new Set(scopes);

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

describe("missingScopes — all of a tool's scopes, never any", () => {
  it('is empty only when every required scope AND the master switch are granted', () => {
    const granted = all('assistant.enabled', 'assistant.assets', 'assistant.profile');
    expect(missingScopes(granted, ['assistant.assets', 'assistant.profile'])).toEqual([]);
  });

  it('names every scope that is missing, so a refusal is actionable', () => {
    // A user told "something was denied" learns the feature is broken; a user
    // told which switch to turn on learns it is gated.
    const granted = all('assistant.enabled', 'assistant.assets');
    expect(missingScopes(granted, ['assistant.assets', 'assistant.documents.metadata'])).toEqual([
      'assistant.documents.metadata',
    ]);
  });

  it('reports the master switch in its own right', () => {
    // Not collapsed into every scope: the capability grants may all be present,
    // and telling the user to re-grant them would send them somewhere useless.
    expect(missingScopes(all('assistant.assets'), ['assistant.assets'])).toEqual([
      'assistant.enabled',
    ]);
  });

  it('refuses a multi-scope analyser holding only one of its scopes', () => {
    // The rule that makes an analyser safe: a partial run would answer "no
    // conflicts" from data nobody agreed to share.
    const granted = all('assistant.enabled', 'assistant.assets');
    expect(
      missingScopes(granted, [
        'assistant.assets',
        'assistant.documents.metadata',
        'assistant.profile',
      ]),
    ).toEqual(['assistant.documents.metadata', 'assistant.profile']);
  });

  it('requires the master switch even for an empty requirement list', () => {
    // Defence in depth behind `assertScoped`: a tool that declared no scope
    // would still not run for a user who has the assistant switched off.
    expect(missingScopes(all(), [])).toEqual(['assistant.enabled']);
  });
});
