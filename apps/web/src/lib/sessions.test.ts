import { AUDIENCE_COPY, audienceCopy } from './sessions';

describe('what a session row says about a credential', () => {
  it('covers every audience the BFF enum can send', () => {
    // The Record is total over the union, so this is a compile-time guarantee
    // restated at runtime — cheap, and it fails loudly if someone widens the
    // union by casting rather than by adding an entry.
    expect(Object.keys(AUDIENCE_COPY).sort()).toEqual([
      'ACCOUNT',
      'EXTENSION',
      'OPERATOR',
      'VAULT',
    ]);
    for (const copy of Object.values(AUDIENCE_COPY)) {
      expect(copy.label.length).toBeGreaterThan(0);
      expect(copy.detail.length).toBeGreaterThan(0);
    }
  });

  it('says what the extension credential CANNOT do, which is the boundary M16 creates', () => {
    // A row that only said "browser extension" would leave the user to guess
    // how much a credential they do not recognise is worth. The one fact worth
    // reading here is its reach.
    expect(AUDIENCE_COPY.EXTENSION.detail).toMatch(/cannot reset your vault/i);
    expect(AUDIENCE_COPY.VAULT.detail).toMatch(/15 minutes/);
    // M21 PR3a. The operator row has the hardest job on this list: a user who
    // sees it needs to know it reaches NONE of their estate, because the word
    // "operator" invites exactly the opposite reading. That is the one fact
    // worth asserting, and it is the same reason the extension row asserts what
    // it cannot do rather than what it is.
    expect(AUDIENCE_COPY.OPERATOR.detail).toMatch(/reaches none of your estate/i);
    expect(AUDIENCE_COPY.OPERATOR.detail).toMatch(/15 minutes/);
  });

  it('falls back rather than blanking a row for an audience it has never heard of', () => {
    // A BFF deployed ahead of this app can send a token this build cannot look
    // up. `lib/findings.ts` settled the rule: a service ahead of the app must
    // not blank the page — and on THIS page the row still has to be revocable,
    // because an unrecognised credential is exactly the one worth revoking.
    const unknown = audienceCopy('SOMETHING_NEW');
    expect(unknown.label).toBe('Unrecognised credential');
    expect(unknown.detail).toMatch(/revoke it/i);
  });

  it('resolves the known audiences to their own entries', () => {
    expect(audienceCopy('EXTENSION')).toBe(AUDIENCE_COPY.EXTENSION);
  });
});
