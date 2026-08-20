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
      'UNKNOWN',
      'VAULT',
    ]);
    for (const copy of Object.values(AUDIENCE_COPY)) {
      expect(copy.label.length).toBeGreaterThan(0);
      expect(copy.detail.length).toBeGreaterThan(0);
    }
  });

  it('names an audience it does not recognise rather than calling it a normal sign-in', () => {
    /*
     * TWO SKEWS, TWO MECHANISMS, and this is the one the edge used to swallow.
     * `UNKNOWN` is what the BFF sends when IDENTITY minted an audience the BFF
     * has never heard of — before this it failed the whole `z.array` and the
     * page rendered an error instead of the rows. The fallback below covers the
     * opposite direction (a BFF ahead of this app).
     *
     * What must never happen either way is this row reading as ACCOUNT: that
     * tells somebody the credential they do not recognise is their own browser,
     * on the one page they open to revoke it.
     */
    expect(AUDIENCE_COPY.UNKNOWN.label).not.toMatch(/sign-?in|browser/i);
    expect(AUDIENCE_COPY.UNKNOWN.detail).toMatch(/revoke it/i);
    expect(AUDIENCE_COPY.UNKNOWN).not.toEqual(AUDIENCE_COPY.ACCOUNT);
  });

  it('says what the extension credential CANNOT do, which is the boundary M16 creates', () => {
    // A row that only said "browser extension" would leave the user to guess
    // how much a credential they do not recognise is worth. The one fact worth
    // reading here is its reach.
    expect(AUDIENCE_COPY.EXTENSION.detail).toMatch(/cannot reset your vault/i);
    expect(AUDIENCE_COPY.VAULT.detail).toMatch(/15 minutes/);
    // M21 PR3a, NARROWED BY PR3b. The operator row has the hardest job on this
    // list: the word "operator" invites the reading that arriving is the
    // permission, so the row has to say what the credential cannot reach — the
    // same shape as the extension row, and for the same reason. What it must
    // NOT say is the absolute PR3a shipped; see below.
    /*
     * THE RESTRICTION IS STATED AS A RESTRICTION, and the absolute it replaced
     * is asserted GONE (M21 PR3b).
     *
     * "Reaches none of your estate" stopped being true when the operator
     * audience was admitted to settlement's case routes, four of which reach a
     * case through `assertCaseVisible` — which admits the decedent, the
     * reporter and the estate's executor as well as an operator. Asserting the
     * ABSENCE of the old sentence is what makes this a regression pin rather
     * than a spelling check: re-adding it beside the new words would otherwise
     * stay green.
     */
    expect(AUDIENCE_COPY.OPERATOR.detail).toMatch(
      /cannot reach your assets, documents, people or vault/i,
    );
    expect(AUDIENCE_COPY.OPERATOR.detail).toMatch(/the review queue and settlement cases/i);
    expect(AUDIENCE_COPY.OPERATOR.detail).toMatch(/15 minutes/);
    expect(AUDIENCE_COPY.OPERATOR.detail).not.toMatch(/reaches none of your estate/i);
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
