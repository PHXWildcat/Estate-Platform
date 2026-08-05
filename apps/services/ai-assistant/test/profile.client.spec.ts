import { ProfileClient } from '../src/clients';
import type { FetchLike } from '../src/clients/http';

/**
 * The one client with a carve-out from the flat failure taxonomy, so the one
 * client whose transport behaviour needs pinning at this level (M10 PR3).
 *
 * The stack e2e's first live run found the gap these tests close: profile
 * answers `404 {error: 'not_found'}` for a user who never created a profile
 * row, and reading that as "the read did not happen" turned three analyses and
 * the profile-facts tool into a permanent 503 for exactly those users. The
 * fix distinguishes THE PEER'S OWN not-found token from every other failure —
 * and the distinction is precisely what must not rot, because widening it is a
 * fail-open (a misdeployed peer reading as "empty profile") and narrowing it
 * re-creates the 503.
 */

const BEARER = 'callers-own-bearer';

function respond(ok: boolean, body: unknown): FetchLike {
  return () => Promise.resolve({ ok, json: () => Promise.resolve(body) });
}

function client(fetchImpl: FetchLike): ProfileClient {
  return new ProfileClient('http://profile.invalid', fetchImpl);
}

describe('ProfileClient.facts', () => {
  it('narrows a real profile to the two planning facts', async () => {
    // The wire body carries the full Zone B row; the schema strips everything
    // identifying before it exists as a value in this process.
    const facts = await client(
      respond(true, {
        legalName: 'Someone Real',
        dob: '1960-01-01',
        ssnLast4: '1234',
        stateOfResidence: 'TX',
        maritalStatus: 'married',
      }),
    ).facts(BEARER);
    expect(facts).toEqual({ stateOfResidence: 'TX', maritalStatus: 'married' });
  });

  it("maps the peer's own not_found token to the empty facts view", async () => {
    // "No profile row" is the true answer "nothing on file" — the analysers
    // render it as "state of residence unknown", not as an outage.
    const facts = await client(respond(false, { error: 'not_found' })).facts(BEARER);
    expect(facts).toEqual({ stateOfResidence: null, maritalStatus: null });
  });

  it('keeps a route-level 404 fail-closed — a wrong URL is not an empty profile', async () => {
    // Nest's default 404 body, which is what a misconfigured PROFILE_URL or a
    // misdeployed peer produces. It must stay null, or an outage-class failure
    // becomes a confidently empty answer.
    const facts = await client(
      respond(false, { message: 'Cannot GET /v1/profile', error: 'Not Found', statusCode: 404 }),
    ).facts(BEARER);
    expect(facts).toBeNull();
  });

  it.each([
    ['a non-not_found error token', { error: 'forbidden' }],
    ['an empty body object', {}],
    ['a null body', null],
    ['a string body', 'not_found'],
  ])('keeps %s fail-closed', async (_name, body) => {
    await expect(client(respond(false, body)).facts(BEARER)).resolves.toBeNull();
  });

  it('answers null for a non-JSON failure body and for a thrown transport', async () => {
    const nonJson: FetchLike = () =>
      Promise.resolve({ ok: false, json: () => Promise.reject(new Error('not json')) });
    await expect(client(nonJson).facts(BEARER)).resolves.toBeNull();

    const dead: FetchLike = () => Promise.reject(new Error('ECONNREFUSED'));
    await expect(client(dead).facts(BEARER)).resolves.toBeNull();
  });

  it('refuses an empty bearer without a round trip', async () => {
    let calls = 0;
    const counting: FetchLike = () => {
      calls += 1;
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    };
    await expect(client(counting).facts('')).resolves.toBeNull();
    expect(calls).toBe(0);
  });
});

describe('ProfileClient.family', () => {
  it('keeps the flat taxonomy — no not_found carve-out', async () => {
    // Family is a LIST route: a user with no members gets [] from the peer, so
    // there is no absent case to distinguish and a 404 here can only be the
    // route-level kind. It stays fail-closed.
    await expect(client(respond(false, { error: 'not_found' })).family(BEARER)).resolves.toBeNull();
  });

  it('narrows members to structure, never identity', async () => {
    const family = await client(
      respond(true, [{ id: 'f1', relation: 'child', isMinor: true, name: 'A Child' }]),
    ).family(BEARER);
    expect(family).toEqual([{ id: 'f1', relation: 'child', isMinor: true }]);
  });
});
