import { FetchIdentityClient } from '../src/identity-client';

/**
 * The REAL identity client against a stubbed transport (the peer-client
 * pattern used for profile, assets and documents).
 *
 * M14 added the first routes on this client whose refusals a USER acts on, so
 * this is where the error firewall is pinned: the caller's bearer goes out on
 * every call, identity's response text never comes back, a malformed answer is
 * refused rather than half-trusted, and the two refusals whose remedies differ
 * arrive as different codes while every refusal that must stay
 * indistinguishable collapses to one.
 */

const TOKEN = 'access-token-value-123';
const BASE = 'http://identity.test';

function response(status: number, body: unknown): Response {
  const json = (): Promise<unknown> => Promise.resolve(body);
  const res = {
    ok: status >= 200 && status < 300,
    status,
    json,
    clone: () => ({ json }) as unknown as Response,
  };
  return res as unknown as Response;
}

interface Recorded {
  url: string;
  init: RequestInit;
}

function clientWith(answer: (recorded: Recorded) => Response): {
  client: FetchIdentityClient;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const fetchFn = (input: unknown, init: RequestInit): Promise<Response> => {
    const recorded = { url: String(input), init };
    calls.push(recorded);
    return Promise.resolve(answer(recorded));
  };
  return { client: new FetchIdentityClient(BASE, fetchFn), calls };
}

describe('emailVerificationStatus', () => {
  it.each(['verified', 'unverified', 'unavailable'] as const)(
    'reads %s from the dedicated route, on the caller bearer',
    async (status) => {
      const { client, calls } = clientWith(() => response(200, { status }));
      await expect(client.emailVerificationStatus(TOKEN)).resolves.toBe(status);
      expect(calls[0]?.url).toBe(`${BASE}/v1/auth/email/verification`);
      expect((calls[0]?.init.headers as Record<string, string>).authorization).toBe(
        `Bearer ${TOKEN}`,
      );
    },
  );

  it('refuses an unknown state rather than half-trusting it', async () => {
    // A third value would mean identity and the edge disagree about what the
    // states ARE, and guessing would be worse than failing: the whole point of
    // three states is that one of them is about the platform, not the user.
    const { client } = clientWith(() => response(200, { status: 'probably' }));
    await expect(client.emailVerificationStatus(TOKEN)).rejects.toThrow(/validation/);
  });

  it('maps an expired session to UNAUTHENTICATED', async () => {
    const { client } = clientWith(() => response(401, { error: 'unauthenticated' }));
    await expect(client.emailVerificationStatus(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'UNAUTHENTICATED' },
    });
  });
});

describe('resendEmailVerification', () => {
  it.each(['sent', 'too_soon', 'already_verified', 'unavailable'] as const)(
    'carries the %s outcome back rather than flattening it',
    async (outcome) => {
      const { client, calls } = clientWith(() => response(200, { outcome }));
      await expect(client.resendEmailVerification(TOKEN)).resolves.toBe(outcome);
      expect(calls[0]?.url).toBe(`${BASE}/v1/auth/email/verification/resend`);
      expect(calls[0]?.init.method).toBe('POST');
    },
  );

  it('refuses an outcome it does not recognise', async () => {
    const { client } = clientWith(() => response(200, { outcome: 'maybe' }));
    await expect(client.resendEmailVerification(TOKEN)).rejects.toThrow(/validation/);
  });
});

describe('verifyEmail', () => {
  it('posts the code unchanged and resolves on success', async () => {
    const { client, calls } = clientWith(() => response(200, { verified: true }));
    await expect(client.verifyEmail(TOKEN, '  ev1-k7mn ')).resolves.toBeUndefined();
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/email/verification/verify`);
    expect(JSON.parse((calls[0]?.init.body ?? '') as string)).toEqual({ code: '  ev1-k7mn ' });
  });

  it('gives every refused code ONE token — the uniformity is the control', async () => {
    // Identity answers the same `invalid_code` for unknown, expired, spent,
    // revoked, attempt-exhausted and belonging-to-someone-else. The edge must
    // carry that through rather than re-deriving distinctions, or it
    // re-creates the oracle the uniform answer removes.
    const { client } = clientWith(() => response(400, { error: 'invalid_code' }));
    await expect(client.verifyEmail(TOKEN, 'nope')).rejects.toMatchObject({
      extensions: { code: 'INVALID_VERIFICATION_CODE' },
    });
  });

  it('keeps "we could not complete it" apart from "wrong code"', async () => {
    // Same 400 from identity, different fact: the code was fine and the
    // delivery store has no live row to vouch for. Nothing for the user to
    // re-check, so folding them together would send them hunting a typo that
    // does not exist.
    const { client } = clientWith(() => response(400, { error: 'verification_unavailable' }));
    await expect(client.verifyEmail(TOKEN, 'EV1-K7MN')).rejects.toMatchObject({
      extensions: { code: 'VERIFICATION_UNAVAILABLE' },
    });
  });

  it('treats a 400 with no recognisable token as a refused code', async () => {
    // The safe default on this route: it is reached only by submitting a code,
    // and telling somebody their code was refused is both true and actionable.
    const { client } = clientWith(() => response(400, { unexpected: true }));
    await expect(client.verifyEmail(TOKEN, 'EV1-K7MN')).rejects.toMatchObject({
      extensions: { code: 'INVALID_VERIFICATION_CODE' },
    });
  });

  it('falls through to the shared mapping for everything that is not a 400', async () => {
    const { client } = clientWith(() => response(401, { error: 'unauthenticated' }));
    await expect(client.verifyEmail(TOKEN, 'EV1-K7MN')).rejects.toMatchObject({
      extensions: { code: 'UNAUTHENTICATED' },
    });

    const { client: broken } = clientWith(() => response(500, { error: 'boom' }));
    // Identity's own text never reaches a GraphQL client — a plain Error that
    // yoga's masking turns generic.
    await expect(broken.verifyEmail(TOKEN, 'EV1-K7MN')).rejects.toThrow(/status 500/);
  });
});

/**
 * The vault handoff (M15).
 *
 * Here for the reason M14 wrote down when it created this file: every other BFF
 * spec drives the FAKE identity client, so a real method added without a case
 * here is a real method nobody executes — and the package's coverage floor is
 * what surfaces that, which is why the floor is never the thing that moves.
 *
 * What is pinned is the firewall rather than the happy path: the caller's own
 * bearer goes out, identity's text never comes back, and a malformed answer
 * becomes a refusal instead of a form the browser posts at the vault origin.
 */
describe('FetchIdentityClient.mintVaultHandoff', () => {
  const MINTED = { code: 'a-single-use-code', expiresAt: '2026-08-08T00:01:00.000Z' };

  it('posts to the handoff route on the caller’s own bearer', async () => {
    const { client, calls } = clientWith(() => response(201, MINTED));
    await expect(client.mintVaultHandoff(TOKEN)).resolves.toEqual(MINTED);

    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/handoff`);
    expect(calls[0]?.init.method).toBe('POST');
    expect((calls[0]?.init.headers as Record<string, string>).authorization).toBe(
      `Bearer ${TOKEN}`,
    );
    // The code must never travel in a URL — it goes in a hidden form field.
    expect(calls[0]?.url).not.toContain(MINTED.code);
  });

  it('surfaces STEPUP_REQUIRED so the surface can prompt rather than fail', async () => {
    const { client } = clientWith(() => response(403, { error: 'stepup_required' }));
    await expect(client.mintVaultHandoff(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'STEPUP_REQUIRED' },
    });
  });

  it('refuses a malformed body rather than half-trusting it', async () => {
    // A response missing `code` must not become a form posting `code=undefined`
    // at the vault origin. VAULT_UNAVAILABLE, not UNKNOWN: the remedy is "try
    // again in a moment", and the vault is where a vague failure is least
    // acceptable.
    const { client } = clientWith(() => response(201, { expiresAt: MINTED.expiresAt }));
    await expect(client.mintVaultHandoff(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'VAULT_UNAVAILABLE' },
    });
  });

  it('never lets identity’s own error text reach a GraphQL client', async () => {
    const { client } = clientWith(() => response(500, { error: 'pg: relation does not exist' }));
    await expect(client.mintVaultHandoff(TOKEN)).rejects.toThrow(/status 500/);
    await expect(client.mintVaultHandoff(TOKEN)).rejects.not.toThrow(/relation does not exist/);
  });
});

/**
 * The paired-devices client (M16). Same firewall, and one thing more.
 *
 * A MALFORMED PAIRING RESPONSE IS NOT A VAULT FAILURE. This path first reused
 * `VAULT_UNAVAILABLE` because the two ceremonies share a wire shape, and the
 * code carries copy that reassures the reader "nothing about your vault has
 * changed" — on a screen where nothing was opening a vault. That is the M12
 * finding exactly: one code changing meaning with the surface is what produced
 * copy about a password on a form that has none.
 */
describe('FetchIdentityClient — sessions, revoke and pairing', () => {
  const MINTED = { code: 'EP1-ABCD-EFGH-JKMN', expiresAt: '2026-08-10T12:10:00.000Z' };

  it('lists sessions on the caller’s own bearer, carrying the audience', async () => {
    const rows = [
      {
        sessionId: 's-1',
        audience: 'extension',
        createdAt: '2026-08-10T12:00:00.000Z',
        expiresAt: '2026-09-09T12:00:00.000Z',
        current: false,
      },
    ];
    const { client, calls } = clientWith(() => response(200, { sessions: rows }));
    await expect(client.sessions(TOKEN)).resolves.toEqual(rows);
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/sessions`);
    expect((calls[0]?.init.headers as Record<string, string>).authorization).toBe(
      `Bearer ${TOKEN}`,
    );
  });

  it('refuses a session list with an audience it cannot recognise', async () => {
    // The audience is the whole of what a row says, so an unrecognised value is
    // a parse failure rather than a row rendered as something it is not.
    const { client } = clientWith(() =>
      response(200, {
        sessions: [
          {
            sessionId: 's-1',
            audience: 'something-new',
            createdAt: 'x',
            expiresAt: 'y',
            current: false,
          },
        ],
      }),
    );
    await expect(client.sessions(TOKEN)).rejects.toThrow(/failed validation/);
  });

  it('revokes by id, and surfaces identity’s UNIFORM 404 as NOT_FOUND', async () => {
    const { client, calls } = clientWith(() => response(204, {}));
    await expect(client.revokeSession(TOKEN, 's-1')).resolves.toBeUndefined();
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/sessions/s-1`);
    expect(calls[0]?.init.method).toBe('DELETE');

    // Unknown and not-yours are one answer at identity — the owner predicate is
    // in its UPDATE — and the edge invents no distinction of its own.
    const missing = clientWith(() => response(404, { error: 'not_found' }));
    await expect(missing.client.revokeSession(TOKEN, 's-2')).rejects.toMatchObject({
      extensions: { code: 'NOT_FOUND' },
    });
  });

  it('mints a pairing code, and keeps it out of the URL', async () => {
    const { client, calls } = clientWith(() => response(201, MINTED));
    await expect(client.startExtensionPairing(TOKEN)).resolves.toEqual(MINTED);
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/extension/pairing`);
    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.url).not.toContain(MINTED.code);
  });

  it('surfaces STEPUP_REQUIRED so the surface can prompt rather than fail', async () => {
    const { client } = clientWith(() => response(403, { error: 'stepup_required' }));
    await expect(client.startExtensionPairing(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'STEPUP_REQUIRED' },
    });
  });

  /**
   * M19 PR4 review. Identity's step-up cap (M17 PR6's two-scope bound) answers
   * 429 `too_many_attempts`, and every route on this client routes its refusals
   * through one `mapError` — which had no 429 branch, so a control firing
   * exactly as designed fell through to `Error('identity responded with status
   * 429')` and reached the browser as "something went wrong on our side".
   *
   * That is the M9 rule (a control firing must not read as an outage), and the
   * identical shape the 404 branch three lines below it already names. M19 is
   * what made it worth fixing rather than recording: PR3 and PR4 put step-up
   * ceremonies on the assets surface (a designation, a retirement), so the cap
   * is now reachable from two more places, and the user meeting it is told to
   * retry the thing they must in fact WAIT to retry.
   *
   * PROVEN BY EXECUTION against the running stack before it was fixed: five
   * wrong codes at `POST /v1/auth/stepup` answer 401 `invalid_code`, the sixth
   * answers 429 `too_many_attempts`.
   */
  it('names identity’s rate cap rather than letting a control read as an outage', async () => {
    const { client } = clientWith(() => response(429, { error: 'too_many_attempts' }));
    await expect(client.stepUp(TOKEN, '000000')).rejects.toMatchObject({
      extensions: { code: 'TOO_MANY_ATTEMPTS' },
    });
    // Not the generic branch, whose message names a status code.
    await expect(client.stepUp(TOKEN, '000000')).rejects.not.toThrow(/status 429/);
  });

  it('refuses a malformed pairing body as a PAIRING failure, not a vault one', async () => {
    const { client } = clientWith(() => response(201, { expiresAt: MINTED.expiresAt }));
    await expect(client.startExtensionPairing(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'PAIRING_UNAVAILABLE' },
    });
  });

  it('never lets identity’s own error text reach a GraphQL client', async () => {
    const { client } = clientWith(() => response(500, { error: 'pg: relation does not exist' }));
    await expect(client.startExtensionPairing(TOKEN)).rejects.toThrow(/status 500/);
    await expect(client.sessions(TOKEN)).rejects.not.toThrow(/relation does not exist/);
  });
});

describe('the passkey vertical (M17 PR5)', () => {
  const CREATION_OPTIONS = { challenge: 'Y2hhbGxlbmdl', rp: { id: 'localhost' } };
  const ATTESTATION = {
    id: 'cred-1',
    rawId: 'cred-1',
    type: 'public-key',
    clientExtensionResults: {},
    response: { clientDataJSON: 'a', attestationObject: 'b' },
  };

  it('forwards the ceremony payloads OPAQUELY — path, bearer and body, nothing added', async () => {
    // The design claim under test: this edge validates NOTHING about
    // attestation (identity's library owns semantics), so what goes out must
    // be exactly what was handed in.
    const { client, calls } = clientWith((recorded) =>
      recorded.url.endsWith('/register/options')
        ? response(200, CREATION_OPTIONS)
        : response(200, { verified: true }),
    );
    const options = await client.webauthnRegisterOptions(TOKEN);
    expect(options).toEqual(CREATION_OPTIONS);
    await client.webauthnRegister(TOKEN, ATTESTATION);

    expect(calls.map((c) => c.url)).toEqual([
      `${BASE}/v1/auth/webauthn/register/options`,
      `${BASE}/v1/auth/webauthn/register/verify`,
    ]);
    for (const call of calls) {
      expect((call.init.headers as Record<string, string>)['authorization']).toBe(
        `Bearer ${TOKEN}`,
      );
    }
    expect(JSON.parse(calls[1]?.init.body as string)).toEqual(ATTESTATION);
  });

  it('step-up verify parses the elevation and refuses a malformed one as WEBAUTHN_FAILED', async () => {
    const good = clientWith(() =>
      response(200, { mfaLevel: 'stepup', stepupExpiresAt: '2026-08-13T12:05:00Z' }),
    );
    await expect(good.client.webauthnStepUp(TOKEN, ATTESTATION)).resolves.toEqual({
      stepupExpiresAt: '2026-08-13T12:05:00Z',
    });
    // A missing field is NO DATA, never data: an elevation the client cannot
    // read must not be reported as one it can.
    const skewed = clientWith(() => response(200, {}));
    await expect(skewed.client.webauthnStepUp(TOKEN, ATTESTATION)).rejects.toMatchObject({
      extensions: { code: 'WEBAUTHN_FAILED' },
    });
  });

  it('maps webauthn_failed BY TOKEN on both statuses — a refused assertion must not read as a dead session', async () => {
    // Identity answers 400 (registration) AND 401 (assertion) with one token.
    // The 401 half collapsing into UNAUTHENTICATED is the M16 PR2b shape: the
    // client would forget a valid session over a refused ceremony.
    const reg = clientWith(() => response(400, { error: 'webauthn_failed' }));
    await expect(reg.client.webauthnRegister(TOKEN, ATTESTATION)).rejects.toMatchObject({
      extensions: { code: 'WEBAUTHN_FAILED' },
    });
    const assertion = clientWith(() => response(401, { error: 'webauthn_failed' }));
    await expect(assertion.client.webauthnStepUp(TOKEN, ATTESTATION)).rejects.toMatchObject({
      extensions: { code: 'WEBAUTHN_FAILED' },
    });
    // …while a genuinely dead session still surfaces as UNAUTHENTICATED.
    const dead = clientWith(() => response(401, { error: 'unauthorized' }));
    await expect(dead.client.passkeys(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'UNAUTHENTICATED' },
    });
  });

  it('every method surfaces a peer refusal through the one mapper — none swallows', async () => {
    // The error BRANCH of each new method, driven once each: a 403 refusal
    // must arrive as STEPUP_REQUIRED from any of them, because the enrolment
    // gate can fire on options and the revoke route is step-up gated.
    const refused = clientWith(() => response(403, { error: 'stepup_required' }));
    await expect(refused.client.webauthnRegisterOptions(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'STEPUP_REQUIRED' },
    });
    await expect(refused.client.webauthnStepUpOptions(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'STEPUP_REQUIRED' },
    });
    await expect(refused.client.revokePasskey(TOKEN, 'pk-1')).rejects.toMatchObject({
      extensions: { code: 'STEPUP_REQUIRED' },
    });
    await expect(refused.client.renamePasskey(TOKEN, 'pk-1', 'x')).rejects.toMatchObject({
      extensions: { code: 'STEPUP_REQUIRED' },
    });
    await expect(refused.client.webauthnStepUp(TOKEN, {})).rejects.toMatchObject({
      extensions: { code: 'STEPUP_REQUIRED' },
    });
  });

  it('lists passkeys through the shape guard, and refuses a skewed list as no data', async () => {
    const rows = [
      {
        id: 'pk-1',
        nickname: 'MacBook',
        isHardwareKey: false,
        createdAt: '2026-08-13T00:00:00Z',
        lastUsedAt: null,
      },
    ];
    const good = clientWith(() => response(200, { credentials: rows }));
    await expect(good.client.passkeys(TOKEN)).resolves.toEqual(rows);
  });

  it('revoke and rename hit their routes with the id encoded, mapping the uniform 404', async () => {
    const notFound = clientWith(() => response(404, { error: 'not_found' }));
    await expect(notFound.client.revokePasskey(TOKEN, 'pk-9')).rejects.toMatchObject({
      extensions: { code: 'NOT_FOUND' },
    });
    const { client, calls } = clientWith(() => response(204, {}));
    await client.revokePasskey(TOKEN, 'pk 1');
    await client.renamePasskey(TOKEN, 'pk 1', 'YubiKey');
    expect(calls.map((c) => [String(c.init.method), c.url])).toEqual([
      ['DELETE', `${BASE}/v1/auth/webauthn/credentials/pk%201`],
      ['PATCH', `${BASE}/v1/auth/webauthn/credentials/pk%201`],
    ]);
    expect(JSON.parse(calls[1]?.init.body as string)).toEqual({ nickname: 'YubiKey' });
  });
});

/**
 * M20 PR1 — the account password change, the first product consumer of any of
 * M17's six recovery routes.
 */
describe('changePassword', () => {
  it('POSTs both halves to /v1/auth/password on the caller bearer', async () => {
    const { client, calls } = clientWith(() => response(204, undefined));

    await client.changePassword(TOKEN, 'old-passphrase', 'a-much-longer-passphrase');

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/password`);
    expect(calls[0]?.init.method).toBe('POST');
    expect((calls[0]?.init.headers as Record<string, string>).authorization).toBe(
      `Bearer ${TOKEN}`,
    );
    // BOTH halves, in their own fields and not swapped: each covers what the
    // other cannot, so a transposition would send the new password to be
    // VERIFIED and store the old one.
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual({
      currentPassword: 'old-passphrase',
      newPassword: 'a-much-longer-passphrase',
    });
  });

  it('resolves on 204 without parsing the empty body', async () => {
    // The route answers 204 No Content. Parsing it would throw 'identity
    // response was not JSON' and turn every SUCCESSFUL change into an error —
    // a failure that only ever shows up on the happy path.
    const { client } = clientWith(
      () =>
        ({
          ok: true,
          status: 204,
          json: () => Promise.reject(new Error('not JSON')),
          clone() {
            return this;
          },
        }) as unknown as Response,
    );

    await expect(
      client.changePassword(TOKEN, 'old', 'new-long-passphrase'),
    ).resolves.toBeUndefined();
  });

  it.each([
    [401, 'invalid_credentials', 'INVALID_CREDENTIALS'],
    [403, 'stepup_required', 'STEPUP_REQUIRED'],
    [429, 'too_many_attempts', 'TOO_MANY_ATTEMPTS'],
    [400, 'invalid_request', 'INVALID_REQUEST'],
  ] as const)('maps %s %s to %s', async (status, token, code) => {
    // These four have DIFFERENT remedies — re-check the password, find your
    // authenticator, wait, and fix the request — so they must not collapse.
    // 429 in particular is M17's bound firing as designed; the M9 rule is that
    // a control firing must not read as an outage.
    const { client } = clientWith(() => response(status, { error: token }));

    await expect(client.changePassword(TOKEN, 'old', 'new-long-passphrase')).rejects.toMatchObject({
      extensions: { code },
    });
  });

  it('never returns identity’s response text', async () => {
    const { client } = clientWith(() =>
      response(401, { error: 'invalid_credentials', detail: 'hash mismatch for user 42' }),
    );

    // Asserted over the WHOLE serialized error, not just `message`: a detail
    // leaked into `extensions` would satisfy a message-only check while still
    // reaching the browser.
    const thrown = await client
      .changePassword(TOKEN, 'old', 'new-long-passphrase')
      .then(() => null)
      .catch((err: unknown) => err);
    expect(thrown).not.toBeNull();
    expect(JSON.stringify(thrown)).not.toContain('hash mismatch');
    expect(String(thrown)).not.toContain('hash mismatch');
  });
});

/**
 * M20 PR2 — the address change, three legs of one ceremony.
 *
 * THE REQUEST LEG NEEDS ITS OWN ERROR MAPPER, and that is the thing this
 * describe exists to pin. The shared `mapError` keys 400 on the STATUS and
 * answers INVALID_REQUEST — right for most routes and wrong for both of these,
 * because identity answers **400** here for a rejected account password and for
 * every refused code. Without the route-specific mappers a wrong password would
 * reach the browser as "something about that request wasn't right", which names
 * no field and implies no remedy.
 */
describe('email change', () => {
  it('POSTs the request to /v1/auth/email/change/request on the caller bearer', async () => {
    const { client, calls } = clientWith(() => response(202, { status: 'ok' }));

    await client.requestEmailChange(TOKEN, 'the-passphrase', 'new@example.test');

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/email/change/request`);
    expect(calls[0]?.init.method).toBe('POST');
    expect((calls[0]?.init.headers as Record<string, string>).authorization).toBe(
      `Bearer ${TOKEN}`,
    );
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual({
      currentPassword: 'the-passphrase',
      newEmail: 'new@example.test',
    });
  });

  it('resolves the request on 202 WITHOUT treating it as a delivery receipt', async () => {
    // Identity answers before it knows whether it will send anything: the
    // availability lookup, the encrypt, the stage and the mail all run
    // detached, so an address that already belongs to somebody else is answered
    // identically and never mailed. The client returns void — there is no field
    // for a caller to mistake for confirmation — and the surface's copy is
    // conditional because of it.
    const { client } = clientWith(() => response(202, { status: 'ok' }));

    await expect(
      client.requestEmailChange(TOKEN, 'p', 'new@example.test'),
    ).resolves.toBeUndefined();
  });

  it.each([
    [400, 'invalid_credentials', 'INVALID_CREDENTIALS'],
    [400, 'too_soon', 'CODE_REQUESTED_RECENTLY'],
    [400, 'invalid_request', 'INVALID_REQUEST'],
    [403, 'stepup_required', 'STEPUP_REQUIRED'],
    [401, '', 'UNAUTHENTICATED'],
  ] as const)('maps request %s %s to %s', async (status, token, code) => {
    // THREE OF THESE SHARE ONE STATUS. The shared mapper answers 400 by status
    // alone, so all three would arrive as INVALID_REQUEST — a wrong password
    // and a rate refusal both rendered as "review your request".
    const { client } = clientWith(() => response(status, token === '' ? {} : { error: token }));

    await expect(client.requestEmailChange(TOKEN, 'p', 'new@example.test')).rejects.toMatchObject({
      extensions: { code },
    });
  });

  it('POSTs the code to /v1/auth/email/change and resolves on 204', async () => {
    const { client, calls } = clientWith(() => response(204, undefined));

    await expect(client.completeEmailChange(TOKEN, 'EC1-ABCD-EFGH')).resolves.toBeUndefined();
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/email/change`);
    expect(calls[0]?.init.method).toBe('POST');
    // EXACTLY AS TYPED. The canonical fold decides the digest compare and lives
    // in identity; folding here would be a second matching rule free to
    // disagree with the one that matters.
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual({ code: 'EC1-ABCD-EFGH' });
  });

  it('maps every completion refusal to the ONE uniform code', async () => {
    // Identity gives one `invalid_code` for unknown, expired, spent, cancelled,
    // attempt-exhausted, mis-shaped, key-rotated, and address-taken-during-the-
    // window. That uniformity is the control — no progress meter for whoever is
    // guessing, and no leak of another account's existence — so the edge
    // carries it through rather than re-deriving distinctions from it.
    const { client } = clientWith(() => response(400, { error: 'invalid_code' }));

    await expect(client.completeEmailChange(TOKEN, 'EC1-WRONG')).rejects.toMatchObject({
      extensions: { code: 'INVALID_VERIFICATION_CODE' },
    });
  });

  it('DELETEs the cancel to /v1/auth/email/change with no body', async () => {
    const { client, calls } = clientWith(() => response(204, undefined));

    await expect(client.cancelEmailChange(TOKEN)).resolves.toBeUndefined();
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/email/change`);
    expect(calls[0]?.init.method).toBe('DELETE');
    expect(calls[0]?.init.body).toBeUndefined();
  });

  it('never returns identity’s response text on any leg', async () => {
    const leak = 'staged address is victim@example.test';
    const { client } = clientWith(() => response(400, { error: 'invalid_code', detail: leak }));

    // Asserted over the WHOLE serialized error, not just `message`: a detail
    // leaked into `extensions` would satisfy a message-only check while still
    // reaching the browser — and on this ceremony the detail an implementation
    // is most tempted to include is the pending address itself.
    const thrown = await client
      .completeEmailChange(TOKEN, 'EC1-WRONG')
      .then(() => null)
      .catch((err: unknown) => err);
    expect(thrown).not.toBeNull();
    expect(JSON.stringify(thrown)).not.toContain(leak);
    expect(String(thrown)).not.toContain(leak);
  });
});
