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
