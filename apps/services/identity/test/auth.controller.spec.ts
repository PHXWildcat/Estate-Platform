/**
 * THE CONTROLLER'S OWN INVARIANT: WHO A HANDLER ACTS FOR.
 *
 * Every authenticated route here takes the subject from `request.auth` — the
 * context `SessionGuard` attached after verifying the presented token — and
 * never from the body, the query or a path parameter. That is the whole of the
 * controller's contribution to authorization, and until now nothing tested it:
 * `auth.controller.ts` had NO unit spec, and the integration suites that reach
 * it only run with `PG_TEST_URL`, so on an ordinary developer machine 23 route
 * handlers were 0% covered.
 *
 * The gap was found by the M16 PR5 review while chasing a coverage floor that
 * had drifted under without anyone noticing — CI always sets `PG_TEST_URL`, so
 * the number the floor was calibrated against is the one number nothing
 * measured. It is the M9 PR2 shape exactly, where the notifications floor "was
 * set from a number CI never produced" and was closed by the controller's first
 * specs.
 *
 * WHAT THIS PINS, and why each is worth a test rather than a reading:
 *
 *   · the subject is the CALLER'S. A handler that read a `userId` from the body
 *     would be a horizontal-privilege defect with no other control standing in
 *     front of it — the guard verifies the token, it does not check that the
 *     handler then used it.
 *   · `parseBody` refuses malformed input with one token and NEVER echoes the
 *     submitted value, which is what keeps a validation error from becoming a
 *     reflection of whatever was sent.
 *   · `requireAuth` fails CLOSED on a wiring mistake. It is unreachable behind
 *     the guard, which is exactly why nothing would notice if it stopped
 *     throwing.
 *
 * It is a UNIT spec against faked services on purpose: what is under test is
 * the controller's own dispatch, and a Postgres-backed test would prove the
 * services instead. The int suites already do that.
 */
import { BadRequestException } from '@nestjs/common';
import type { AuthService } from '../src/auth.service';
import { AuthController } from '../src/auth.controller';
import type { EmailVerificationService } from '../src/email-verification.service';
import type { ExtensionPairingService } from '../src/extension-pairing.service';
import type { HandoffService } from '../src/handoff.service';
import type { AuthedRequest, SessionContext } from '../src/session.guard';
import type { WebAuthnService } from '../src/webauthn.service';

const CALLER: SessionContext = {
  userId: 'caller-user',
  sessionId: 'caller-session',
  mfaLevel: 'stepup',
  stepupExpiresAt: new Date('2026-08-12T00:05:00.000Z'),
  audience: 'account',
};

/** What a hostile body would carry if a handler could be talked into reading it. */
const IMPOSTOR = { userId: 'victim-user', sessionId: 'victim-session' };

interface Fakes {
  auth: Record<string, jest.Mock>;
  webauthn: Record<string, jest.Mock>;
  emailVerification: Record<string, jest.Mock>;
  handoff: Record<string, jest.Mock>;
  extensionPairing: Record<string, jest.Mock>;
}

function makeFakes(): Fakes {
  const fn = (value: unknown): jest.Mock => jest.fn().mockResolvedValue(value);
  return {
    auth: {
      register: fn(undefined),
      login: fn({ accessToken: 'a', refreshToken: 'r', sessionId: 's', userId: 'u' }),
      refresh: fn({ accessToken: 'a', refreshToken: 'r', sessionId: 's', userId: 'u' }),
      logout: fn(undefined),
      logoutByRefreshToken: fn(undefined),
      enrollTotp: fn({ methodId: 'm', otpauthUri: 'otpauth://totp/x?secret=Y' }),
      verifyTotp: fn(undefined),
      stepUp: fn({ mfaLevel: 'stepup', stepupExpiresAt: '2026-08-12T00:05:00.000Z' }),
      listSessions: fn([]),
      revokeOwnSession: fn(undefined),
    },
    webauthn: {
      registrationOptions: fn({ challenge: 'c' }),
      verifyRegistration: fn({ verified: true }),
      authenticationOptions: fn({ challenge: 'c' }),
      verifyAuthentication: fn({
        accessToken: 'a',
        refreshToken: 'r',
        sessionId: 's',
        userId: 'u',
      }),
    },
    emailVerification: {
      status: fn({ verified: false }),
      reissue: fn('sent'),
      verify: fn(undefined),
    },
    handoff: { mint: fn({ code: 'EV1-AAAA', expiresAt: new Date('2026-08-12T00:01:00.000Z') }) },
    extensionPairing: {
      mint: fn({ code: 'EP1-AAAA', expiresAt: new Date('2026-08-12T00:10:00.000Z') }),
      redeem: fn({
        accessToken: 'a',
        refreshToken: 'r',
        userId: 'u',
        sessionId: 's',
        expiresAt: new Date('2026-09-11T00:00:00.000Z'),
      }),
    },
  };
}

function makeController(fakes: Fakes): AuthController {
  return new AuthController(
    fakes.auth as unknown as AuthService,
    fakes.webauthn as unknown as WebAuthnService,
    fakes.emailVerification as unknown as EmailVerificationService,
    fakes.handoff as unknown as HandoffService,
    fakes.extensionPairing as unknown as ExtensionPairingService,
  );
}

const authed = (): AuthedRequest => ({ headers: {}, auth: { ...CALLER } });
const unauthed = (): AuthedRequest => ({ headers: {} });

describe('AuthController takes the subject from the verified session', () => {
  /**
   * Every authenticated handler, driven with a body that TRIES to name somebody
   * else. The assertion is on the arguments each service call received: the
   * caller's own ids, and never the impostor's.
   */
  const CASES: ReadonlyArray<{
    name: string;
    run: (c: AuthController) => Promise<unknown>;
    called: (f: Fakes) => jest.Mock;
  }> = [
    {
      name: 'logout',
      run: (c) => c.logout(authed()),
      called: (f) => f.auth['logout'] as jest.Mock,
    },
    {
      name: 'emailVerificationStatus',
      run: (c) => c.emailVerificationStatus(authed()),
      called: (f) => f.emailVerification['status'] as jest.Mock,
    },
    {
      name: 'resendEmailVerification',
      run: (c) => c.resendEmailVerification(authed()),
      called: (f) => f.emailVerification['reissue'] as jest.Mock,
    },
    {
      name: 'verifyEmail',
      run: (c) => c.verifyEmail(authed(), { ...IMPOSTOR, code: 'EV1-ABCD-EFGH-JKMN' }),
      called: (f) => f.emailVerification['verify'] as jest.Mock,
    },
    {
      name: 'enrollTotp',
      run: (c) => c.enrollTotp(authed()),
      called: (f) => f.auth['enrollTotp'] as jest.Mock,
    },
    {
      name: 'verifyTotp',
      run: (c) => c.verifyTotp(authed(), { ...IMPOSTOR, code: '123456' }),
      called: (f) => f.auth['verifyTotp'] as jest.Mock,
    },
    {
      name: 'stepUp',
      run: (c) => c.stepUp(authed(), { ...IMPOSTOR, code: '123456' }),
      called: (f) => f.auth['stepUp'] as jest.Mock,
    },
    {
      name: 'mintHandoff',
      run: (c) => c.mintHandoff(authed()),
      called: (f) => f.handoff['mint'] as jest.Mock,
    },
    {
      name: 'listSessions',
      run: (c) => c.listSessions(authed()),
      called: (f) => f.auth['listSessions'] as jest.Mock,
    },
    {
      name: 'mintExtensionPairing',
      run: (c) => c.mintExtensionPairing(authed()),
      called: (f) => f.extensionPairing['mint'] as jest.Mock,
    },
  ];

  it.each(CASES)(
    '$name acts for the caller, never for a body-supplied id',
    async ({ run, called }) => {
      const fakes = makeFakes();
      await run(makeController(fakes));

      const call = called(fakes).mock.calls[0] as unknown[];
      expect(call[0]).toBe(CALLER.userId);
      // Whatever else it passes, nothing the body offered reached the service.
      const serialised = JSON.stringify(call);
      expect(serialised).not.toContain(IMPOSTOR.userId);
      expect(serialised).not.toContain(IMPOSTOR.sessionId);
    },
  );

  it('revokeSession names the caller as owner and the PATH id as the target', async () => {
    // The one route whose subject and object differ, and the shape that makes
    // `revokeOwned` safe: the id to kill comes from the path, the owner it must
    // belong to comes from the session.
    const fakes = makeFakes();
    const target = '11111111-2222-4333-8444-555555555555';
    await makeController(fakes).revokeSession(authed(), target);
    expect(fakes.auth['revokeOwnSession']).toHaveBeenCalledWith(CALLER.userId, target);
  });

  it('revokeSession refuses a path id that is not a uuid', async () => {
    const fakes = makeFakes();
    await expect(makeController(fakes).revokeSession(authed(), 'not-a-uuid')).rejects.toThrow(
      BadRequestException,
    );
    expect(fakes.auth['revokeOwnSession']).not.toHaveBeenCalled();
  });

  it('enrollTotp hands the SESSION CONTEXT down, which is what the gate reads', async () => {
    // M16 PR5: enrolment is step-up gated when a verified factor exists, and the
    // condition lives in the service — so the controller has to pass the context
    // the guard attached. Passing anything else would make the gate read a
    // freshness that is not the caller's.
    const fakes = makeFakes();
    await makeController(fakes).enrollTotp(authed());
    expect(fakes.auth['enrollTotp']).toHaveBeenCalledWith(
      CALLER.userId,
      CALLER.sessionId,
      expect.objectContaining({ mfaLevel: 'stepup', stepupExpiresAt: CALLER.stepupExpiresAt }),
    );
  });

  it('session() describes the presented token and asserts nothing else', async () => {
    const controller = makeController(makeFakes());
    expect(controller.session(authed())).toEqual({
      userId: CALLER.userId,
      sessionId: CALLER.sessionId,
      mfaLevel: 'stepup',
      stepupExpiresAt: '2026-08-12T00:05:00.000Z',
      audience: 'account',
    });
    await Promise.resolve();
  });

  it('session() reports a null step-up as null rather than omitting it', () => {
    const controller = makeController(makeFakes());
    const request: AuthedRequest = {
      headers: {},
      auth: { ...CALLER, mfaLevel: 'none', stepupExpiresAt: null },
    };
    expect(controller.session(request)).toMatchObject({ mfaLevel: 'none', stepupExpiresAt: null });
  });
});

describe('AuthController fails closed on bad input and bad wiring', () => {
  /**
   * `requireAuth` is unreachable behind `SessionGuard`, which is precisely why
   * it needs a test: nothing would notice if it stopped throwing, and what it
   * guards against is a route registered without its guard.
   */
  const UNGUARDED: ReadonlyArray<{ name: string; run: (c: AuthController) => unknown }> = [
    { name: 'logout', run: (c) => c.logout(unauthed()) },
    { name: 'session', run: (c) => c.session(unauthed()) },
    { name: 'enrollTotp', run: (c) => c.enrollTotp(unauthed()) },
    { name: 'stepUp', run: (c) => c.stepUp(unauthed(), { code: '123456' }) },
    { name: 'listSessions', run: (c) => c.listSessions(unauthed()) },
    { name: 'mintHandoff', run: (c) => c.mintHandoff(unauthed()) },
  ];

  it.each(UNGUARDED)('$name refuses when no session was attached', async ({ run }) => {
    const fakes = makeFakes();
    const controller = makeController(fakes);
    await expect(Promise.resolve().then(() => run(controller))).rejects.toThrow(
      BadRequestException,
    );
    // And it refused BEFORE reaching anything that acts.
    const groups: Record<string, jest.Mock>[] = [
      fakes.auth,
      fakes.webauthn,
      fakes.emailVerification,
      fakes.handoff,
      fakes.extensionPairing,
    ];
    for (const group of groups) {
      for (const mock of Object.values(group)) expect(mock).not.toHaveBeenCalled();
    }
  });

  const MALFORMED: ReadonlyArray<{ name: string; run: (c: AuthController) => Promise<unknown> }> = [
    { name: 'register', run: (c) => c.register({ email: 'not-an-email', password: 'x' }) },
    { name: 'login', run: (c) => c.login({}) },
    { name: 'refresh', run: (c) => c.refresh({ refreshToken: 42 }) },
    { name: 'logoutByRefresh', run: (c) => c.logoutByRefresh({}) },
    { name: 'verifyTotp', run: (c) => c.verifyTotp(authed(), { code: 'abcdef' }) },
    { name: 'stepUp', run: (c) => c.stepUp(authed(), { code: '1' }) },
    { name: 'verifyEmail', run: (c) => c.verifyEmail(authed(), { code: '' }) },
    { name: 'redeemHandoff', run: (c) => c.redeemHandoff({ code: '' }) },
    { name: 'redeemExtensionPairing', run: (c) => c.redeemExtensionPairing({ code: '' }) },
  ];

  it.each(MALFORMED)('$name rejects a malformed body with one token', async ({ run }) => {
    const controller = makeController(makeFakes());
    await expect(run(controller)).rejects.toMatchObject({
      response: { error: 'invalid_request' },
    });
  });

  it('NEVER echoes the submitted value in a validation error', async () => {
    // A validation error that reflected its input would turn every schema in
    // the service into a mirror for whatever an attacker sent.
    const controller = makeController(makeFakes());
    const secret = 'correct-horse-battery-staple';
    await expect(
      controller.register({ email: 'not-an-email', password: secret }),
    ).rejects.toMatchObject({ response: { error: 'invalid_request' } });
    try {
      await controller.register({ email: 'not-an-email', password: secret });
    } catch (err) {
      expect(JSON.stringify(err)).not.toContain(secret);
      expect((err as Error).message).not.toContain(secret);
    }
  });
});

describe('AuthController passes credentials through without reshaping them', () => {
  it('register answers the same shape whatever the service did', async () => {
    const fakes = makeFakes();
    await expect(
      makeController(fakes).register({ email: 'a@example.com', password: 'a-long-enough-secret' }),
    ).resolves.toEqual({ status: 'ok' });
    expect(fakes.auth['register']).toHaveBeenCalledWith('a@example.com', 'a-long-enough-secret');
  });

  it('login and refresh return the issued tokens untouched', async () => {
    const fakes = makeFakes();
    const controller = makeController(fakes);
    const issued = { accessToken: 'a', refreshToken: 'r', sessionId: 's', userId: 'u' };
    await expect(
      controller.login({ email: 'a@example.com', password: 'a-long-enough-secret' }),
    ).resolves.toEqual(issued);
    await expect(controller.refresh({ refreshToken: 'r' })).resolves.toEqual(issued);
  });

  it('mintHandoff and mintExtensionPairing serialise their expiry as ISO', async () => {
    // Both mint a code the caller must type or post; a Date crossing JSON
    // un-serialised is how one of them starts arriving as `{}`.
    const controller = makeController(makeFakes());
    await expect(controller.mintHandoff(authed())).resolves.toEqual({
      code: 'EV1-AAAA',
      expiresAt: '2026-08-12T00:01:00.000Z',
    });
    await expect(controller.mintExtensionPairing(authed())).resolves.toEqual({
      code: 'EP1-AAAA',
      expiresAt: '2026-08-12T00:10:00.000Z',
    });
  });

  it('emailVerificationStatus keeps `unavailable` apart from `unverified`', async () => {
    // M14's rule: an outage must not read as an unverified address, because the
    // remedies differ and one of them cannot even be attempted.
    const fakes = makeFakes();
    (fakes.emailVerification['status'] as jest.Mock).mockResolvedValue(null);
    await expect(makeController(fakes).emailVerificationStatus(authed())).resolves.toEqual({
      status: 'unavailable',
    });

    (fakes.emailVerification['status'] as jest.Mock).mockResolvedValue({ verified: true });
    await expect(makeController(fakes).emailVerificationStatus(authed())).resolves.toEqual({
      status: 'verified',
    });
  });
});
