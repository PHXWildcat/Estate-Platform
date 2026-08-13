import { HttpNotificationsClient, SERVICE_CREDENTIAL_HEADER, type FetchLike } from '../src/client';

const USER = 'b6c9a1de-0000-4000-8000-000000000001';
/**
 * A REAL minted-shape reset code. The earlier fixture here was `'PR1-ABCD'`,
 * which `RESET_CODE_PATTERN` rejects — this file asserts method, URL and
 * credential rather than the body, so an unroutable payload passed unnoticed
 * and helped hide the client/schema disagreement M17 PR3 shipped. The body
 * itself is now checked against the real schema in
 * `apps/services/notifications/test/wire-parity.spec.ts`.
 */
const RESET_CODE = 'PR1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';
const CHANGE_CODE = 'EC1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';

interface RecordedCall {
  url: string;
  init: { method: string; headers: Record<string, string>; body?: string };
}

function transportDouble(
  respond: (call: RecordedCall) => { ok: boolean; status: number; payload: unknown },
): { fetchImpl: FetchLike; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetchImpl: FetchLike = (url, init) => {
    const call = { url, init };
    calls.push(call);
    const out = respond(call);
    return Promise.resolve({
      ok: out.ok,
      status: out.status,
      json: () => Promise.resolve(out.payload),
    });
  };
  return { fetchImpl, calls };
}

describe('HttpNotificationsClient.send', () => {
  it('posts the content-free payload with the service credential and returns the outcome', async () => {
    const { fetchImpl, calls } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { delivered: true, channel: 'email' },
    }));
    const client = new HttpNotificationsClient({
      notificationsUrl: 'http://notifications:3009/',
      credentials: { send: 'secret', recipients: 'secret' },
      fetchImpl,
    });

    const outcome = await client.send({
      userId: USER,
      kind: 'settlement.case_opened',
      channel: 'push',
      deadline: new Date('2026-08-04T00:00:00.000Z'),
    });

    // M14: `recipientVerified` rides the response so a caller that PROCEEDS on
    // an unverified recipient can record that fact without holding the status
    // credential — settlement is the case that matters.
    expect(outcome).toEqual({
      accepted: true,
      delivered: true,
      channel: 'email',
      recipientVerified: false,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('http://notifications:3009/internal/v1/notifications/send');
    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.init.headers[SERVICE_CREDENTIAL_HEADER]).toBe('secret');
    // The wire has exactly these fields — there is nowhere to put content.
    expect(JSON.parse(calls[0]?.init.body ?? '{}')).toEqual({
      userId: USER,
      kind: 'settlement.case_opened',
      channel: 'push',
      deadline: '2026-08-04T00:00:00.000Z',
    });
  });

  it('defaults the requested channel to email and omits an absent deadline', async () => {
    const { fetchImpl, calls } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { delivered: false, channel: 'email' },
    }));
    const client = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 'secret', recipients: 'secret' },
      fetchImpl,
    });

    const outcome = await client.send({ userId: USER, kind: 'emergency.requested' });

    expect(outcome).toEqual({
      accepted: true,
      delivered: false,
      channel: 'email',
      recipientVerified: false,
    });
    expect(JSON.parse(calls[0]?.init.body ?? '{}')).toEqual({
      userId: USER,
      kind: 'emergency.requested',
      channel: 'email',
    });
  });

  it('short-circuits to not-accepted when the credential is unwired — nothing is sent', async () => {
    const { fetchImpl, calls } = transportDouble(() => {
      throw new Error('must not be called');
    });
    const client = new HttpNotificationsClient({ notificationsUrl: 'http://n', fetchImpl });

    expect(await client.send({ userId: USER, kind: 'emergency.blocked' })).toEqual({
      accepted: false,
    });
    expect(calls).toHaveLength(0);
  });

  it('narrows network failure, non-2xx, and contract drift to not-accepted, never throwing', async () => {
    const failing: FetchLike = () => Promise.reject(new Error('ECONNREFUSED'));
    const network = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 's', recipients: 's' },
      fetchImpl: failing,
    });
    expect(await network.send({ userId: USER, kind: 'vault.reset' })).toEqual({ accepted: false });

    const { fetchImpl: http503 } = transportDouble(() => ({
      ok: false,
      status: 503,
      payload: {},
    }));
    const unavailable = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 's', recipients: 's' },
      fetchImpl: http503,
    });
    expect(await unavailable.send({ userId: USER, kind: 'vault.reset' })).toEqual({
      accepted: false,
    });

    const { fetchImpl: drifted } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { delivered: 'yes' },
    }));
    const drift = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 's', recipients: 's' },
      fetchImpl: drifted,
    });
    expect(await drift.send({ userId: USER, kind: 'vault.reset' })).toEqual({ accepted: false });
  });
});

describe('HttpNotificationsClient.send — the recipient-verified passthrough (M14)', () => {
  it('carries the service answer through verbatim', async () => {
    const { fetchImpl } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { delivered: true, channel: 'email', recipientVerified: true },
    }));
    const client = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 's' },
      fetchImpl,
    });
    expect(await client.send({ userId: USER, kind: 'vault.reset' })).toMatchObject({
      recipientVerified: true,
    });
  });

  it('defaults to FALSE against a service that predates the field', async () => {
    // The safe direction, and why the field is `.default(false)` rather than
    // required: a version skew must degrade to "could not confirm reach", never
    // narrow the whole send to contract drift (which would read as a delivery
    // failure) and never claim a confirmation that was never made.
    const { fetchImpl } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { delivered: true, channel: 'email' },
    }));
    const client = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 's' },
      fetchImpl,
    });
    expect(await client.send({ userId: USER, kind: 'vault.reset' })).toEqual({
      accepted: true,
      delivered: true,
      channel: 'email',
      recipientVerified: false,
    });
  });
});

describe('HttpNotificationsClient transport failures', () => {
  it('narrows a body that is not JSON to the failure outcome, never throwing', async () => {
    // A 200 whose body cannot be parsed is the one transport failure the other
    // cases do not reach: `requestJson` catches it and returns null, so every
    // method degrades to its own recorded non-outcome rather than throwing into
    // a caller that has no error path (the M9 SendOutcome discipline).
    const fetchImpl: FetchLike = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.reject(new Error('not json')),
      });
    const client = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: {
        send: 's',
        recipients: 's',
        verification: 's',
        status: 's',
        security: 's',
        recovery: 's',
      },
      fetchImpl,
    });

    expect(await client.send({ userId: USER, kind: 'vault.reset' })).toEqual({ accepted: false });
    expect(await client.upsertRecipient({ userId: USER, email: 'a@b.c' })).toEqual({ ok: false });
    expect(await client.markRecipientVerified({ userId: USER })).toEqual({ ok: false });
    expect(await client.sendAddressVerification({ userId: USER, code: 'EV1-ABCD' })).toEqual({
      accepted: false,
    });
    expect(
      await client.sendAccountSecurity({ userId: USER, kind: 'identity.password_changed' }),
    ).toEqual({ accepted: false });
    expect(
      await client.sendPasswordReset({
        userId: USER,
        kind: 'identity.password_reset',
        code: RESET_CODE,
      }),
    ).toEqual({
      accepted: false,
    });
    expect(await client.recipientStatus(USER)).toBeNull();
  });
});

describe('HttpNotificationsClient.upsertRecipient', () => {
  it('PUTs the recipient and reports ok on the literal contract answer', async () => {
    const { fetchImpl, calls } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { ok: true },
    }));
    const client = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 'secret', recipients: 'secret' },
      fetchImpl,
    });

    expect(await client.upsertRecipient({ userId: USER, email: 'owner@example.com' })).toEqual({
      ok: true,
    });
    expect(calls[0]?.url).toBe('http://n/internal/v1/notifications/recipients');
    expect(calls[0]?.init.method).toBe('PUT');
  });

  it('reports not-ok on unwired credential, failure, or drift — callers stay best-effort', async () => {
    const unwired = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      fetchImpl: () => Promise.reject(new Error('must not be called')),
    });
    expect(await unwired.upsertRecipient({ userId: USER, email: 'a@b.c' })).toEqual({ ok: false });

    const { fetchImpl: drifted } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { ok: false },
    }));
    const drift = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 's', recipients: 's' },
      fetchImpl: drifted,
    });
    expect(await drift.upsertRecipient({ userId: USER, email: 'a@b.c' })).toEqual({ ok: false });
  });
});

/**
 * ONE CREDENTIAL PER EDGE, enforced at the transport (M14).
 *
 * The point of splitting the fields is that a service holding one capability
 * cannot exercise another, and the place that has to be true is the header
 * this client puts on the wire. A single `serviceCredential` — the pre-M14
 * shape — would have sent identity's recipients secret to the send route and
 * back, which is exactly the M9 collapse re-created inside one object.
 */
describe('HttpNotificationsClient credential partitioning', () => {
  const ALL = {
    send: 'send-cred',
    recipients: 'rcpt-cred',
    verification: 'verify-cred',
    status: 'status-cred',
    security: 'security-cred',
    recovery: 'recovery-cred',
    emailChange: 'echange-cred',
  };

  it('routes each capability to its own path with its own secret', async () => {
    const { fetchImpl, calls } = transportDouble(({ url }) => ({
      ok: true,
      status: 200,
      payload: url.endsWith('/status')
        ? { verified: true }
        : url.endsWith('/verified')
          ? { ok: true }
          : { delivered: true, channel: 'email' },
    }));
    const client = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: ALL,
      fetchImpl,
    });

    await client.send({ userId: USER, kind: 'vault.reset' });
    await client.upsertRecipient({ userId: USER, email: 'a@b.c' });
    await client.markRecipientVerified({ userId: USER });
    await client.sendAddressVerification({ userId: USER, code: 'EV1-ABCD' });
    await client.sendAccountSecurity({ userId: USER, kind: 'identity.password_changed' });
    await client.sendPasswordReset({
      userId: USER,
      kind: 'identity.password_reset',
      code: RESET_CODE,
    });
    await client.sendEmailChange({
      userId: USER,
      kind: 'identity.email_change',
      code: CHANGE_CODE,
      email: 'new@example.com',
    });
    await client.replaceRecipient({ userId: USER, email: 'new@example.com' });
    await client.recipientStatus(USER);

    expect(
      calls.map((call) => [
        call.init.method,
        call.url.replace('http://n/internal/v1/notifications', ''),
        call.init.headers[SERVICE_CREDENTIAL_HEADER],
      ]),
    ).toEqual([
      ['POST', '/send', 'send-cred'],
      ['PUT', '/recipients', 'rcpt-cred'],
      // Vouching rides the RECIPIENTS credential: setting an address and
      // declaring it proved are the same capability class (M14 decision 5).
      ['PUT', `/recipients/${USER}/verified`, 'rcpt-cred'],
      ['POST', '/verification', 'verify-cred'],
      // M17. Its OWN path and its OWN secret: announcing a credential change is
      // neither an estate send (vault, settlement and profile hold that) nor a
      // verification code (a future resend holder must not inherit this).
      ['POST', '/security', 'security-cred'],
      // M17 PR3. Its OWN path and its OWN secret, and this is the row that
      // matters most: what this route mails can be redeemed with no session, so
      // it must not share a credential with the verification code beside it.
      ['POST', '/recovery', 'recovery-cred'],
      // M17 PR4. Its OWN path and its OWN secret: the one send whose payload
      // names a destination must not share a credential with anything that
      // merely sends — a future holder of any sibling must not inherit the
      // power to aim platform mail at arbitrary addresses.
      ['POST', '/email-change', 'echange-cred'],
      // Repoint-and-vouch rides RECIPIENTS, exactly as `verified` does: both
      // decide what the store believes about reaching a user.
      ['PUT', `/recipients/${USER}/replace`, 'rcpt-cred'],
      ['GET', `/recipients/${USER}/status`, 'status-cred'],
    ]);
  });

  it('makes NO round trip for a capability it does not hold', async () => {
    // A service granted only `send` must not even announce itself to the other
    // routes: an over-broad client should be a configuration that cannot reach
    // them, not one that reaches them and is rejected.
    const { fetchImpl, calls } = transportDouble(() => {
      throw new Error('must not be called');
    });
    const sendOnly = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { send: 'send-cred' },
      fetchImpl,
    });

    expect(await sendOnly.upsertRecipient({ userId: USER, email: 'a@b.c' })).toEqual({ ok: false });
    expect(await sendOnly.markRecipientVerified({ userId: USER })).toEqual({ ok: false });
    expect(await sendOnly.sendAddressVerification({ userId: USER, code: 'EV1-ABCD' })).toEqual({
      accepted: false,
    });
    // M17. A send-only holder must not be able to announce a credential change:
    // no round trip at all, so an over-broad client is a configuration that
    // CANNOT REACH the route rather than one the route rejects.
    expect(
      await sendOnly.sendAccountSecurity({ userId: USER, kind: 'identity.password_changed' }),
    ).toEqual({ accepted: false });
    // M17 PR4. Nor mail a challenge to an arbitrary address, nor repoint the
    // store: the destination-naming send and the repoint-and-vouch are the two
    // capabilities a send-only holder must be furthest from.
    expect(
      await sendOnly.sendEmailChange({
        userId: USER,
        kind: 'identity.email_change',
        code: CHANGE_CODE,
        email: 'anywhere@example.com',
      }),
    ).toEqual({ accepted: false });
    expect(
      await sendOnly.replaceRecipient({ userId: USER, email: 'anywhere@example.com' }),
    ).toEqual({ ok: false });
    expect(
      await sendOnly.sendPasswordReset({
        userId: USER,
        kind: 'identity.password_reset',
        code: RESET_CODE,
      }),
    ).toEqual({
      accepted: false,
    });
    expect(await sendOnly.recipientStatus(USER)).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it('the DEFAULT transport is real fetch, and a dead peer degrades to the failure outcome', async () => {
    // No fetchImpl injected — this is the one test that executes the default
    // arrow, against a port nothing listens on. The property is the client's
    // whole error contract in one line: ANY transport failure is an outcome,
    // never a throw, because a notification failure must not roll back the
    // state change it describes.
    const real = new HttpNotificationsClient({
      notificationsUrl: 'http://127.0.0.1:1',
      credentials: { send: 'send-cred' },
    });
    await expect(real.send({ userId: USER, kind: 'vault.reset' })).resolves.toEqual({
      accepted: false,
    });
  });

  it('answers null — not false — when the status query is unanswerable', async () => {
    // The distinction is the whole reason the return type is nullable: an
    // outage and a genuinely unverified address are different facts, and the
    // arming gates must state what an outage means rather than inherit it from
    // a flattened boolean.
    const cases: FetchLike[] = [
      () => Promise.reject(new Error('ECONNREFUSED')),
      () => Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) }),
      () =>
        Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ verified: 'yes' }),
        }),
    ];
    for (const fetchImpl of cases) {
      const client = new HttpNotificationsClient({
        notificationsUrl: 'http://n',
        credentials: { status: 'status-cred' },
        fetchImpl,
      });
      expect(await client.recipientStatus(USER)).toBeNull();
    }

    const { fetchImpl: ok } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { verified: false },
    }));
    const answered = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { status: 'status-cred' },
      fetchImpl: ok,
    });
    expect(await answered.recipientStatus(USER)).toEqual({ verified: false });
  });

  it('sends the verification code as a typed field and nothing else', async () => {
    const { fetchImpl, calls } = transportDouble(() => ({
      ok: true,
      status: 200,
      payload: { delivered: true, channel: 'email' },
    }));
    const client = new HttpNotificationsClient({
      notificationsUrl: 'http://n',
      credentials: { verification: 'verify-cred' },
      fetchImpl,
    });

    expect(await client.sendAddressVerification({ userId: USER, code: 'EV1-ABCD' })).toEqual({
      accepted: true,
      delivered: true,
      channel: 'email',
      recipientVerified: false,
    });
    // Two fields. There is no subject, no body, no text — the approved
    // deviation is a CODE, and the wire is what makes that literal.
    expect(JSON.parse(calls[0]?.init.body ?? '{}')).toEqual({ userId: USER, code: 'EV1-ABCD' });
  });
});
