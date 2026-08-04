import { HttpNotificationsClient, SERVICE_CREDENTIAL_HEADER, type FetchLike } from '../src/client';

const USER = 'b6c9a1de-0000-4000-8000-000000000001';

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
      serviceCredential: 'secret',
      fetchImpl,
    });

    const outcome = await client.send({
      userId: USER,
      kind: 'settlement.case_opened',
      channel: 'push',
      deadline: new Date('2026-08-04T00:00:00.000Z'),
    });

    expect(outcome).toEqual({ accepted: true, delivered: true, channel: 'email' });
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
      serviceCredential: 'secret',
      fetchImpl,
    });

    const outcome = await client.send({ userId: USER, kind: 'emergency.requested' });

    expect(outcome).toEqual({ accepted: true, delivered: false, channel: 'email' });
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
      serviceCredential: 's',
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
      serviceCredential: 's',
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
      serviceCredential: 's',
      fetchImpl: drifted,
    });
    expect(await drift.send({ userId: USER, kind: 'vault.reset' })).toEqual({ accepted: false });
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
      serviceCredential: 'secret',
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
      serviceCredential: 's',
      fetchImpl: drifted,
    });
    expect(await drift.upsertRecipient({ userId: USER, email: 'a@b.c' })).toEqual({ ok: false });
  });
});
