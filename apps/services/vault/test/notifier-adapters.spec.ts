import type { NotificationsPort, SendOutcome } from '@estate/notifications-client';
import { HttpNotifier, StubNotifier } from '../src/notifications';

const OWNER = 'c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f';

/**
 * The vault's real notification adapter.
 *
 * It carries the M14 decision the whole arming gate rests on: an UNANSWERABLE
 * status query collapses to `false` HERE, at the boundary that knows what the
 * question was for. The shared client deliberately returns `null` so that
 * decision cannot be inherited by accident, which means this file is where it
 * has to be pinned — and until the M14 review it had no test at all.
 */
function clientDouble(overrides: Partial<NotificationsPort>): NotificationsPort {
  return {
    send: (): Promise<SendOutcome> => Promise.resolve({ accepted: false }),
    upsertRecipient: () => Promise.resolve({ ok: false }),
    sendAddressVerification: (): Promise<SendOutcome> => Promise.resolve({ accepted: false }),
    // M17. Present because the port declares it, and REFUSING because vault
    // holds no account-security credential — the client would short-circuit
    // without a round trip anyway. A double that quietly SUCCEEDED here would
    // let a vault code path that should never reach this method look healthy
    // (the M16 PR4a lesson about doubles that accept what the platform refuses).
    sendAccountSecurity: (): Promise<SendOutcome> => Promise.resolve({ accepted: false }),
    // M17 PR3, same reasoning: present because the port declares it, REFUSING
    // because vault holds no recovery credential and the real client would
    // short-circuit without a round trip.
    sendPasswordReset: (): Promise<SendOutcome> => Promise.resolve({ accepted: false }),
    markRecipientVerified: () => Promise.resolve({ ok: false }),
    recipientStatus: () => Promise.resolve(null),
    ...overrides,
  };
}

describe('HttpNotifier.recipientVerified', () => {
  it('is TRUE only when the store says so', async () => {
    const notifier = new HttpNotifier(
      clientDouble({ recipientStatus: () => Promise.resolve({ verified: true }) }),
    );
    await expect(notifier.recipientVerified(OWNER)).resolves.toBe(true);
  });

  it('is FALSE for a real unverified answer', async () => {
    const notifier = new HttpNotifier(
      clientDouble({ recipientStatus: () => Promise.resolve({ verified: false }) }),
    );
    await expect(notifier.recipientVerified(OWNER)).resolves.toBe(false);
  });

  it('FAILS CLOSED when the question cannot be answered', async () => {
    // `null` is the client's UNANSWERABLE — no credential, network failure,
    // non-2xx, contract drift. It must never read as permission. An outage
    // therefore delays a legitimate owner by minutes, where the other direction
    // hands an attacker the whole §5.2 waiting period.
    const notifier = new HttpNotifier(
      clientDouble({ recipientStatus: () => Promise.resolve(null) }),
    );
    await expect(notifier.recipientVerified(OWNER)).resolves.toBe(false);
  });

  it('asks about the OWNER, and nobody else', async () => {
    const asked: string[] = [];
    const notifier = new HttpNotifier(
      clientDouble({
        recipientStatus: (userId: string) => {
          asked.push(userId);
          return Promise.resolve({ verified: true });
        },
      }),
    );
    await notifier.recipientVerified(OWNER);
    expect(asked).toEqual([OWNER]);
  });
});

describe('HttpNotifier.notify', () => {
  it('reports non-delivery rather than throwing', async () => {
    // M14 changed this from throw-based to outcome-based because an exception
    // cannot carry the second fact a send now reports. The regression that
    // followed — `vault.service.ts` still assuming a throw, and so recording
    // every reset as delivered — is why the behaviour is pinned here.
    const notifier = new HttpNotifier(clientDouble({}));
    await expect(
      notifier.notify({ kind: 'reset', ownerUserId: OWNER, policyId: null }),
    ).resolves.toEqual({ delivered: false, recipientVerified: false });
  });

  it('passes the delivery and verification facts through verbatim', async () => {
    const notifier = new HttpNotifier(
      clientDouble({
        send: () =>
          Promise.resolve({
            accepted: true,
            delivered: true,
            channel: 'email',
            recipientVerified: true,
          }),
      }),
    );
    await expect(
      notifier.notify({ kind: 'requested', ownerUserId: OWNER, policyId: 'p1' }),
    ).resolves.toEqual({ delivered: true, recipientVerified: true });
  });

  it('treats an accepted-but-undelivered send as a non-delivery', async () => {
    const notifier = new HttpNotifier(
      clientDouble({
        send: () =>
          Promise.resolve({
            accepted: true,
            delivered: false,
            channel: 'email',
            recipientVerified: false,
          }),
      }),
    );
    await expect(
      notifier.notify({ kind: 'released', ownerUserId: OWNER, policyId: 'p1' }),
    ).resolves.toEqual({ delivered: false, recipientVerified: false });
  });

  it('carries the deadline only when the notification has one', async () => {
    const sent: Array<Record<string, unknown>> = [];
    const notifier = new HttpNotifier(
      clientDouble({
        send: (input) => {
          sent.push(input as unknown as Record<string, unknown>);
          return Promise.resolve({
            accepted: true,
            delivered: true,
            channel: 'email',
            recipientVerified: false,
          });
        },
      }),
    );
    const releasesAt = new Date('2026-08-20T00:00:00.000Z');
    await notifier.notify({ kind: 'requested', ownerUserId: OWNER, policyId: 'p1', releasesAt });
    await notifier.notify({ kind: 'revoked', ownerUserId: OWNER, policyId: 'p1' });
    expect(sent[0]).toMatchObject({ kind: 'emergency.requested', deadline: releasesAt });
    expect(sent[1]).not.toHaveProperty('deadline');
  });
});

describe('StubNotifier', () => {
  it('records what would have been sent, and vouches for nothing', async () => {
    const stub = new StubNotifier();
    await expect(stub.recipientVerified()).resolves.toBe(false);
    await expect(
      stub.notify({ kind: 'reset', ownerUserId: OWNER, policyId: null }),
    ).resolves.toEqual({ delivered: true, recipientVerified: false });
    expect(stub.sent).toEqual([{ kind: 'reset', ownerUserId: OWNER, policyId: null }]);
    expect(stub.deliversToRealChannels).toBe(false);
  });
});
