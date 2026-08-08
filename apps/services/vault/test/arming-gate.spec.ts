import { ServiceUnavailableException } from '@nestjs/common';
import { StubNotifier, type NotificationPort } from '../src/notifications';
import { EmergencyAccessService } from '../src/emergency.service';
import type { VaultConfig } from '../src/config';
import type { Db } from '../src/db';
import type { EmergencyRepo } from '../src/emergency.repo';
import type { EventsService } from '../src/events.service';
import type { KeysetsRepo } from '../src/keysets.repo';
import type { VaultAuthz } from '../src/authz.service';

/**
 * THE ARMING GATE (M14).
 *
 * `deliversToRealChannels` — the bit M6, M7 and M13 all rested on — is a
 * hardcoded literal on an adapter class, chosen at DI time from this service's
 * own NOTIFY_MODE. It asks whether SES is wired. It never asks whether the
 * stored address belongs to the owner, and could not: it never looks at a
 * recipient. So an escrow could arm, the §5.2 clock could start, and the
 * notification whose whole purpose is to let the owner INTERRUPT it could be
 * going to an address they had never confirmed.
 *
 * These cases pin the half that is genuinely new: a per-recipient question,
 * asked before the capability exists, failing closed.
 */

const OWNER = 'c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f';

function configFor(nodeEnv: VaultConfig['nodeEnv']): VaultConfig {
  return {
    nodeEnv,
    port: 3006,
    databaseUrl: 'postgres://localhost/vault',
    kafkaBrokers: null,
    identityUrl: 'http://localhost:3001',
    notify: { mode: 'stub' },
    settlementUrl: 'http://localhost:3007',
    settlementInternalToken: 's'.repeat(32),
    notificationsUrl: 'http://localhost:3008',
    notificationsInternalToken: '',
    notificationsStatusToken: '',
  };
}

interface Harness {
  service: EmergencyAccessService;
  emitted: Array<Record<string, unknown>>;
  statusAsked: string[];
}

/**
 * Nothing here reaches the database: the gates fire before any other work, so a
 * proxy that throws on every access proves the refusal happened FIRST rather
 * than after some state had already moved.
 */
function harness(
  nodeEnv: VaultConfig['nodeEnv'],
  notifier: NotificationPort,
  statusAsked: string[] = [],
): Harness {
  const unusable = new Proxy(
    {},
    {
      get: () => (): never => {
        throw new Error('the gate must fire before any other work');
      },
    },
  );
  const emitted: Array<Record<string, unknown>> = [];
  const events = {
    audit: {
      emit: (event: Record<string, unknown>): Promise<void> => {
        emitted.push(event);
        return Promise.resolve();
      },
    },
  } as unknown as EventsService;
  const service = new EmergencyAccessService(
    unusable as Db,
    unusable as EmergencyRepo,
    unusable as KeysetsRepo,
    { assertCan: (): void => undefined } as unknown as VaultAuthz,
    events,
    notifier,
    { checkVaultRelease: () => Promise.resolve({ permitted: true, caseId: null }) },
    configFor(nodeEnv),
    () => new Date('2026-08-01T00:00:00.000Z'),
  );
  return { service, emitted, statusAsked };
}

/** A production-shaped adapter whose only variable is the recipient answer. */
function realNotifier(verified: boolean | 'throws', asked: string[]): NotificationPort {
  return {
    channel: 'ses',
    deliversToRealChannels: true,
    recipientVerified: (ownerUserId: string): Promise<boolean> => {
      asked.push(ownerUserId);
      // The PORT is what collapses an unanswerable query to false; an adapter
      // that threw would be breaking its own contract, and the gate must still
      // refuse rather than propagate.
      return verified === 'throws'
        ? Promise.reject(new Error('notifications unreachable'))
        : Promise.resolve(verified);
    },
    notify: () => Promise.resolve({ delivered: true, recipientVerified: verified === true }),
  };
}

const GRANTEE = '11112222-3333-4444-8555-666677778888';

const CONFIGURE_INPUT = {
  threshold: 1,
  platformPart: Buffer.alloc(32).toString('base64'),
  wrappedMasterKeyRecovery: 'AAAA',
  grantees: [
    {
      granteeContactId: GRANTEE,
      granteeUserId: GRANTEE,
      keyShare: 'AAAA',
      granteePublicKeySha256: Buffer.alloc(32).toString('base64'),
      waitingPeriodHours: 24,
    },
  ],
};

describe('escrow configure — the arming gate', () => {
  it('REFUSES in production when the owner never proved their address', async () => {
    const asked: string[] = [];
    const h = harness('production', realNotifier(false, asked), asked);

    await expect(h.service.configure(OWNER, 'session', CONFIGURE_INPUT)).rejects.toThrow(
      ServiceUnavailableException,
    );
    // Asked about the OWNER, and refused before any database work.
    expect(asked).toEqual([OWNER]);
  });

  it('answers `recipient_unverified`, distinct from the adapter refusal', async () => {
    // Two different operator responses: "SES is not wired" is a deployment
    // problem; "this owner never confirmed their address" is the owner's to
    // fix. Collapsing them into one token would send an operator hunting a
    // carrier outage that does not exist.
    const asked: string[] = [];
    const h = harness('production', realNotifier(false, asked), asked);

    await h.service.configure(OWNER, 'session', CONFIGURE_INPUT).catch((err: unknown) => {
      expect((err as ServiceUnavailableException).getResponse()).toEqual({
        error: 'recipient_unverified',
      });
    });
    expect.assertions(2);

    const refusal = h.emitted.find(
      (event) => event['action'] === 'vault.emergency.notifications_refused',
    );
    expect(refusal?.['detail']).toEqual({ reason: 'recipient_unverified' });
  });

  it('FAILS CLOSED when the question cannot be answered', async () => {
    // The first network round trip these gates have ever made, so what an
    // outage means had to be decided rather than inherited. It means the escrow
    // does not arm: a legitimate owner is delayed by minutes, where the other
    // direction hands an attacker the whole §5.2 waiting period.
    const asked: string[] = [];
    const h = harness('production', realNotifier('throws', asked), asked);

    await expect(h.service.configure(OWNER, 'session', CONFIGURE_INPUT)).rejects.toThrow();
    // Whatever it threw, no escrow was created: the database proxy was never
    // reached, which is what the harness makes observable.
    expect(asked).toEqual([OWNER]);
  });

  it('lets a PROVED owner through to the work', async () => {
    // Without this the three refusals above would pass just as well against a
    // gate that refuses everything — the vacuity failure this repo keeps
    // catching.
    const asked: string[] = [];
    const h = harness('production', realNotifier(true, asked), asked);

    await expect(h.service.configure(OWNER, 'session', CONFIGURE_INPUT)).rejects.toThrow(
      /the gate must fire before any other work/,
    );
    expect(asked).toEqual([OWNER]);
  });

  it('does not ask at all outside production, where the stub is intended', async () => {
    for (const env of ['development', 'test'] as const) {
      const asked: string[] = [];
      const h = harness(env, realNotifier(false, asked), asked);
      await expect(h.service.configure(OWNER, 'session', CONFIGURE_INPUT)).rejects.toThrow(
        /the gate must fire before any other work/,
      );
      expect(asked).toEqual([]);
    }
  });
});

describe('rearm — the arming gate M14 added to the table', () => {
  it('REFUSES in production for an unproved owner', async () => {
    // Re-arming restores a grantee's ability to start the §5.2 clock — denial
    // is sticky with no cooldown precisely so it stays the owner's decision —
    // and the actor here IS the recipient, so refusing costs the owner an
    // action they can unblock themselves rather than denying a third party.
    const asked: string[] = [];
    const h = harness('production', realNotifier(false, asked), asked);

    await expect(h.service.rearm(OWNER, 'session', 'policy-1')).rejects.toThrow(
      ServiceUnavailableException,
    );
    expect(asked).toEqual([OWNER]);
  });
});

describe('request and release — PROCEED and RECORD, never refuse', () => {
  it('never asks the arming question on a GRANTEE-driven path', async () => {
    // The load-bearing asymmetry. `request` is driven by a grantee, so blocking
    // it on the OWNER's unverified address would let an owner's own typo
    // permanently deny a legitimate emergency contact — the M6 rule (the
    // protective action must never be harder than the permissive one) pointed
    // the wrong way. It proceeds; the send records what it found.
    const asked: string[] = [];
    const h = harness('production', realNotifier(false, asked), asked);

    await expect(
      h.service.request(GRANTEE, 'session', 'policy-1'),
    ).rejects.toThrow(/the gate must fire before any other work/);
    expect(asked).toEqual([]);
  });
});

describe('the stub notifier', () => {
  it('reports UNVERIFIED, never vouching for an address it cannot see', () => {
    // A stub that answered true would be the "fail-open in style" shape M8 PR1
    // named: a dev default must never be the permissive answer to a security
    // question.
    return expect(new StubNotifier().recipientVerified()).resolves.toBe(false);
  });
});
