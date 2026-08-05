import { ServiceUnavailableException } from '@nestjs/common';
import { StubNotifier, type NotificationPort } from '../src/notifications';
import { EmergencyAccessService } from '../src/emergency.service';
import type { VaultConfig } from '../src/config';
import type { Db } from '../src/db';
import type { EmergencyRepo } from '../src/emergency.repo';
import type { EventsService } from '../src/events.service';
import type { KeysetsRepo } from '../src/keysets.repo';
import type { VaultAuthz } from '../src/authz.service';

const OWNER = 'c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f';
const GRANTEE = '11112222-3333-4444-8555-666677778888';

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
  };
}

/** Nothing below reaches the database: the gate fires before any work. */
function serviceWith(nodeEnv: VaultConfig['nodeEnv'], notifier: NotificationPort) {
  const unusable = new Proxy(
    {},
    {
      get: () => (): never => {
        throw new Error('the notification gate must fire before any other work');
      },
    },
  );
  // The gate itself AUDITS its refusal (M9), so events must accept that one
  // emit; everything else stays unreachable.
  const events = { audit: { emit: () => Promise.resolve() } } as unknown as EventsService;
  return new EmergencyAccessService(
    unusable as Db,
    unusable as EmergencyRepo,
    unusable as KeysetsRepo,
    { assertCan: (): void => undefined } as unknown as VaultAuthz,
    events,
    notifier,
    // A permissive settlement gate: this suite is about the NOTIFICATION gate,
    // and the settlement gate is proven separately. Permitting here keeps the
    // assertion honest — the notification refusal must fire on its own.
    { checkVaultRelease: () => Promise.resolve({ permitted: true, caseId: null }) },
    configFor(nodeEnv),
    () => new Date('2026-08-01T00:00:00.000Z'),
  );
}

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

describe('StubNotifier', () => {
  it('records what it would have sent and admits it is not a real channel', async () => {
    const notifier = new StubNotifier();
    expect(notifier.deliversToRealChannels).toBe(false);
    expect(notifier.channel).toBe('stub');

    await notifier.notify({ kind: 'requested', ownerUserId: OWNER, policyId: 'p1' });
    expect(notifier.sent).toEqual([{ kind: 'requested', ownerUserId: OWNER, policyId: 'p1' }]);
  });
});

describe('the production notification gate', () => {
  it('refuses to arm an escrow in production behind the stub', async () => {
    // docs/03 §5.2's control is a waiting period the owner can interrupt. With
    // no channel that reaches them there is nothing to interrupt it with, so
    // this fails closed rather than shipping a control that only looks like one.
    const service = serviceWith('production', new StubNotifier());
    await expect(service.configure(OWNER, 'session', CONFIGURE_INPUT)).rejects.toThrow(
      ServiceUnavailableException,
    );
  });

  it('refuses a request and a re-arm in production too', async () => {
    const service = serviceWith('production', new StubNotifier());
    await expect(service.request(GRANTEE, 'session', 'policy')).rejects.toThrow(
      ServiceUnavailableException,
    );
    await expect(service.rearm(OWNER, 'session', 'policy')).rejects.toThrow(
      ServiceUnavailableException,
    );
  });

  it('reports a generic, actionable token', async () => {
    const service = serviceWith('production', new StubNotifier());
    await service.configure(OWNER, 'session', CONFIGURE_INPUT).catch((err: unknown) => {
      expect((err as ServiceUnavailableException).getResponse()).toEqual({
        error: 'notifications_unavailable',
      });
    });
    expect.assertions(1);
  });

  it('lets a real channel through in production', async () => {
    // The shape a real adapter takes when the notifications milestone lands.
    const real: NotificationPort = {
      channel: 'ses',
      deliversToRealChannels: true,
      notify: (): Promise<void> => Promise.resolve(),
    };
    const service = serviceWith('production', real);
    // Past the gate, so it fails on the database proxy instead.
    await expect(service.configure(OWNER, 'session', CONFIGURE_INPUT)).rejects.toThrow(
      /notification gate must fire before any other work/,
    );
  });

  it('does not gate dev or test, where the stub is the intended adapter', async () => {
    for (const env of ['development', 'test'] as const) {
      const service = serviceWith(env, new StubNotifier());
      await expect(service.configure(OWNER, 'session', CONFIGURE_INPUT)).rejects.toThrow(
        /notification gate must fire before any other work/,
      );
    }
  });

  it('never gates denial - stopping a request must always be possible', async () => {
    // Even in production with no channel: the owner has already been told
    // somehow, and refusing their "no" would be the worst possible failure.
    const service = serviceWith('production', new StubNotifier());
    await expect(service.deny(OWNER, 'session', 'policy')).rejects.toThrow(
      /notification gate must fire before any other work/,
    );
  });
});
