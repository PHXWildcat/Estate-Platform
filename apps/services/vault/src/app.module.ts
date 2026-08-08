import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import type { AuditProducer } from '@estate/audit-emitter';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import {
  HttpSettlementAuthority,
  SETTLEMENT_AUTHORITY,
  type SettlementVaultGate,
} from '@estate/settlement-client';
import {
  ALLOWED_SESSION_AUDIENCES,
  CallerGuard,
  HttpSessionVerifier,
  SESSION_VERIFIER,
  StepUpGuard,
} from '@estate/auth-guard';
import type { PoolConfig } from 'pg';
import { InMemoryAuditProducer, KafkaAuditProducer } from '@estate/kafka';
import { VaultAuthz } from './authz.service';
import { loadConfig, type VaultConfig } from './config';
import { Db } from './db';
import {
  AUDIT_PRODUCER,
  CLOCK,
  CONFIG,
  NOTIFIER,
  PG_POOL_CONFIG,
  POLICY_DECISION_POINT,
} from './di-tokens';
import { EmergencyAccessController } from './emergency.controller';
import { EmergencyRepo } from './emergency.repo';
import { EmergencyAccessService } from './emergency.service';
import { HttpNotificationsClient } from '@estate/notifications-client';
import { HttpNotifier, StubNotifier, type NotificationPort } from './notifications';
import { EventsService } from './events.service';
import { HandshakesRepo } from './handshakes.repo';
import { HttpErrorFilter } from './http-error.filter';
import { ItemsRepo } from './items.repo';
import { KeysetsRepo } from './keysets.repo';
import { VaultSessionsRepo } from './sessions.repo';
import { VaultController } from './vault.controller';
import { VaultSessionGuard } from './vault-session.guard';
import { VaultService } from './vault.service';

/**
 * Notice what this module does NOT wire: no KMS provider, no FieldCrypto, no
 * DEK repository. Zone A holds no key material server-side (docs/01 §1), so
 * there is nothing here for a KMS grant to scope and nothing to decrypt. If a
 * future change adds one of those providers to this module, that is a trust
 * zone moving, not a refactor.
 */
/**
 * Select the notifier. Exhaustive over the config union with a `never` check —
 * a selector that could quietly fall through to the stub is the M4
 * fail-open-in-style lesson. config.ts pins 'http' in production; the
 * per-route capability gate (EmergencyAccessService.assertNotificationsUsable)
 * remains as defense in depth, and the vault's core routes still serve even if
 * the notifications service itself is down (sends record as undelivered).
 */
function notifierFor(config: VaultConfig): NotificationPort {
  const notify = config.notify;
  switch (notify.mode) {
    case 'http':
      return new HttpNotifier(
        new HttpNotificationsClient({
          notificationsUrl: config.notificationsUrl,
          // ONE FIELD PER EDGE (M14). Vault holds SEND and STATUS and nothing
          // else — notably NOT the recipients credential, so it can neither
          // repoint an owner's address nor vouch for one; it can only ask
          // whether somebody already did. Every other method on the client
          // short-circuits without a round trip, so an over-broad client would
          // be a configuration that cannot reach the route rather than one that
          // reaches it and is rejected.
          credentials: {
            send: config.notificationsInternalToken,
            status: config.notificationsStatusToken,
          },
        }),
      );
    case 'stub':
      return new StubNotifier();
    default: {
      const exhausted: never = notify;
      throw new Error(`unhandled NOTIFY_MODE: ${String(exhausted)}`);
    }
  }
}

@Module({
  controllers: [VaultController, EmergencyAccessController],
  providers: [
    { provide: CONFIG, useFactory: (): VaultConfig => loadConfig() },
    { provide: CLOCK, useValue: (): Date => new Date() },
    {
      provide: PG_POOL_CONFIG,
      inject: [CONFIG],
      useFactory: (config: VaultConfig): PoolConfig => ({
        connectionString: config.databaseUrl,
      }),
    },
    Db,
    {
      provide: AUDIT_PRODUCER,
      inject: [CONFIG],
      useFactory: (config: VaultConfig): AuditProducer => {
        if (config.kafkaBrokers) {
          return new KafkaAuditProducer({
            clientId: 'service-vault',
            brokers: config.kafkaBrokers,
          });
        }
        // Config already fails fast in production without brokers; this guard
        // makes the invariant local and unmissable: the no-op producer can
        // NEVER be constructed in production.
        if (config.nodeEnv === 'production') {
          throw new Error('audit emission requires Kafka in production');
        }
        return new InMemoryAuditProducer();
      },
    },
    EventsService,
    // The Cedar PDP is constructed once from the bundled, in-repo policy set.
    // Deny by default.
    {
      provide: POLICY_DECISION_POINT,
      useFactory: (): PolicyDecisionPoint => new PolicyDecisionPoint(loadBundledPolicies()),
    },
    // Real cross-service session verification: the guards resolve the caller's
    // bearer token against the identity service (@estate/auth-guard).
    {
      provide: SESSION_VERIFIER,
      inject: [CONFIG],
      useFactory: (config: VaultConfig): HttpSessionVerifier =>
        new HttpSessionVerifier({ identityUrl: config.identityUrl }),
    },
    /**
     * THE ONE SERVICE THAT ADMITS A VAULT-AUDIENCE SESSION (M15).
     *
     * Zone A lives on an isolated origin (docs/03 TB6) reached by a single-use
     * handoff, and the session that handoff redeems for is minted `vault`. Every
     * other service leaves this token unbound and therefore refuses it, which is
     * what keeps a leaked handoff from becoming authority over assets,
     * documents, profile or identity.
     *
     * `account` stays admitted alongside it, deliberately. An account session is
     * strictly MORE powerful — it already opens every other service — so
     * refusing it here would protect nothing while making this service reachable
     * only through the handoff, including from its own integration tests. The
     * property being bought runs one way only.
     *
     * Declared in `AUDIENCE_ADMITTERS` and checked by
     * `packages/auth-guard/test/session-audience.spec.ts`.
     */
    { provide: ALLOWED_SESSION_AUDIENCES, useValue: ['account', 'vault'] },
    { provide: NOTIFIER, inject: [CONFIG], useFactory: notifierFor },
    // docs/03 §6a: emergency access is the LAST staged grant of a settlement,
    // so release consults settlement state. The client fails closed on every
    // error path — an unreachable settlement blocks Zone A rather than opening
    // it. The credential is required because this asks about the OWNER's
    // estate, not the calling grantee's authority.
    {
      provide: SETTLEMENT_AUTHORITY,
      inject: [CONFIG],
      useFactory: (config: VaultConfig): SettlementVaultGate =>
        new HttpSettlementAuthority({
          settlementUrl: config.settlementUrl,
          serviceCredential: config.settlementInternalToken,
        }),
    },
    VaultAuthz,
    KeysetsRepo,
    ItemsRepo,
    HandshakesRepo,
    VaultSessionsRepo,
    EmergencyRepo,
    VaultService,
    EmergencyAccessService,
    CallerGuard,
    StepUpGuard,
    VaultSessionGuard,
    { provide: APP_FILTER, useClass: HttpErrorFilter },
  ],
})
export class AppModule implements OnApplicationShutdown {
  constructor(@Inject(AUDIT_PRODUCER) private readonly producer: AuditProducer) {}

  async onApplicationShutdown(): Promise<void> {
    if (this.producer instanceof KafkaAuditProducer) {
      await this.producer.disconnect();
    }
  }
}
