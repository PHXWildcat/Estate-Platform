import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import type { AuditProducer } from '@estate/audit-emitter';
import {
  CallerGuard,
  HttpSessionVerifier,
  SESSION_VERIFIER,
  StepUpGuard,
} from '@estate/auth-guard';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import type { PoolConfig } from 'pg';
import { InMemoryAuditProducer, KafkaAuditProducer } from './audit-producer';
import { SettlementAuthz } from './authz.service';
import { CasesRepo } from './cases.repo';
import { loadConfig, type SettlementConfig } from './config';
import { ContactAttemptsRepo } from './contact-attempts.repo';
import { CoreReadsRepo } from './core-reads.repo';
import { Db } from './db';
import {
  AUDIT_PRODUCER,
  CLOCK,
  CONFIG,
  IDENTITY_LOCK,
  NOTIFIER,
  PG_POOL_CONFIG,
  POLICY_DECISION_POINT,
} from './di-tokens';
import { EventsService } from './events.service';
import { HttpErrorFilter } from './http-error.filter';
import { HttpIdentityLock, type IdentityLockPort } from './identity-lock';
import { StubNotifier, type NotificationPort } from './notifications';
import { OperatorController } from './operator.controller';
import { OperatorsRepo } from './operators.repo';
import { SettingsRepo } from './settings.repo';
import { SettlementController } from './settlement.controller';
import { SettlementService } from './settlement.service';
import { SettlementWorkflowDriver } from './workflow-driver';

/** Only the stub exists today; a real adapter joins the NOTIFY_MODE enum with
 * the notifications milestone. The service gates on the adapter's own
 * deliversToRealChannels capability bit, not on this selector. */
function notifierFor(): NotificationPort {
  return new StubNotifier();
}

@Module({
  controllers: [SettlementController, OperatorController],
  providers: [
    { provide: CONFIG, useFactory: (): SettlementConfig => loadConfig() },
    { provide: CLOCK, useValue: (): Date => new Date() },
    {
      provide: PG_POOL_CONFIG,
      inject: [CONFIG],
      useFactory: (config: SettlementConfig): PoolConfig => ({
        connectionString: config.databaseUrl,
      }),
    },
    Db,
    {
      provide: AUDIT_PRODUCER,
      inject: [CONFIG],
      useFactory: (config: SettlementConfig): AuditProducer => {
        if (config.kafkaBrokers) {
          return new KafkaAuditProducer(config.kafkaBrokers);
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
    // The Cedar PDP is constructed once from the bundled, in-repo policy set
    // (settlement.cedar's narrow permits). Deny by default.
    {
      provide: POLICY_DECISION_POINT,
      useFactory: (): PolicyDecisionPoint => new PolicyDecisionPoint(loadBundledPolicies()),
    },
    // Real cross-service session verification: the guards resolve the caller's
    // bearer token against the identity service (@estate/auth-guard).
    {
      provide: SESSION_VERIFIER,
      inject: [CONFIG],
      useFactory: (config: SettlementConfig): HttpSessionVerifier =>
        new HttpSessionVerifier({ identityUrl: config.identityUrl }),
    },
    // The account-lock/liveness client. Fails closed on every error; with an
    // unset dev credential, identity's guard refuses and the lock-touching
    // transitions 503 until both sides are provisioned.
    {
      provide: IDENTITY_LOCK,
      inject: [CONFIG],
      useFactory: (config: SettlementConfig): IdentityLockPort =>
        new HttpIdentityLock({
          identityUrl: config.identityUrl,
          credential: config.settlementInternalToken,
        }),
    },
    { provide: NOTIFIER, useFactory: (): NotificationPort => notifierFor() },
    SettlementAuthz,
    CasesRepo,
    ContactAttemptsRepo,
    OperatorsRepo,
    SettingsRepo,
    CoreReadsRepo,
    SettlementService,
    SettlementWorkflowDriver,
    CallerGuard,
    StepUpGuard,
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
