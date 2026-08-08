import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { KMSClient } from '@aws-sdk/client-kms';
import type { AuditProducer } from '@estate/audit-emitter';
import {
  CallerGuard,
  HttpSessionVerifier,
  SERVICE_CREDENTIAL,
  SESSION_VERIFIER,
  ServiceCredentialGuard,
  StepUpGuard,
} from '@estate/auth-guard';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import {
  FieldCrypto,
  LocalKmsProvider,
  type DekRepository,
  type KmsKeyProvider,
} from '@estate/crypto';
import { AwsKmsProvider } from '@estate/kms-aws';
import type { PoolConfig } from 'pg';
import { SettlementAdminController, SettlementVaultGateController } from './admin.controller';
import { SettlementAdminService } from './admin.service';
import { PgSettlementDekRepository } from './dek.repository';
import { DistributionsRepo } from './distributions.repo';
import { StagesRepo } from './stages.repo';
import { TasksRepo } from './tasks.repo';
import { InMemoryAuditProducer, KafkaAuditProducer } from '@estate/kafka';
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
  DEK_REPOSITORY,
  DOCUMENTS_HOLD,
  FIELD_CRYPTO,
  IDENTITY_LOCK,
  NOTIFIER,
  PG_POOL_CONFIG,
  POLICY_DECISION_POINT,
} from './di-tokens';
import { HttpDocumentsHold, type DocumentsHoldPort } from './documents-hold';
import { EventsService } from './events.service';
import { HttpErrorFilter } from './http-error.filter';
import { HttpIdentityLock, type IdentityLockPort } from './identity-lock';
import { HttpNotificationsClient } from '@estate/notifications-client';
import { HttpNotifier, StubNotifier, type NotificationPort } from './notifications';
import { OperatorController } from './operator.controller';
import { OperatorsRepo } from './operators.repo';
import { SettingsRepo } from './settings.repo';
import { SettlementController } from './settlement.controller';
import { SettlementService } from './settlement.service';
import { SettlementWorkflowDriver } from './workflow-driver';

/**
 * Select the notifier. Exhaustive over the config union with a `never` check —
 * a selector that could quietly fall through to the stub is the M4
 * fail-open-in-style lesson. config.ts pins 'http' in production; the
 * per-route capability gates (intake, review-approve) remain as defense in
 * depth, still reading the adapter's own deliversToRealChannels bit.
 */
function notifierFor(config: SettlementConfig): NotificationPort {
  const notify = config.notify;
  switch (notify.mode) {
    case 'http':
      return new HttpNotifier(
        new HttpNotificationsClient({
          notificationsUrl: config.notificationsUrl,
          // ONE FIELD PER EDGE (M14). This service holds the SEND credential
          // and nothing else, so every other method on the client
          // short-circuits without a round trip — an over-broad client would be
          // a configuration that cannot reach the route, never one that reaches
          // it and is rejected.
          credentials: { send: config.notificationsInternalToken },
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

/**
 * Select the KMS backend. Production uses AWS KMS under THIS service's own KEK
 * ('settlement/kek') — never profile's 'core/kek', even though they share the
 * cluster — so the KMS grant, not the database, is the isolation chokepoint
 * (docs/03 §5.3). config.ts already fails fast if the active mode's settings
 * are missing.
 */
function kmsProviderFor(config: SettlementConfig): KmsKeyProvider {
  if (config.kms.mode === 'aws') {
    const { region, endpoint, keyId } = config.kms;
    return new AwsKmsProvider(new KMSClient({ region, ...(endpoint ? { endpoint } : {}) }), {
      keyId,
    });
  }
  return new LocalKmsProvider(config.kms.masterKey);
}

@Module({
  controllers: [
    SettlementController,
    OperatorController,
    SettlementAdminController,
    SettlementVaultGateController,
  ],
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
          return new KafkaAuditProducer({
            clientId: 'service-settlement',
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
          // The OUTBOUND credential — distinct from the one this service
          // expects inbound, so a gate caller never holds account-lock power.
          credential: config.identityInternalToken,
        }),
    },
    // The legal-hold client (M9 PR2). Fails closed on every error; with an
    // unset dev credential, documents' guard refuses and the hold-touching
    // transitions 503 until both sides are provisioned.
    {
      provide: DOCUMENTS_HOLD,
      inject: [CONFIG],
      useFactory: (config: SettlementConfig): DocumentsHoldPort =>
        new HttpDocumentsHold({
          documentsUrl: config.documentsUrl,
          // The documents-callee OUTBOUND credential — the fourth secret this
          // service touches, distinct from the other three by config refusal.
          credential: config.documentsInternalToken,
        }),
    },
    { provide: NOTIFIER, inject: [CONFIG], useFactory: notifierFor },
    PgSettlementDekRepository,
    { provide: DEK_REPOSITORY, useExisting: PgSettlementDekRepository },
    {
      provide: FIELD_CRYPTO,
      inject: [CONFIG, DEK_REPOSITORY, EventsService],
      useFactory: (
        config: SettlementConfig,
        deks: DekRepository,
        events: EventsService,
      ): FieldCrypto =>
        new FieldCrypto(
          kmsProviderFor(config),
          deks,
          async (event): Promise<void> => {
            // Every field decryption is a logged event (docs/01 Zone B rule).
            await events.audit.emit({
              action: 'crypto.field.decrypted',
              actorId: event.actorId,
              actorType: event.actorType,
              onBehalfOf: null,
              resourceType: 'field',
              resourceId: event.userId,
              sessionId: null,
              detail: { dekId: event.dekId, field: event.field, purpose: event.purpose },
            });
          },
          { kekAlias: config.kekAlias },
        ),
    },
    {
      // '' when unset: ServiceCredentialGuard fails closed, so the vault-gate
      // authority route refuses and emergency release stays blocked — the safe
      // direction for Zone A. This is the INBOUND credential only; it opens a
      // read-only authority answer and confers no lock power.
      provide: SERVICE_CREDENTIAL,
      inject: [CONFIG],
      useFactory: (config: SettlementConfig): string => config.internalApiToken,
    },
    ServiceCredentialGuard,
    SettlementAuthz,
    CasesRepo,
    ContactAttemptsRepo,
    OperatorsRepo,
    SettingsRepo,
    StagesRepo,
    TasksRepo,
    DistributionsRepo,
    CoreReadsRepo,
    SettlementService,
    SettlementAdminService,
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
