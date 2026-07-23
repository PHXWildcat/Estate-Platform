import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { KMSClient } from '@aws-sdk/client-kms';
import type { AuditProducer } from '@estate/audit-emitter';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import {
  FieldCrypto,
  LocalKmsProvider,
  type DekRepository,
  type KmsKeyProvider,
} from '@estate/crypto';
import { AwsKmsProvider } from '@estate/kms-aws';
import {
  CallerGuard,
  HttpSessionVerifier,
  SESSION_VERIFIER,
  StepUpGuard,
} from '@estate/auth-guard';
import type { PoolConfig } from 'pg';
import { AccountsRepo } from './accounts.repo';
import { InMemoryAuditProducer, KafkaAuditProducer } from './audit-producer';
import { PlaidAuthz } from './authz.service';
import { loadConfig, type PlaidConfig } from './config';
import { Db } from './db';
import { PgDekRepository } from './dek.repository';
import {
  AUDIT_PRODUCER,
  CLOCK,
  CONFIG,
  DEK_REPOSITORY,
  FIELD_CRYPTO,
  PG_POOL_CONFIG,
  PLAID_GATEWAY,
  POLICY_DECISION_POINT,
} from './di-tokens';
import { EventsService } from './events.service';
import { FieldCipher } from './field-cipher';
import { HttpErrorFilter } from './http-error.filter';
import { ItemsRepo } from './items.repo';
import { LivePlaidGateway } from './live-plaid-gateway';
import { PlaidController } from './plaid.controller';
import { PlaidService } from './plaid.service';
import { StubPlaidGateway } from './stub-plaid-gateway';
import { SyncActivityMonitor } from './sync-monitor';
import { WebhookController } from './webhook.controller';
import { WebhookVerifier } from './webhook-verifier';
import type { PlaidGateway } from './plaid-gateway';

/**
 * Select the KMS backend. Production uses AWS KMS under THIS service's own
 * KEK ('plaid/kek') — never the asset service's 'financial/kek' — so the KMS
 * grant, not the database, is the TB5 isolation chokepoint. Dev/test uses the
 * in-process LocalKmsProvider; config.ts already fails fast if the required
 * settings for the active mode are missing.
 */
function kmsProviderFor(config: PlaidConfig): KmsKeyProvider {
  if (config.kms.mode === 'aws') {
    return new AwsKmsProvider(new KMSClient({ region: config.kms.region }), {
      keyId: config.kms.keyId,
    });
  }
  return new LocalKmsProvider(config.kms.masterKey);
}

@Module({
  controllers: [PlaidController, WebhookController],
  providers: [
    { provide: CONFIG, useFactory: (): PlaidConfig => loadConfig() },
    { provide: CLOCK, useValue: (): Date => new Date() },
    {
      provide: PG_POOL_CONFIG,
      inject: [CONFIG],
      useFactory: (config: PlaidConfig): PoolConfig => ({
        connectionString: config.databaseUrl,
      }),
    },
    Db,
    PgDekRepository,
    { provide: DEK_REPOSITORY, useExisting: PgDekRepository },
    {
      provide: AUDIT_PRODUCER,
      inject: [CONFIG],
      useFactory: (config: PlaidConfig): AuditProducer => {
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
    {
      provide: PLAID_GATEWAY,
      inject: [CONFIG],
      useFactory: (config: PlaidConfig): PlaidGateway => {
        if (config.plaid.mode === 'live') {
          return new LivePlaidGateway({
            env: config.plaid.env,
            clientId: config.plaid.clientId,
            secret: config.plaid.secret,
          });
        }
        // config.ts guarantees this branch is unreachable in production.
        return new StubPlaidGateway();
      },
    },
    EventsService,
    {
      provide: FIELD_CRYPTO,
      inject: [CONFIG, DEK_REPOSITORY, EventsService],
      useFactory: (config: PlaidConfig, deks: DekRepository, events: EventsService): FieldCrypto =>
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
    // The Cedar PDP is constructed once from the bundled, in-repo policy set.
    // Deny by default; owner.cedar is the only permit that can match here.
    {
      provide: POLICY_DECISION_POINT,
      useFactory: (): PolicyDecisionPoint => new PolicyDecisionPoint(loadBundledPolicies()),
    },
    FieldCipher,
    PlaidAuthz,
    ItemsRepo,
    AccountsRepo,
    SyncActivityMonitor,
    WebhookVerifier,
    PlaidService,
    // Real cross-service session verification (@estate/auth-guard): the guards
    // introspect the caller's bearer token against the identity service,
    // replacing the M2 gateway-injected header trust.
    {
      provide: SESSION_VERIFIER,
      inject: [CONFIG],
      useFactory: (config: PlaidConfig): HttpSessionVerifier =>
        new HttpSessionVerifier({ identityUrl: config.identityUrl }),
    },
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
