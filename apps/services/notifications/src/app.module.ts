import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { KMSClient } from '@aws-sdk/client-kms';
import { SESClient } from '@aws-sdk/client-ses';
import type { AuditProducer } from '@estate/audit-emitter';
import { SERVICE_CREDENTIAL, ServiceCredentialGuard } from '@estate/auth-guard';
import {
  FieldCrypto,
  LocalKmsProvider,
  type DekRepository,
  type KmsKeyProvider,
} from '@estate/crypto';
import { InMemoryAuditProducer, KafkaAuditProducer } from '@estate/kafka';
import { AwsKmsProvider } from '@estate/kms-aws';
import type { PoolConfig } from 'pg';
import { loadConfig, type NotificationsConfig } from './config';
import { Db } from './db';
import { PgNotificationDekRepository } from './dek.repository';
import {
  AUDIT_PRODUCER,
  CLOCK,
  CONFIG,
  DEK_REPOSITORY,
  EMAIL_SENDER,
  FIELD_CRYPTO,
  PG_POOL_CONFIG,
  RECIPIENTS_CREDENTIAL,
  RECIPIENT_STATUS_CREDENTIAL,
  VERIFICATION_CREDENTIAL,
} from './di-tokens';
import { SesEmailSender, StubEmailSender, type EmailSender } from './email';
import { EventsService } from './events.service';
import { HttpErrorFilter } from './http-error.filter';
import {
  InternalController,
  RecipientStatusController,
  RecipientsController,
  VerificationController,
} from './internal.controller';
import { RecipientStatusCredentialGuard } from './recipient-status-credential.guard';
import { RecipientsCredentialGuard } from './recipients-credential.guard';
import { VerificationCredentialGuard } from './verification-credential.guard';
import { NotificationsService } from './notifications.service';
import { RecipientsRepo } from './recipients.repo';
import { SendsRepo } from './sends.repo';

/**
 * Select the carrier. Exhaustive over the config union with a `never` check —
 * a selector that could quietly fall through to the stub is the M4
 * fail-open-in-style lesson, and in THIS service the stub in production would
 * hollow out the M6/M7 waiting-period controls (config.ts already pins 'ses'
 * there; this keeps the invariant local).
 */
function emailSenderFor(config: NotificationsConfig): EmailSender {
  const email = config.email;
  switch (email.mode) {
    case 'ses':
      return new SesEmailSender(
        new SESClient({
          region: email.region,
          ...(email.endpoint ? { endpoint: email.endpoint } : {}),
        }),
        email.fromAddress,
      );
    case 'stub':
      return new StubEmailSender();
    default: {
      const exhausted: never = email;
      throw new Error(`unhandled EMAIL_MODE: ${String(exhausted)}`);
    }
  }
}

/** Select the KMS backend — 'notifications/kek' only, never 'core/kek'. */
function kmsProviderFor(config: NotificationsConfig): KmsKeyProvider {
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
    InternalController,
    RecipientsController,
    VerificationController,
    RecipientStatusController,
  ],
  providers: [
    { provide: CONFIG, useFactory: (): NotificationsConfig => loadConfig() },
    { provide: CLOCK, useValue: (): Date => new Date() },
    {
      provide: PG_POOL_CONFIG,
      inject: [CONFIG],
      useFactory: (config: NotificationsConfig): PoolConfig => ({
        connectionString: config.databaseUrl,
      }),
    },
    Db,
    {
      provide: AUDIT_PRODUCER,
      inject: [CONFIG],
      useFactory: (config: NotificationsConfig): AuditProducer => {
        if (config.kafkaBrokers) {
          return new KafkaAuditProducer({
            clientId: 'service-notifications',
            brokers: config.kafkaBrokers,
          });
        }
        if (config.nodeEnv === 'production') {
          throw new Error('audit emission requires Kafka in production');
        }
        return new InMemoryAuditProducer();
      },
    },
    EventsService,
    { provide: EMAIL_SENDER, inject: [CONFIG], useFactory: emailSenderFor },
    PgNotificationDekRepository,
    { provide: DEK_REPOSITORY, useExisting: PgNotificationDekRepository },
    {
      provide: FIELD_CRYPTO,
      inject: [CONFIG, DEK_REPOSITORY, EventsService],
      useFactory: (
        config: NotificationsConfig,
        deks: DekRepository,
        events: EventsService,
      ): FieldCrypto =>
        new FieldCrypto(
          kmsProviderFor(config),
          deks,
          async (event): Promise<void> => {
            // Every field decryption is a logged event (docs/01 Zone B rule) —
            // here, that means every address read.
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
      // '' when unset: ServiceCredentialGuard fails closed and the SEND route
      // refuses (dev must opt in explicitly by provisioning the edge).
      provide: SERVICE_CREDENTIAL,
      inject: [CONFIG],
      useFactory: (config: NotificationsConfig): string => config.internalApiToken,
    },
    {
      // The second inbound credential, for the recipient-upsert surface only.
      // Two tokens because a guard binds exactly one, and these two routes
      // have different legitimate holders — sending is vault + settlement,
      // saying where a user's notifications GO is identity's alone
      // (credential-graph.ts; found by the M9 security review). Fails closed
      // on '' exactly as the send credential does.
      provide: RECIPIENTS_CREDENTIAL,
      inject: [CONFIG],
      useFactory: (config: NotificationsConfig): string => config.recipientsApiToken,
    },
    {
      // M14 #3: mailing one address-verification code. Identity alone. Kept off
      // the send credential (which fires estate alarms) and off the recipients
      // credential (which can repoint an address); this one can only mail to
      // whatever is already on file. Fails closed on '' like the others.
      provide: VERIFICATION_CREDENTIAL,
      inject: [CONFIG],
      useFactory: (config: NotificationsConfig): string => config.verificationApiToken,
    },
    {
      // M14 #4: reading the verified bit. A read of DELIVERY STATE, which the
      // send edge promises not to expose — hence its own token rather than a
      // widening of that promise.
      provide: RECIPIENT_STATUS_CREDENTIAL,
      inject: [CONFIG],
      useFactory: (config: NotificationsConfig): string => config.recipientStatusApiToken,
    },
    ServiceCredentialGuard,
    RecipientsCredentialGuard,
    VerificationCredentialGuard,
    RecipientStatusCredentialGuard,
    RecipientsRepo,
    SendsRepo,
    NotificationsService,
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
