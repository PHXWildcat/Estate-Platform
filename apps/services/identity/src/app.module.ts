import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { KMSClient } from '@aws-sdk/client-kms';
import type { AuditProducer } from '@estate/audit-emitter';
import { SERVICE_CREDENTIAL, ServiceCredentialGuard } from '@estate/auth-guard';
import {
  FieldCrypto,
  LocalKmsProvider,
  type DekRepository,
  type KmsKeyProvider,
} from '@estate/crypto';
import { AwsKmsProvider } from '@estate/kms-aws';
import {
  HttpNotificationsClient,
  NOTIFICATIONS,
  type NotificationsPort,
} from '@estate/notifications-client';
import type { PoolConfig } from 'pg';
import { AuthController } from './auth.controller';
import { AuthEventsRepo } from './auth-events.repo';
import { EmailVerificationRepo } from './email-verification.repo';
import { EmailVerificationService } from './email-verification.service';
import { HandoffService } from './handoff.service';
import { ExtensionPairingService } from './extension-pairing.service';
import { ExtensionPairingsRepo } from './extension-pairings.repo';
import { HandoffsRepo } from './handoffs.repo';
import { AuthService } from './auth.service';
import { InMemoryAuditProducer, KafkaAuditProducer } from '@estate/kafka';
import { loadConfig, type IdentityConfig } from './config';
import { Db } from './db';
import { PgDekRepository } from './dek.repository';
import {
  AUDIT_PRODUCER,
  CLOCK,
  CONFIG,
  DEK_REPOSITORY,
  FIELD_CRYPTO,
  PG_POOL_CONFIG,
} from './di-tokens';
import { EventsService } from './events.service';
import { HttpErrorFilter } from './http-error.filter';
import { MfaRepo } from './mfa.repo';
import { PasswordResetRepo } from './password-reset.repo';
import { PasswordResetService } from './password-reset.service';
import { EmailChangeService } from './email-change.service';
import { EmailChangeRepo } from './email-change.repo';
import { PasswordHasher } from './password';
import { SessionGuard } from './session.guard';
import { SecondFactorGate } from './second-factor-gate';
import { SessionsRepo } from './sessions.repo';
import { SettlementLockController } from './settlement-lock.controller';
import { SettlementLockService } from './settlement-lock.service';
import { StepUpGuard } from './stepup.guard';
import { UsersRepo } from './users.repo';
import { WebAuthnRepo } from './webauthn.repo';
import { WebAuthnService } from './webauthn.service';

/**
 * Select the KMS backend. Production uses AWS KMS (CloudHSM-rooted KEKs, the
 * insider-threat chokepoint per docs/03 §5.3); dev/test uses the in-process
 * LocalKmsProvider. config.ts already fails fast if the required settings for
 * the active mode are missing, so this switch is total.
 */
function kmsProviderFor(config: IdentityConfig): KmsKeyProvider {
  if (config.kms.mode === 'aws') {
    const { region, endpoint, keyId } = config.kms;
    return new AwsKmsProvider(new KMSClient({ region, ...(endpoint ? { endpoint } : {}) }), {
      keyId,
    });
  }
  return new LocalKmsProvider(config.kms.masterKey);
}

@Module({
  controllers: [AuthController, SettlementLockController],
  providers: [
    { provide: CONFIG, useFactory: (): IdentityConfig => loadConfig() },
    { provide: CLOCK, useValue: (): Date => new Date() },
    {
      provide: PG_POOL_CONFIG,
      inject: [CONFIG],
      useFactory: (config: IdentityConfig): PoolConfig => ({
        connectionString: config.databaseUrl,
      }),
    },
    Db,
    PgDekRepository,
    { provide: DEK_REPOSITORY, useExisting: PgDekRepository },
    {
      provide: AUDIT_PRODUCER,
      inject: [CONFIG],
      useFactory: (config: IdentityConfig): AuditProducer => {
        if (config.kafkaBrokers) {
          return new KafkaAuditProducer({
            clientId: 'service-identity',
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
    {
      provide: FIELD_CRYPTO,
      inject: [CONFIG, DEK_REPOSITORY, EventsService],
      useFactory: (
        config: IdentityConfig,
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
    PasswordHasher,
    UsersRepo,
    SessionsRepo,
    SecondFactorGate,
    MfaRepo,
    PasswordResetRepo,
    EmailChangeRepo,
    PasswordResetService,
    EmailChangeService,
    AuthEventsRepo,
    WebAuthnRepo,
    AuthService,
    WebAuthnService,
    EmailVerificationRepo,
    EmailVerificationService,
    // M15: the cross-origin vault handoff.
    HandoffsRepo,
    ExtensionPairingsRepo,
    ExtensionPairingService,
    HandoffService,
    SettlementLockService,
    SessionGuard,
    StepUpGuard,
    {
      // '' when unset: ServiceCredentialGuard fails closed and the internal
      // settlement-lock routes refuse everything (dev must opt in explicitly).
      // This is identity's OWN inbound credential — held by settlement alone,
      // never by the other services (M7 security review).
      provide: SERVICE_CREDENTIAL,
      inject: [CONFIG],
      useFactory: (config: IdentityConfig): string => config.internalApiToken,
    },
    ServiceCredentialGuard,
    {
      // The recipient-store feed (M9), M14's verification ceremony, and M17's
      // account-security notice. Best-effort by contract for the first two: the
      // client never throws, so a notifications outage cannot block
      // registration or login.
      //
      // FIVE credentials, one per EDGE, and identity holds no sixth: it does
      // NOT hold `NOTIFICATIONS_INTERNAL_TOKEN`, so nothing here can fire an
      // estate notification — a password-change notice is about the ACCOUNT and
      // travels on its own credential, precisely so that gaining the ability to
      // say "your password changed" does not come with the ability to say "a
      // death report was filed on your account". A method whose credential is
      // absent short-circuits without a round trip, so this object grants
      // exactly the four capabilities the graph names and no more. All four are
      // distinct from identity's own inbound value; config.ts refuses any
      // equality in production with a full pairwise loop.
      provide: NOTIFICATIONS,
      inject: [CONFIG],
      useFactory: (config: IdentityConfig): NotificationsPort =>
        new HttpNotificationsClient({
          notificationsUrl: config.notificationsUrl,
          credentials: {
            recipients: config.notificationsInternalToken,
            verification: config.notificationsVerifyToken,
            status: config.notificationsStatusToken,
            security: config.notificationsSecurityToken,
            recovery: config.notificationsRecoveryToken,
            emailChange: config.notificationsEmailChangeToken,
          },
        }),
    },
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
