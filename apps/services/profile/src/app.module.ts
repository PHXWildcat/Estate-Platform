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
import { CallerGuard, HttpSessionVerifier, SESSION_VERIFIER } from '@estate/auth-guard';
import type { PoolConfig } from 'pg';
import { InMemoryAuditProducer, KafkaAuditProducer } from '@estate/kafka';
import { HttpNotificationsClient } from '@estate/notifications-client';
import { ProfileAuthz } from './authz.service';
import { loadConfig, type ProfileConfig } from './config';
import { ContactsController } from './contacts.controller';
import { ContactsRepo } from './contacts.repo';
import { ContactsService } from './contacts.service';
import { ContactLinksController } from './contact-links.controller';
import { ContactLinksRepo } from './contact-links.repo';
import { ContactLinksService } from './contact-links.service';
import { Db } from './db';
import { PgDekRepository } from './dek.repository';
import {
  AUDIT_PRODUCER,
  CLOCK,
  LINK_NOTIFIER,
  CONFIG,
  DEK_REPOSITORY,
  FIELD_CRYPTO,
  PG_POOL_CONFIG,
  POLICY_DECISION_POINT,
} from './di-tokens';
import { EventsService } from './events.service';
import { HttpLinkNotifier, StubLinkNotifier, type LinkNotificationPort } from './notifications';
import { FamilyRepo } from './family.repo';
import { FamilyService } from './family.service';
import { FieldCipher } from './field-cipher';
import { HttpErrorFilter } from './http-error.filter';
import { ProfileController } from './profile.controller';
import { ProfileRepo } from './profile.repo';
import { ProfileService } from './profile.service';
import { PermissionGrantsRepo, RolesRepo } from './roles.repo';
import { RolesController } from './roles.controller';
import { RolesService } from './roles.service';

/**
 * Select the KMS backend. Production uses AWS KMS (CloudHSM-rooted KEKs, the
 * insider-threat chokepoint per docs/03 §5.3) under the core cluster's own KEK
 * alias; dev/test uses the in-process LocalKmsProvider. config.ts already fails
 * fast if the required settings for the active mode are missing.
 */
function kmsProviderFor(config: ProfileConfig): KmsKeyProvider {
  if (config.kms.mode === 'aws') {
    const { region, endpoint, keyId } = config.kms;
    return new AwsKmsProvider(new KMSClient({ region, ...(endpoint ? { endpoint } : {}) }), {
      keyId,
    });
  }
  return new LocalKmsProvider(config.kms.masterKey);
}

@Module({
  controllers: [ProfileController, ContactsController, RolesController, ContactLinksController],
  providers: [
    { provide: CONFIG, useFactory: (): ProfileConfig => loadConfig() },
    { provide: CLOCK, useValue: (): Date => new Date() },
    {
      provide: PG_POOL_CONFIG,
      inject: [CONFIG],
      useFactory: (config: ProfileConfig): PoolConfig => ({
        connectionString: config.databaseUrl,
      }),
    },
    Db,
    PgDekRepository,
    ContactLinksRepo,
    ContactLinksService,
    /*
     * The owner-notification adapter for the link ceremony. Production pins
     * 'http' in config, so the stub can never be selected there — and the
     * redemption route additionally refuses behind an adapter whose
     * `deliversToRealChannels` is false, which is what makes the notification a
     * precondition rather than a side effect (the M6/M9 rule).
     */
    {
      provide: LINK_NOTIFIER,
      inject: [CONFIG],
      useFactory: (config: ProfileConfig): LinkNotificationPort =>
        config.notify.mode === 'http'
          ? new HttpLinkNotifier(
              new HttpNotificationsClient({
                notificationsUrl: config.notificationsUrl,
                serviceCredential: config.notificationsInternalToken,
              }),
            )
          : new StubLinkNotifier(),
    },
    { provide: DEK_REPOSITORY, useExisting: PgDekRepository },
    {
      provide: AUDIT_PRODUCER,
      inject: [CONFIG],
      useFactory: (config: ProfileConfig): AuditProducer => {
        if (config.kafkaBrokers) {
          return new KafkaAuditProducer({
            clientId: 'service-profile',
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
        config: ProfileConfig,
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
    // The Cedar PDP is constructed once from the bundled, in-repo policy set
    // (owner.cedar + beneficiary.cedar + profile.cedar). Deny by default.
    {
      provide: POLICY_DECISION_POINT,
      useFactory: (): PolicyDecisionPoint => new PolicyDecisionPoint(loadBundledPolicies()),
    },
    FieldCipher,
    ProfileAuthz,
    ProfileRepo,
    FamilyRepo,
    ContactsRepo,
    RolesRepo,
    PermissionGrantsRepo,
    ProfileService,
    FamilyService,
    ContactsService,
    RolesService,
    // Real cross-service session verification (@estate/auth-guard): CallerGuard
    // introspects the caller's bearer token against the identity service,
    // replacing the M2 gateway-injected `x-estate-user-id` header trust.
    {
      provide: SESSION_VERIFIER,
      inject: [CONFIG],
      useFactory: (config: ProfileConfig): HttpSessionVerifier =>
        new HttpSessionVerifier({ identityUrl: config.identityUrl }),
    },
    CallerGuard,
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
