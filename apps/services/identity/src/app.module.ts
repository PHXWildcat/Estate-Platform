import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import type { AuditProducer } from '@estate/audit-emitter';
import { FieldCrypto, LocalKmsProvider, type DekRepository } from '@estate/crypto';
import type { PoolConfig } from 'pg';
import { AuthController } from './auth.controller';
import { AuthEventsRepo } from './auth-events.repo';
import { AuthService } from './auth.service';
import { InMemoryAuditProducer, KafkaAuditProducer } from './audit-producer';
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
import { PasswordHasher } from './password';
import { SessionGuard } from './session.guard';
import { SessionsRepo } from './sessions.repo';
import { StepUpGuard } from './stepup.guard';
import { UsersRepo } from './users.repo';

@Module({
  controllers: [AuthController],
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
    {
      provide: FIELD_CRYPTO,
      inject: [CONFIG, DEK_REPOSITORY, EventsService],
      useFactory: (
        config: IdentityConfig,
        deks: DekRepository,
        events: EventsService,
      ): FieldCrypto =>
        new FieldCrypto(
          // LocalKmsProvider is DEV/TEST ONLY — replaced by the AWS KMS
          // adapter (CloudHSM-rooted KEKs) before any real deployment.
          new LocalKmsProvider(config.kmsMasterKey),
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
    MfaRepo,
    AuthEventsRepo,
    AuthService,
    SessionGuard,
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
