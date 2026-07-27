import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import type { AuditProducer } from '@estate/audit-emitter';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import {
  CallerGuard,
  HttpSessionVerifier,
  SESSION_VERIFIER,
  StepUpGuard,
} from '@estate/auth-guard';
import type { PoolConfig } from 'pg';
import { InMemoryAuditProducer, KafkaAuditProducer } from './audit-producer';
import { VaultAuthz } from './authz.service';
import { loadConfig, type VaultConfig } from './config';
import { Db } from './db';
import { AUDIT_PRODUCER, CLOCK, CONFIG, PG_POOL_CONFIG, POLICY_DECISION_POINT } from './di-tokens';
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
@Module({
  controllers: [VaultController],
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
    VaultAuthz,
    KeysetsRepo,
    ItemsRepo,
    HandshakesRepo,
    VaultSessionsRepo,
    VaultService,
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
