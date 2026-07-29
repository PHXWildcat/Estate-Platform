import { connect } from 'node:net';
import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { KMSClient } from '@aws-sdk/client-kms';
import { S3Client } from '@aws-sdk/client-s3';
import { TextractClient } from '@aws-sdk/client-textract';
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
  SERVICE_CREDENTIAL,
  SESSION_VERIFIER,
  ServiceCredentialGuard,
  StepUpGuard,
} from '@estate/auth-guard';
import {
  HttpSettlementAuthority,
  SETTLEMENT_AUTHORITY,
  type SettlementAuthority,
} from '@estate/settlement-client';
import type { PoolConfig } from 'pg';
import { InMemoryAuditProducer, KafkaAuditProducer } from './audit-producer';
import { DocumentsAuthz } from './authz.service';
import { loadConfig, type DocumentsConfig } from './config';
import { ContentCipher } from './content-cipher';
import { Db } from './db';
import { PgDocumentDekRepository } from './dek.repository';
import {
  AUDIT_PRODUCER,
  CLOCK,
  CONFIG,
  DEK_REPOSITORY,
  FIELD_CRYPTO,
  MALWARE_SCANNER,
  OBJECT_STORE,
  OCR_ENGINE,
  PG_POOL_CONFIG,
  POLICY_DECISION_POINT,
} from './di-tokens';
import { DocumentsController } from './documents.controller';
import { DocumentsRepo } from './documents.repo';
import { DocumentsService } from './documents.service';
import { EventsService } from './events.service';
import { EvidenceController } from './evidence.controller';
import { LegalHoldController } from './legal-hold.controller';
import { HttpErrorFilter } from './http-error.filter';
import { ClamdScanner, StubScanner, type MalwareScanner } from './malware-scanner';
import { LocalFsObjectStore, type ObjectStore } from './object-store';
import { StubOcr, TesseractOcr, TextractOcr, type OcrEngine } from './ocr';
import { S3ObjectStore, s3ClientConfig } from './s3-object-store';
import { SearchIndexer } from './search-indexer';
import { SearchTokensRepo } from './search-tokens.repo';
import { TemplateEngine } from './template-engine';
import { TemplatesController } from './templates.controller';
import { TemplatesRepo } from './templates.repo';
import { VersionsRepo } from './versions.repo';

/**
 * Select the KMS backend. Production uses AWS KMS (CloudHSM-rooted KEKs, the
 * insider-threat chokepoint per docs/03 §5.3) under this cluster's own KEK
 * alias ('documents/kek'); dev/test uses the in-process LocalKmsProvider.
 * config.ts already fails fast if the active mode's settings are missing.
 */
function kmsProviderFor(config: DocumentsConfig): KmsKeyProvider {
  if (config.kms.mode === 'aws') {
    const { region, endpoint, keyId } = config.kms;
    return new AwsKmsProvider(new KMSClient({ region, ...(endpoint ? { endpoint } : {}) }), {
      keyId,
    });
  }
  return new LocalKmsProvider(config.kms.masterKey);
}

/** Select the object store (fs dev/test, S3 in production; config-enforced). */
function objectStoreFor(config: DocumentsConfig): ObjectStore {
  if (config.objectStore.mode === 's3') {
    const { region, endpoint, bucket } = config.objectStore;
    return new S3ObjectStore(new S3Client(s3ClientConfig(region, endpoint)), bucket);
  }
  return new LocalFsObjectStore(config.objectStore.dir);
}

/** Select the malware scanner (stub dev/test, clamd in production). */
function scannerFor(config: DocumentsConfig): MalwareScanner {
  if (config.scanner.mode === 'clamd') {
    const { host, port } = config.scanner;
    return new ClamdScanner({ connect: () => connect(port, host) });
  }
  return new StubScanner();
}

/**
 * Select the OCR engine (stub dev/test; a real engine in production).
 *
 * Exhaustive by construction: a chain of `if`s falling through to `StubOcr`
 * would silently hand a FUTURE engine the stub, which is the fail-open-in-style
 * the M4 review found on the scan gate. The `never` makes that a compile error.
 */
function ocrFor(config: DocumentsConfig): OcrEngine {
  switch (config.ocr.mode) {
    case 'textract': {
      const { region, endpoint } = config.ocr;
      return new TextractOcr(new TextractClient({ region, ...(endpoint ? { endpoint } : {}) }));
    }
    case 'tesseract':
      return new TesseractOcr({ endpoint: config.ocr.endpoint });
    case 'stub':
      return new StubOcr();
    default: {
      const unreachable: never = config.ocr;
      throw new Error(`unsupported OCR engine: ${JSON.stringify(unreachable)}`);
    }
  }
}

@Module({
  controllers: [DocumentsController, EvidenceController, LegalHoldController, TemplatesController],
  providers: [
    { provide: CONFIG, useFactory: (): DocumentsConfig => loadConfig() },
    { provide: CLOCK, useValue: (): Date => new Date() },
    {
      provide: PG_POOL_CONFIG,
      inject: [CONFIG],
      useFactory: (config: DocumentsConfig): PoolConfig => ({
        connectionString: config.databaseUrl,
      }),
    },
    Db,
    PgDocumentDekRepository,
    { provide: DEK_REPOSITORY, useExisting: PgDocumentDekRepository },
    {
      provide: AUDIT_PRODUCER,
      inject: [CONFIG],
      useFactory: (config: DocumentsConfig): AuditProducer => {
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
        config: DocumentsConfig,
        deks: DekRepository,
        events: EventsService,
      ): FieldCrypto =>
        new FieldCrypto(
          kmsProviderFor(config),
          deks,
          async (event): Promise<void> => {
            // Every content decryption is a logged event (docs/01 Zone B
            // rule). The DEK subject in this cluster is the DOCUMENT
            // (per-object DEKs), so event.userId is a document id.
            await events.audit.emit({
              action: 'crypto.field.decrypted',
              actorId: event.actorId,
              actorType: event.actorType,
              onBehalfOf: null,
              resourceType: 'document',
              resourceId: event.userId,
              sessionId: null,
              detail: { dekId: event.dekId, field: event.field, purpose: event.purpose },
            });
          },
          { kekAlias: config.kekAlias },
        ),
    },
    {
      provide: OBJECT_STORE,
      inject: [CONFIG],
      useFactory: (config: DocumentsConfig): ObjectStore => objectStoreFor(config),
    },
    {
      provide: MALWARE_SCANNER,
      inject: [CONFIG],
      useFactory: (config: DocumentsConfig): MalwareScanner => scannerFor(config),
    },
    {
      provide: OCR_ENGINE,
      inject: [CONFIG],
      useFactory: (config: DocumentsConfig): OcrEngine => ocrFor(config),
    },
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
      useFactory: (config: DocumentsConfig): HttpSessionVerifier =>
        new HttpSessionVerifier({ identityUrl: config.identityUrl }),
    },
    // M7: settlement answers evidence-read authority questions; the client
    // fails closed, so an unreachable settlement refuses rather than widens.
    {
      provide: SETTLEMENT_AUTHORITY,
      inject: [CONFIG],
      useFactory: (config: DocumentsConfig): SettlementAuthority =>
        new HttpSettlementAuthority({ settlementUrl: config.settlementUrl }),
    },
    {
      // '' when unset: ServiceCredentialGuard fails closed and the internal
      // legal-hold route refuses everything (dev must opt in explicitly).
      provide: SERVICE_CREDENTIAL,
      inject: [CONFIG],
      useFactory: (config: DocumentsConfig): string => config.internalApiToken,
    },
    ServiceCredentialGuard,
    ContentCipher,
    DocumentsAuthz,
    TemplatesRepo,
    TemplateEngine,
    DocumentsRepo,
    VersionsRepo,
    SearchIndexer,
    SearchTokensRepo,
    DocumentsService,
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
