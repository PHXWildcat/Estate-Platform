import { Inject, Module, type OnApplicationShutdown } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { KMSClient } from '@aws-sdk/client-kms';
import type { AuditProducer } from '@estate/audit-emitter';
import {
  CallerGuard,
  HttpSessionVerifier,
  SESSION_VERIFIER,
  StepUpGuard,
} from '@estate/auth-guard';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import {
  FieldCrypto,
  LocalKmsProvider,
  type DekRepository,
  type KmsKeyProvider,
} from '@estate/crypto';
import { InMemoryAuditProducer, KafkaAuditProducer } from '@estate/kafka';
import { AwsKmsProvider } from '@estate/kms-aws';
import type { PoolConfig } from 'pg';
import { AssistantController } from './assistant.controller';
import { AssistantAuthz } from './authz.service';
import { AssetsClient, DocumentsClient, ProfileClient } from './clients';
import { loadConfig, type AiAssistantConfig } from './config';
import { ConsentsController } from './consents.controller';
import { ConsentsRepo } from './consents.repo';
import { ConversationService, TOOL_EXECUTOR, type ToolExecutorPort } from './conversation.service';
import { ConversationsRepo } from './conversations.repo';
import { Db } from './db';
import { PgAssistantDekRepository } from './dek.repository';
import {
  AUDIT_PRODUCER,
  CLOCK,
  CONFIG,
  DEK_REPOSITORY,
  FIELD_CRYPTO,
  LLM_GATEWAY,
  PG_POOL_CONFIG,
  POLICY_DECISION_POINT,
} from './di-tokens';
import { EventsService } from './events.service';
import { FieldCipher } from './field-cipher';
import { HttpErrorFilter } from './http-error.filter';
import { StubLlmGateway, type LlmGateway } from './llm-gateway';
import { MessagesRepo } from './messages.repo';
import { ToolExecutor } from './tool-executor';
import { buildToolRegistry, ToolRegistry } from './tools';

/**
 * THIS MODULE WIRES NO SERVICE CREDENTIAL, IN EITHER DIRECTION, AND THAT
 * ABSENCE IS THE DESIGN — see src/di-tokens.ts for the argument in full.
 *
 * There is no `provide: SERVICE_CREDENTIAL` here and no `*_INTERNAL_TOKEN`
 * anywhere in `src/**`, because this service exposes no internal route for a
 * peer to open and reaches its own peers by FORWARDING the caller's bearer
 * (the M8 PR5 BFF pattern, realized in src/clients/http.ts). It is the one
 * process in the product an attacker can address in natural language — through
 * the document text and OCR output it is asked to read (docs/03 §4 TB5, risk
 * #6) — so a static key that opens another service's internal routes must not
 * sit behind it. A repo-wide fence spec reads this file and fails the build if
 * one appears; the credential graph in packages/auth-guard likewise lists this
 * service as a HOLDER of nothing, and test/config.spec.ts asserts the empty set
 * in both directions.
 */

/**
 * Select the model-provider gateway. Exhaustive over the config union with a
 * `never` check — a ternary chain that fell through to the stub is the M4
 * fail-open-in-style lesson, and here the failure would be silent in the worst
 * possible place: a deployment that believes it is talking to a reviewed
 * provider while a deterministic stub answers, or the reverse.
 *
 * `loadConfig` already refuses `LLM_MODE=anthropic` outright in every
 * environment until PR2 wires the live adapter; the throwing arm below makes
 * that invariant LOCAL, so this selector can never be reached with a mode it
 * has no implementation for (the notifications/settlement selector shape).
 */
function llmGatewayFor(config: AiAssistantConfig): LlmGateway {
  const llm = config.llm;
  switch (llm.mode) {
    case 'stub':
      return new StubLlmGateway();
    case 'anthropic':
      throw new Error('LLM_MODE "anthropic" has no adapter in this build (M10 PR2 wires it)');
    default: {
      const exhausted: never = llm;
      throw new Error(`unhandled LLM_MODE: ${String(exhausted)}`);
    }
  }
}

/**
 * Select the KMS backend. Production uses AWS KMS under THIS service's own KEK
 * ('ai-assistant/kek') — never profile's 'core/kek', even though profile,
 * settlement and notifications share the cluster — so the KMS grant, not the
 * database, is the isolation chokepoint (docs/03 §5.3): a co-tenant with SELECT
 * on `assistant_messages` still holds no grant that can unwrap a conversation.
 * config.ts already fails fast if the active mode's settings are missing.
 */
function kmsProviderFor(config: AiAssistantConfig): KmsKeyProvider {
  if (config.kms.mode === 'aws') {
    const { region, endpoint, keyId } = config.kms;
    return new AwsKmsProvider(new KMSClient({ region, ...(endpoint ? { endpoint } : {}) }), {
      keyId,
    });
  }
  return new LocalKmsProvider(config.kms.masterKey);
}

@Module({
  controllers: [AssistantController, ConsentsController],
  providers: [
    { provide: CONFIG, useFactory: (): AiAssistantConfig => loadConfig() },
    { provide: CLOCK, useValue: (): Date => new Date() },
    {
      provide: PG_POOL_CONFIG,
      inject: [CONFIG],
      useFactory: (config: AiAssistantConfig): PoolConfig => ({
        connectionString: config.databaseUrl,
      }),
    },
    Db,
    {
      provide: AUDIT_PRODUCER,
      inject: [CONFIG],
      useFactory: (config: AiAssistantConfig): AuditProducer => {
        if (config.kafkaBrokers) {
          return new KafkaAuditProducer({
            clientId: 'service-ai-assistant',
            brokers: config.kafkaBrokers,
          });
        }
        // Config already fails fast in production without brokers; this guard
        // makes the invariant local and unmissable. The no-op producer can
        // NEVER be constructed in production — this service's audit trail is
        // the only record of what estate data reached a model provider.
        if (config.nodeEnv === 'production') {
          throw new Error('audit emission requires Kafka in production');
        }
        return new InMemoryAuditProducer();
      },
    },
    EventsService,
    // The Cedar PDP is constructed once from the bundled, in-repo policy set
    // (assistant.cedar's single owner-scoped permit, whose resource attribute is
    // `subject` rather than `owner` precisely so owner.cedar cannot widen it).
    // Deny by default.
    {
      provide: POLICY_DECISION_POINT,
      useFactory: (): PolicyDecisionPoint => new PolicyDecisionPoint(loadBundledPolicies()),
    },
    { provide: LLM_GATEWAY, inject: [CONFIG], useFactory: llmGatewayFor },
    PgAssistantDekRepository,
    { provide: DEK_REPOSITORY, useExisting: PgAssistantDekRepository },
    {
      provide: FIELD_CRYPTO,
      inject: [CONFIG, DEK_REPOSITORY, EventsService],
      useFactory: (
        config: AiAssistantConfig,
        deks: DekRepository,
        events: EventsService,
      ): FieldCrypto =>
        new FieldCrypto(
          kmsProviderFor(config),
          deks,
          async (event): Promise<void> => {
            // Every field decryption is a logged event (docs/01 Zone B rule) —
            // here, that means every turn of a transcript opened, whether by
            // the user reading their own history back or by the service
            // rebuilding the context for the next turn. `purpose` is what tells
            // those two apart after the fact, and it carries no plaintext.
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
    FieldCipher,
    // Real cross-service session verification: the guards resolve the caller's
    // bearer token against the identity service (@estate/auth-guard), and the
    // subject every route acts on is the one identity confirms — never a path
    // parameter, never a body field, never a value the model produced.
    {
      provide: SESSION_VERIFIER,
      inject: [CONFIG],
      useFactory: (config: AiAssistantConfig): HttpSessionVerifier =>
        new HttpSessionVerifier({ identityUrl: config.identityUrl }),
    },
    CallerGuard,
    StepUpGuard,
    AssistantAuthz,
    ConversationsRepo,
    MessagesRepo,
    ConsentsRepo,
    // The closed tool surface, built once at boot. `buildToolRegistry` runs the
    // contract checks as it constructs — a duplicate name, or any tool whose
    // input declares a subject, is a process that will not start rather than a
    // request that quietly reads the wrong estate (tools/registry.ts).
    //
    // The peer clients are constructed here and hold NO credential: each method
    // takes the caller's own bearer per invocation, so the registry is stateless
    // with respect to authority.
    {
      provide: ToolRegistry,
      inject: [CONFIG],
      useFactory: (config: AiAssistantConfig): ToolRegistry =>
        buildToolRegistry({
          assets: new AssetsClient(config.assetsUrl),
          documents: new DocumentsClient(config.documentsUrl),
          profile: new ProfileClient(config.profileUrl),
        }),
    },
    ToolExecutor,
    {
      // Bound through a typed factory rather than `useExisting` on purpose: the
      // annotated return type makes the compiler prove that ToolExecutor
      // satisfies ToolExecutorPort. A symbol token is otherwise unchecked, and
      // a drift between the two — an argument order, a return shape — would
      // surface only at runtime, inside the turn loop, in production. That is
      // the M8 PR5 lesson about latent wiring bugs that every test still passes.
      provide: TOOL_EXECUTOR,
      inject: [ToolExecutor],
      useFactory: (executor: ToolExecutor): ToolExecutorPort => executor,
    },
    ConversationService,
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
