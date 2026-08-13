import { Module } from '@nestjs/common';
import { Kafka } from 'kafkajs';
import { Client } from 'pg';
import { AuditEmitter } from '@estate/audit-emitter';
import { KafkaAuditProducer } from '@estate/kafka';
import { loadConfig, type ServiceConfig } from './config';
import { AuditConsumer } from './consumer';
import { DecryptRateDetector } from './decrypt-rate-detector';
import { AuditIngestor } from './ingestor';
import { ChainVerifier } from './verifier';

export const APP_CONFIG = 'APP_CONFIG';
export const PG_CLIENT = 'PG_CLIENT';
export const DETECTOR_PG_CLIENT = 'DETECTOR_PG_CLIENT';
export const AUDIT_PRODUCER = 'AUDIT_PRODUCER';

/**
 * Standalone application context wiring (no HTTP surface in M1 — this
 * service is a Kafka consumer worker; docs/01 §2.11).
 *
 * The pg Client is a single dedicated session by design: the ingestor's
 * chain-head row lock and transaction must live on one connection. The M18
 * detector therefore gets its OWN dedicated session (DETECTOR_PG_CLIENT) —
 * an advisory windowed read must never queue behind, or interleave with, the
 * chain writer's transaction.
 *
 * AUDIT_PRODUCER is this service's FIRST Kafka producer (M18): the detector's
 * anomaly event goes out through the sanctioned AuditEmitter path — schema
 * validation + the PII firewall — onto the same topic this service consumes,
 * so the event lands in the verified chain like any other. No InMemory
 * fallback exists here on purpose: unlike the Zone B services, audit REQUIRES
 * brokers in every environment (KAFKA_BROKERS is one of its two config
 * variables), so there is no configuration in which a no-op producer would be
 * legitimate. Suites never construct this module — they build the classes
 * directly.
 */
@Module({
  providers: [
    { provide: APP_CONFIG, useFactory: (): ServiceConfig => loadConfig() },
    {
      provide: PG_CLIENT,
      useFactory: async (config: ServiceConfig): Promise<Client> => {
        const client = new Client({ connectionString: config.databaseUrl });
        await client.connect();
        return client;
      },
      inject: [APP_CONFIG],
    },
    {
      provide: DETECTOR_PG_CLIENT,
      useFactory: async (config: ServiceConfig): Promise<Client> => {
        const client = new Client({ connectionString: config.databaseUrl });
        await client.connect();
        return client;
      },
      inject: [APP_CONFIG],
    },
    {
      provide: AUDIT_PRODUCER,
      useFactory: (config: ServiceConfig): KafkaAuditProducer =>
        new KafkaAuditProducer({ clientId: 'audit-service', brokers: config.kafkaBrokers }),
      inject: [APP_CONFIG],
    },
    {
      provide: AuditIngestor,
      useFactory: (client: Client): AuditIngestor => new AuditIngestor(client),
      inject: [PG_CLIENT],
    },
    {
      provide: ChainVerifier,
      useFactory: (client: Client): ChainVerifier => new ChainVerifier(client),
      inject: [PG_CLIENT],
    },
    {
      provide: DecryptRateDetector,
      useFactory: (client: Client, producer: KafkaAuditProducer): DecryptRateDetector =>
        new DecryptRateDetector(client, new AuditEmitter(producer)),
      inject: [DETECTOR_PG_CLIENT, AUDIT_PRODUCER],
    },
    {
      provide: AuditConsumer,
      useFactory: (config: ServiceConfig, ingestor: AuditIngestor): AuditConsumer => {
        const kafka = new Kafka({ clientId: 'audit-service', brokers: config.kafkaBrokers });
        return new AuditConsumer(
          kafka.consumer({
            groupId: 'audit-service',
            // Explicit, though it matches kafkajs's default: a RETRIABLE crash
            // (a broker blip) should reconnect, because the events are still on
            // the topic and a container restart buys nothing. This callback can
            // only VETO a restart, never force one — a non-retriable crash is
            // fatal regardless, which is why consumer.ts handles CRASH itself.
            retry: { restartOnFailure: () => Promise.resolve(true) },
          }),
          ingestor,
        );
      },
      inject: [APP_CONFIG, AuditIngestor],
    },
  ],
})
export class AppModule {}
