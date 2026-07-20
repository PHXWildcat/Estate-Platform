import { Module } from '@nestjs/common';
import { Kafka } from 'kafkajs';
import { Client } from 'pg';
import { loadConfig, type ServiceConfig } from './config';
import { AuditConsumer } from './consumer';
import { AuditIngestor } from './ingestor';
import { ChainVerifier } from './verifier';

export const APP_CONFIG = 'APP_CONFIG';
export const PG_CLIENT = 'PG_CLIENT';

/**
 * Standalone application context wiring (no HTTP surface in M1 — this
 * service is a Kafka consumer worker; docs/01 §2.11).
 *
 * The pg Client is a single dedicated session by design: the ingestor's
 * chain-head row lock and transaction must live on one connection.
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
      provide: AuditConsumer,
      useFactory: (config: ServiceConfig, ingestor: AuditIngestor): AuditConsumer => {
        const kafka = new Kafka({ clientId: 'audit-service', brokers: config.kafkaBrokers });
        return new AuditConsumer(kafka.consumer({ groupId: 'audit-service' }), ingestor);
      },
      inject: [APP_CONFIG, AuditIngestor],
    },
  ],
})
export class AppModule {}
