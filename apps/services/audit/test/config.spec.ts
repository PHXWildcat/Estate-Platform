import { credentialEnvVarsFor, credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
import { loadConfig, loadDbConfig } from '../src/config';

const BASE = {
  DATABASE_URL: 'postgres://localhost:5438/audit',
  KAFKA_BROKERS: 'k1:9092, k2:9092 ,',
};

describe('audit service config', () => {
  it('parses a comma-separated broker list', () => {
    expect(loadConfig(BASE).kafkaBrokers).toEqual(['k1:9092', 'k2:9092']);
  });

  it('fails fast without a database url or brokers', () => {
    // The audit worker exists to consume the append-only chain; a silent
    // partial configuration would drop events rather than fail loudly.
    expect(() => loadConfig({ KAFKA_BROKERS: 'k1:9092' })).toThrow(/DATABASE_URL/);
    expect(() => loadConfig({ DATABASE_URL: BASE.DATABASE_URL })).toThrow(/KAFKA_BROKERS/);
  });

  it('names variables in errors, never their values', () => {
    // DATABASE_URL embeds credentials, so the message must stay a name list.
    const secret = 'postgres://user:hunter2@db.internal:5438/audit';
    try {
      loadConfig({ DATABASE_URL: secret });
      throw new Error('expected a config error');
    } catch (err) {
      expect((err as Error).message).not.toContain('hunter2');
      expect((err as Error).message).toContain('KAFKA_BROKERS');
    }
  });

  it('lets the CLIs load a database-only config', () => {
    expect(loadDbConfig({ DATABASE_URL: BASE.DATABASE_URL })).toEqual({
      databaseUrl: BASE.DATABASE_URL,
    });
  });
});

describe('service-credential graph (packages/auth-guard/src/credential-graph.ts)', () => {
  it('holds exactly the credentials the graph grants it — no more, no fewer', () => {
    // Audit is granted none, and that is the assertion. It is a Kafka consumer
    // with no HTTP surface at all, so it neither expects nor presents a service
    // credential — and the append-only chain is precisely what an attacker who
    // reached a credential would want to touch. Every credential in the product
    // is in this environment; audit must absorb none of them.
    const config = loadConfig({ ...BASE, ...credentialSentinelEnv() });
    expect(credentialsHeldIn(config)).toEqual(credentialEnvVarsFor('audit'));
    expect(credentialEnvVarsFor('audit')).toEqual([]);
  });
});
