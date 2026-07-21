import { z } from 'zod';

/**
 * Environment configuration. On failure, the thrown error names the missing
 * or invalid VARIABLE NAMES only — never their values (DATABASE_URL embeds
 * credentials).
 */
const ServiceEnvSchema = z.object({
  DATABASE_URL: z.string().min(1),
  /** Comma-separated broker list, e.g. "kafka-1:9092,kafka-2:9092". */
  KAFKA_BROKERS: z.string().min(1),
});

const DbEnvSchema = ServiceEnvSchema.pick({ DATABASE_URL: true });

export interface ServiceConfig {
  databaseUrl: string;
  kafkaBrokers: string[];
}

export interface DbConfig {
  databaseUrl: string;
}

function fail(prefix: string, error: z.ZodError): never {
  const names = [...new Set(error.issues.map((i) => i.path.join('.') || '(env)'))];
  throw new Error(`${prefix}: missing/invalid environment variables: ${names.join(', ')}`);
}

/** Full worker configuration (Kafka consumer + database). */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): ServiceConfig {
  const parsed = ServiceEnvSchema.safeParse(env);
  if (!parsed.success) {
    fail('audit-service', parsed.error);
  }
  return {
    databaseUrl: parsed.data.DATABASE_URL,
    kafkaBrokers: parsed.data.KAFKA_BROKERS.split(',')
      .map((b) => b.trim())
      .filter((b) => b.length > 0),
  };
}

/** Database-only configuration for the migrate/verify CLIs. */
export function loadDbConfig(env: NodeJS.ProcessEnv = process.env): DbConfig {
  const parsed = DbEnvSchema.safeParse(env);
  if (!parsed.success) {
    fail('audit-service', parsed.error);
  }
  return { databaseUrl: parsed.data.DATABASE_URL };
}
