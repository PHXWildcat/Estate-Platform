/**
 * The local stack's shape, as data.
 *
 * Everything the compose file, the generator and the doctor need to agree on
 * lives here once. The alternative — the same hostnames, ports and cluster
 * assignments retyped into YAML — is how a stack drifts from the services it
 * is supposed to run.
 */

/** In-network addresses. NOT the host ports: inside the compose network every
 *  Postgres listens on 5432 and Redpanda on its PLAINTEXT listener. The
 *  5433-5438 host mappings exist only for host tooling and PG_TEST_URL. */
export const NETWORK = {
  kafkaBrokers: 'redpanda:29092',
  awsEndpoint: 'http://localstack:4566',
  clamdHost: 'clamav',
  ocrUrl: 'http://tesseract:8884',
  region: 'us-east-1',
  objectStoreBucket: 'estate-documents-local',
} as const;

/** The six physical clusters (docs/02). Separate containers, never one server
 *  with six databases: no code may assume clusters are co-located. */
export const CLUSTERS = {
  auth: { host: 'pg-auth', database: 'auth', hostPort: 5433 },
  core: { host: 'pg-core', database: 'core', hostPort: 5434 },
  financial: { host: 'pg-financial', database: 'financial', hostPort: 5435 },
  documents: { host: 'pg-documents', database: 'documents', hostPort: 5436 },
  vault: { host: 'pg-vault', database: 'vault', hostPort: 5437 },
  audit: { host: 'pg-audit', database: 'audit', hostPort: 5438 },
} as const;

export type ClusterName = keyof typeof CLUSTERS;

const PG_USER = 'estate';
/** Dev-only, and never a secret: it is in docker-compose.dev.yml already. */
const PG_PASSWORD = 'estate_dev';

export function databaseUrl(cluster: ClusterName): string {
  const { host, database } = CLUSTERS[cluster];
  return `postgres://${PG_USER}:${PG_PASSWORD}@${host}:5432/${database}`;
}

/** A deployable in the stack, and the facts the generator needs about it. */
export interface StackService {
  /** Compose service name; also the image's ARG PKG target. */
  readonly name: string;
  readonly cluster: ClusterName;
  readonly port: number | null;
  /**
   * Which KEK alias this service's DEKs are wrapped under. `null` means the
   * service holds no key material at all — vault (Zone A: the server can
   * decrypt nothing) and audit (append-only hashes, no ciphertext).
   *
   * SIX DISTINCT ALIASES, not one shared key. The alias is baked into the KMS
   * EncryptionContext, so a DEK wrapped for one domain cannot be unwrapped
   * under another. That binding is testable locally; the IAM grant that would
   * stop a service *asking* is not — see the stack README's limits section.
   */
  readonly kekAlias: string | null;
}

export const SERVICES: readonly StackService[] = [
  { name: 'identity', cluster: 'auth', port: 3001, kekAlias: 'local/auth-kek' },
  { name: 'profile', cluster: 'core', port: 3002, kekAlias: 'core/kek' },
  { name: 'assets', cluster: 'financial', port: 3003, kekAlias: 'financial/kek' },
  { name: 'plaid', cluster: 'financial', port: 3004, kekAlias: 'plaid/kek' },
  { name: 'documents', cluster: 'documents', port: 3005, kekAlias: 'documents/kek' },
  { name: 'vault', cluster: 'vault', port: 3006, kekAlias: null },
  { name: 'settlement', cluster: 'core', port: 3007, kekAlias: 'settlement/kek' },
  { name: 'audit', cluster: 'audit', port: null, kekAlias: null },
];

/** The KMS key id each service is handed. One alias per service KEK. */
export function kmsKeyIdFor(service: StackService): string | null {
  return service.kekAlias === null ? null : `alias/estate-${service.name}-kek`;
}

/**
 * Migration ordering. DDL order between co-tenants is free (disjoint file
 * names, and the migrator ignores rows it has no file for), but RUNTIME order
 * is not: settlement queries profile's `contacts` and `role_assignments`
 * UNQUALIFIED, so profile's schema must exist before settlement's intake and
 * executor routes work. Running each cluster's owners in sequence also keeps
 * two jobs off the same fresh cluster at once — belt to the advisory-lock fix
 * in @estate/db.
 */
export const MIGRATION_ORDER: readonly (readonly string[])[] = [
  ['identity'],
  ['profile', 'settlement'],
  ['assets', 'plaid'],
  ['documents'],
  ['vault'],
  ['audit'],
];
