/**
 * The local stack's shape, as data.
 *
 * Everything the compose file, the generator and the doctor need to agree on
 * lives here once. The alternative — the same hostnames, ports and cluster
 * assignments retyped into YAML — is how a stack drifts from the services it
 * is supposed to run.
 */

/**
 * Where the stack's processes run relative to its infrastructure.
 *
 * 'compose': everything on the compose network — containers address each
 * other by service name and container-side port. The default, and what
 * `pnpm stack:up` runs.
 *
 * 'host': the infra containers stay in compose but the NODE PROCESSES run on
 * the host (CI's fast gate, and the local inner loop) — they reach infra
 * through the PUBLISHED ports on localhost.
 */
export type Addressing = 'compose' | 'host';

interface NetworkAddresses {
  readonly kafkaBrokers: string;
  readonly awsEndpoint: string;
  readonly clamdHost: string;
  readonly ocrUrl: string;
  readonly region: string;
  readonly objectStoreBucket: string;
}

const SHARED = {
  region: 'us-east-1',
  objectStoreBucket: 'estate-documents-local',
} as const;

/** In-network addresses. NOT the host ports: inside the compose network every
 *  Postgres listens on 5432 and Redpanda on its PLAINTEXT listener. */
export const NETWORK: NetworkAddresses = {
  kafkaBrokers: 'redpanda:29092',
  awsEndpoint: 'http://localstack:4566',
  clamdHost: 'clamav',
  ocrUrl: 'http://tesseract:8884',
  ...SHARED,
};

/** The same infrastructure as seen from the HOST, via published ports. */
export const HOST_NETWORK: NetworkAddresses = {
  // Redpanda's OUTSIDE listener — the only one advertised as localhost.
  kafkaBrokers: 'localhost:9092',
  awsEndpoint: 'http://localhost:4566',
  clamdHost: 'localhost',
  ocrUrl: 'http://localhost:8884',
  ...SHARED,
};

/**
 * The AWS endpoint in PRODUCTION mode: TLS, through the terminating proxy.
 *
 * Production config refuses a plaintext AWS_ENDPOINT_URL — wrapped DEKs must
 * not cross the wire in the clear — so the production profile reaches
 * LocalStack through nginx with a generated cert the services actually verify
 * (NODE_EXTRA_CA_CERTS; nothing disables verification). The alternative was
 * weakening the guard, which would delete the control being rehearsed.
 */
export const TLS_AWS_ENDPOINT = 'https://aws-tls' as const;
export const TLS_AWS_ENDPOINT_HOST = 'https://localhost:8443' as const;

/**
 * Where the generated CA is found.
 *
 * The proxy writes it to a BIND MOUNT rather than a named volume, so the same
 * file is visible to containers at `/certs` and to host processes under
 * `./.stack-certs` — host-mode runs trust the identical CA with no extraction
 * step, and there is only one cert in play either way.
 */
export const TLS_CA_PATH = '/certs/aws-tls.crt' as const;
export const TLS_CA_PATH_HOST = './.stack-certs/aws-tls.crt' as const;

export function tlsCaPathFor(addressing: Addressing): string {
  return addressing === 'host' ? TLS_CA_PATH_HOST : TLS_CA_PATH;
}

export function networkFor(
  addressing: Addressing,
  mode: 'development' | 'production' = 'development',
): NetworkAddresses {
  const base = addressing === 'host' ? HOST_NETWORK : NETWORK;
  if (mode !== 'production') {
    return base;
  }
  return {
    ...base,
    awsEndpoint: addressing === 'host' ? TLS_AWS_ENDPOINT_HOST : TLS_AWS_ENDPOINT,
  };
}

/** Base URL of a service, as seen by its peers under each addressing. */
export function serviceUrl(name: string, addressing: Addressing): string {
  const service = SERVICES.find((s) => s.name === name);
  if (!service || service.port === null) {
    throw new Error(`no addressable service named ${name}`);
  }
  return addressing === 'host'
    ? `http://localhost:${service.port}`
    : `http://${service.name}:${service.port}`;
}

/**
 * THE TWO BROWSER-FACING ORIGINS (M15).
 *
 * These are addresses a BROWSER uses, so unlike `serviceUrl` they do not change
 * with `Addressing`: in compose mode they are the published ports, and in host
 * mode they are the same ports on the same names.
 *
 * `vault.localhost` rather than a second port on `localhost`, and that is the
 * whole isolation. MEASURED in a real browser before it was relied on:
 *
 *   · cookie scope IGNORES THE PORT, so a vault surface at `localhost:3010`
 *     receives the app's `estate_access`/`estate_refresh` on every request —
 *     observed live, with a probe on an unrelated port being handed a real
 *     session from a previous stack run;
 *   · `vault.localhost` receives NONE of them, because the app's cookies are
 *     host-only;
 *   · and `*.localhost` is a potentially-trustworthy origin, so the vault's
 *     `__Host-` prefixed `Secure` cookie is accepted there over plain http
 *     exactly as the BFF's is on `localhost`. No TLS terminator is needed for
 *     the dev stack, and the prefix is unconditional in every environment.
 *
 * Production addressing is `vault.<domain>` beside `app.<domain>`. The residual
 * is recorded rather than hidden: a subdomain shares a registrable domain with
 * the app, so a cookie set with a `Domain=` attribute on the parent would be
 * visible to both — which is precisely why the vault's cookie carries `__Host-`,
 * making host-only a property the browser enforces rather than a convention.
 * A separate registrable domain is strictly better and is a deployment choice.
 */
export const APP_ORIGIN = 'http://localhost:3000' as const;
export const VAULT_ORIGIN = 'http://vault.localhost:3010' as const;
export const VAULT_WEB_PORT = 3010;

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

export function databaseUrl(cluster: ClusterName, addressing: Addressing = 'compose'): string {
  const { host, database, hostPort } = CLUSTERS[cluster];
  return addressing === 'host'
    ? `postgres://${PG_USER}:${PG_PASSWORD}@localhost:${hostPort}/${database}`
    : `postgres://${PG_USER}:${PG_PASSWORD}@${host}:5432/${database}`;
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
   * EIGHT DISTINCT ALIASES, not one shared key. The alias is baked into the
   * KMS EncryptionContext, so a DEK wrapped for one domain cannot be unwrapped
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
  // Third core co-tenant (M9): disjoint tables, own KEK — profile and
  // settlement share the cluster and can never unwrap a recipient address.
  { name: 'notifications', cluster: 'core', port: 3008, kekAlias: 'notifications/kek' },
  // FOURTH core co-tenant (M10), same rule one more time: conversation turns
  // quote estate content back to the user, so they are wrapped under this
  // service's OWN KEK and the three tenants sharing the cluster can never
  // unwrap one (docs/03 §5.3 — the KMS grant is the chokepoint, not the
  // database). Also the first service name with a hyphen, which is why every
  // env prefix goes through `envPrefixFor` below.
  { name: 'ai-assistant', cluster: 'core', port: 3009, kekAlias: 'ai-assistant/kek' },
  { name: 'audit', cluster: 'audit', port: null, kekAlias: null },
];

/** The KMS key id each service is handed. One alias per service KEK. */
export function kmsKeyIdFor(service: StackService): string | null {
  return service.kekAlias === null ? null : `alias/estate-${service.name}-kek`;
}

/**
 * The flat-file env-var prefix for a service. Service names are directory
 * names, and a directory may contain a hyphen where an environment-variable
 * key may not — `ai-assistant` would otherwise mint `AI-ASSISTANT_DATABASE_URL`,
 * which is not a legal identifier and which `--env-file` will not hand back.
 * A plain `toUpperCase()` was correct for nine single-word services and stopped
 * being correct at the tenth, so the normalization lives in one place rather
 * than at each of the eleven call sites that build a prefix.
 */
export function envPrefixFor(name: string): string {
  return name.toUpperCase().replace(/-/g, '_');
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
  ['profile', 'settlement', 'notifications', 'ai-assistant'],
  ['assets', 'plaid'],
  ['documents'],
  ['vault'],
  ['audit'],
];
