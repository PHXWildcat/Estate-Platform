import {
  inboundCredentialsFor,
  outboundCredentialsFor,
  type ServiceName,
} from '@estate/auth-guard';
import {
  envPrefixFor,
  kmsKeyIdFor,
  SERVICES,
  serviceUrl,
  type Addressing,
  type StackService,
} from './topology';

/**
 * Maps the flat generated environment (`.env.stack`) onto each process's own
 * variables — the same mapping docker-compose.stack.yml performs for
 * containers, expressed once as code so the host-mode supervisor cannot drift
 * from it. `compose-parity.spec.ts` parses the YAML's environment blocks and
 * asserts the two agree, key for key.
 *
 * The mapping is where a service could be handed another service's key, so it
 * stays explicit: no wildcard passthrough of the parent environment.
 */

/** Which peers each service (and the BFF) calls, hence which *_URL it gets. */
const PEERS: Record<string, readonly string[]> = {
  identity: ['notifications'],
  profile: ['identity'],
  assets: ['identity', 'settlement'],
  plaid: ['identity'],
  documents: ['identity', 'settlement'],
  vault: ['identity', 'settlement', 'notifications'],
  settlement: ['identity', 'notifications', 'documents'],
  notifications: [],
  audit: [],
};

export interface ServiceEnvOptions {
  readonly addressing: Addressing;
  /** Host-mode path to the BFF's persisted-operations manifest. */
  readonly manifestPath?: string;
}

function fromFile(env: ReadonlyMap<string, string>, key: string): string {
  const value = env.get(key);
  if (value === undefined) {
    throw new Error(`generated environment is missing ${key} — regenerate .env.stack`);
  }
  return value;
}

/** The exact process environment for one stack service. */
export function serviceProcessEnv(
  service: StackService,
  env: ReadonlyMap<string, string>,
  options: ServiceEnvOptions,
): Record<string, string> {
  const upper = envPrefixFor(service.name);
  const out: Record<string, string> = {
    DATABASE_URL: fromFile(env, `${upper}_DATABASE_URL`),
    KAFKA_BROKERS: fromFile(env, 'KAFKA_BROKERS'),
  };

  // audit is headless and reads exactly two variables; everything below is
  // the HTTP services' shape.
  if (service.port !== null) {
    out['NODE_ENV'] = fromFile(env, 'STACK_MODE');
    out['PORT'] = String(service.port);
  }

  if (kmsKeyIdFor(service) !== null) {
    out['KMS_MODE'] = fromFile(env, `${upper}_KMS_MODE`);
    out['KMS_MASTER_KEY_HEX'] = fromFile(env, `${upper}_KMS_MASTER_KEY_HEX`);
    out['AWS_KMS_KEY_ID'] = fromFile(env, `${upper}_AWS_KMS_KEY_ID`);
    out['AWS_REGION'] = fromFile(env, 'AWS_REGION');
    out['AWS_ENDPOINT_URL'] = fromFile(env, 'AWS_ENDPOINT_URL');
    out['AWS_ACCESS_KEY_ID'] = fromFile(env, 'AWS_ACCESS_KEY_ID');
    out['AWS_SECRET_ACCESS_KEY'] = fromFile(env, 'AWS_SECRET_ACCESS_KEY');
    // Production reaches AWS over TLS through the stack's proxy, so the CA it
    // must trust travels with the AWS settings. Empty in development, where
    // the endpoint is plain http and Node needs no extra trust anchor.
    out['NODE_EXTRA_CA_CERTS'] = fromFile(env, 'NODE_EXTRA_CA_CERTS');
  }

  for (const peer of PEERS[service.name] ?? []) {
    out[`${envPrefixFor(peer)}_URL`] = serviceUrl(peer, options.addressing);
  }

  // Credentials come from the graph, never from a hand-kept list: the callee's
  // inbound slot plus each outbound grant, prefixed in the file, bare in the
  // process — exactly what the container mapping does.
  const name = service.name as ServiceName;
  for (const inbound of inboundCredentialsFor(name)) {
    // A zero-holder inbound edge has no minted slot; '' keeps the callee's
    // guard failing closed. (Every current edge has holders — M9 PR2 gave
    // documents' legal-hold edge its caller — but the rule is the graph's.)
    // Plural since M9's review: notifications expects one credential per
    // internal surface (send vs recipient-upsert).
    out[inbound.envVar] = env.get(`${upper}_${inbound.envVar}`) ?? '';
  }
  for (const outbound of outboundCredentialsFor(name)) {
    out[outbound.envVar] = fromFile(env, `${upper}_${outbound.envVar}`);
  }

  switch (service.name) {
    case 'identity':
      out['EMAIL_INDEX_KEY_HEX'] = fromFile(env, 'IDENTITY_EMAIL_INDEX_KEY_HEX');
      out['RP_ID'] = fromFile(env, 'RP_ID');
      out['RP_ORIGIN'] = fromFile(env, 'RP_ORIGIN');
      out['RP_NAME'] = fromFile(env, 'RP_NAME');
      break;
    case 'profile':
      out['EMAIL_INDEX_KEY_HEX'] = fromFile(env, 'PROFILE_EMAIL_INDEX_KEY_HEX');
      break;
    case 'plaid':
      out['ITEM_INDEX_KEY_HEX'] = fromFile(env, 'PLAID_ITEM_INDEX_KEY_HEX');
      out['PLAID_MODE'] = fromFile(env, 'PLAID_MODE');
      break;
    case 'documents':
      out['OBJECT_STORE_MODE'] = fromFile(env, 'DOCUMENTS_OBJECT_STORE_MODE');
      out['OBJECT_STORE_BUCKET'] = fromFile(env, 'OBJECT_STORE_BUCKET');
      out['SEARCH_INDEX_KEY_HEX'] = fromFile(env, 'DOCUMENTS_SEARCH_INDEX_KEY_HEX');
      out['SCANNER_MODE'] = fromFile(env, 'DOCUMENTS_SCANNER_MODE');
      out['CLAMD_HOST'] = fromFile(env, 'DOCUMENTS_CLAMD_HOST');
      out['OCR_MODE'] = fromFile(env, 'DOCUMENTS_OCR_MODE');
      out['OCR_URL'] = fromFile(env, 'DOCUMENTS_OCR_URL');
      break;
    case 'vault':
      out['NOTIFY_MODE'] = fromFile(env, 'VAULT_NOTIFY_MODE');
      break;
    case 'settlement':
      out['NOTIFY_MODE'] = fromFile(env, 'SETTLEMENT_NOTIFY_MODE');
      break;
    case 'notifications':
      out['EMAIL_MODE'] = fromFile(env, 'NOTIFICATIONS_EMAIL_MODE');
      out['SES_FROM_ADDRESS'] = fromFile(env, 'SES_FROM_ADDRESS');
      break;
    default:
      break;
  }
  return out;
}

/**
 * Which services a host-mode run starts.
 *
 * Plaid is excluded from a production-mode run for the same reason it has its
 * own compose profile: production config requires PLAID_MODE=live with real
 * credentials that do not exist, so the process would fail fast at boot — the
 * control working, but a supervisor that knowingly starts a doomed child and
 * then reports the death as a failure is testing nothing.
 */
export function plannedServices(env: ReadonlyMap<string, string>): readonly StackService[] {
  const production = env.get('STACK_MODE') === 'production';
  return SERVICES.filter((service) => !(production && service.name === 'plaid'));
}

/**
 * The base a child process inherits, with everything credential-shaped
 * removed. The mapping above sets each service's variables EXPLICITLY; what
 * must never happen is an ambient value — a developer's real AWS_PROFILE, a
 * stray token from the shell — reaching a child because nothing overwrote it.
 * The child still needs the platform basics (PATH, SystemRoot, TEMP …), so
 * this scrubs rather than starts from empty.
 */
export function scrubbedBaseEnv(parent: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(parent)) {
    if (value === undefined) {
      continue;
    }
    if (SCRUBBED.some((pattern) => pattern.test(key))) {
      continue;
    }
    out[key] = value;
  }
  return out;
}

/**
 * What never reaches a child from the ambient shell.
 *
 * The first three are credential-shaped. `NODE_TLS_REJECT_UNAUTHORIZED` and
 * `NODE_OPTIONS` are here for a different reason: the doctor refuses a stack
 * whose ENV FILE disables TLS verification, because that would make production
 * mode's https requirement decoration — but the doctor reads the file, and both
 * of these reach a child from the developer's shell without appearing in it.
 * `NODE_OPTIONS` is the same hole wearing a hat (it can carry
 * `--use-openssl-ca`, `--require`, and more). Anything a service genuinely
 * needs is set EXPLICITLY by the mapping above, including
 * `NODE_EXTRA_CA_CERTS`, which is why scrubbing it costs nothing.
 */
const SCRUBBED: readonly RegExp[] = [
  /^AWS_/i,
  /_INTERNAL_TOKEN$/,
  /^KMS_/,
  /^NODE_TLS_/,
  /^NODE_OPTIONS$/,
  /^NODE_EXTRA_CA_CERTS$/,
];

/** The BFF is not a StackService (no cluster, no credentials); mapped here. */
export function bffProcessEnv(
  env: ReadonlyMap<string, string>,
  options: ServiceEnvOptions,
): Record<string, string> {
  const out: Record<string, string> = {
    NODE_ENV: fromFile(env, 'STACK_MODE'),
    PORT: '4000',
    IDENTITY_URL: serviceUrl('identity', options.addressing),
    ASSETS_URL: serviceUrl('assets', options.addressing),
  };
  if (options.manifestPath) {
    out['PERSISTED_MANIFEST_PATH'] = options.manifestPath;
  }
  return out;
}
