import { randomBytes } from 'node:crypto';
import { SERVICE_CREDENTIAL_GRAPH } from '@estate/auth-guard';
import { databaseUrl, kmsKeyIdFor, NETWORK, SERVICES } from './topology';

/**
 * Generates the local stack's environment.
 *
 * WHY THIS EXISTS RATHER THAN A COMMITTED .env: CLAUDE.md forbids secrets in
 * committed env files, gitleaks is a merge-blocking gate, and — the real
 * reason — a committed value is a value people copy. The M7 collapse was one
 * string pasted into two credential slots.
 *
 * THE CREDENTIAL HALF IS THE POINT. `packages/auth-guard/src/credential-graph.ts`
 * records what it deliberately does NOT enforce: nothing verifies that a
 * holder's copy of a credential really equals the callee's inbound value — an
 * operator pasting one service's secret into another's slot re-creates the M7
 * collapse at deploy time with every service booting cleanly.
 *
 * Generating per EDGE closes that for every environment this produces. One
 * secret is minted for each edge and written to the callee's inbound slot and
 * to each holder's slot, so agreement is structural rather than clerical, and
 * two edges cannot collide because they are independently random. Settlement's
 * production check (its two credentials must differ) becomes a backstop for a
 * hand-edited file rather than the only line of defence.
 *
 * Precisely scoped: this closes the residual for GENERATED environments. A
 * hand-provisioned deployment is still unverified — but deriving provisioning
 * from the graph is the mechanism that carries over to a real secrets store.
 */

/** 32 bytes of hex — the shape every `*_KEY_HEX` variable validates. */
function hexKey(): string {
  return randomBytes(32).toString('hex');
}

/** A service credential. Comfortably over the 32-char production minimum. */
function secret(): string {
  return randomBytes(36).toString('base64url');
}

/**
 * Credentials LocalStack accepts and real AWS refuses.
 *
 * Not a formality — a safety mechanism. Environment variables outrank
 * `~/.aws/credentials` in the SDK's chain, so if the endpoint override is ever
 * missing or wrong, a request reaches real AWS carrying an obviously invalid
 * key and comes back rejected. Without these, an ambient developer profile
 * would make that same misconfiguration succeed silently against a real
 * account. `credentialsLookReal` in doctor.ts enforces the shape.
 */
export const DUMMY_AWS_ACCESS_KEY_ID = 'test';
export const DUMMY_AWS_SECRET_ACCESS_KEY = 'test';

export interface GenerateOptions {
  /** 'development' runs every flow; 'production' is the fail-fast rehearsal. */
  readonly mode: 'development' | 'production';
}

/** Ordered key/value pairs, so the written file is stable and reviewable. */
export type EnvEntries = ReadonlyArray<readonly [string, string]>;

interface Section {
  readonly title: string;
  readonly note?: string;
  readonly entries: EnvEntries;
}

/**
 * Assign every graph credential to the services entitled to it.
 *
 * Returns a map of service name → { envVar → value }. A service absent from
 * the map holds no credentials, which for most of them is correct and is what
 * each service's own config.spec.ts asserts.
 */
export function assignCredentials(
  mint: () => string = secret,
): ReadonlyMap<string, ReadonlyMap<string, string>> {
  const byService = new Map<string, Map<string, string>>();
  const put = (service: string, envVar: string, value: string): void => {
    const existing = byService.get(service) ?? new Map<string, string>();
    existing.set(envVar, value);
    byService.set(service, existing);
  };

  for (const edge of SERVICE_CREDENTIAL_GRAPH) {
    const value = mint();
    // The callee EXPECTS it on its own internal routes...
    put(edge.callee, edge.envVar, value);
    // ...and every declared holder PRESENTS the same value. Equality by
    // construction: there is no second place for it to be typed differently.
    for (const holder of edge.holders) {
      put(holder, edge.envVar, value);
    }
  }
  return byService;
}

/** Build the stack's environment. Deterministic given its key generators. */
export function generateEnv(
  options: GenerateOptions,
  mintKey: () => string = hexKey,
  mintSecret: () => string = secret,
): { sections: readonly Section[]; entries: EnvEntries } {
  const production = options.mode === 'production';
  const credentials = assignCredentials(mintSecret);
  const sections: Section[] = [];

  sections.push({
    title: 'Shared infrastructure',
    note: 'In-network addresses. The 5433-5438 host ports exist only for host tooling.',
    entries: [
      ['STACK_MODE', options.mode],
      ['KAFKA_BROKERS', NETWORK.kafkaBrokers],
      ['AWS_REGION', NETWORK.region],
      ['AWS_ENDPOINT_URL', NETWORK.awsEndpoint],
      ['AWS_ACCESS_KEY_ID', DUMMY_AWS_ACCESS_KEY_ID],
      ['AWS_SECRET_ACCESS_KEY', DUMMY_AWS_SECRET_ACCESS_KEY],
      ['OBJECT_STORE_BUCKET', NETWORK.objectStoreBucket],
    ],
  });

  for (const service of SERVICES) {
    const entries: Array<readonly [string, string]> = [];
    const upper = service.name.toUpperCase();
    entries.push([`${upper}_DATABASE_URL`, databaseUrl(service.cluster)]);

    const keyId = kmsKeyIdFor(service);
    if (keyId !== null) {
      // Every service that holds key material runs the REAL AWS adapter
      // against LocalStack, in both modes. That is the milestone's point: the
      // production KMS path has never been executed anywhere.
      entries.push([`${upper}_KMS_MODE`, 'aws']);
      entries.push([`${upper}_AWS_KMS_KEY_ID`, keyId]);
      // Still generated: it is what the service falls back to if KMS_MODE is
      // ever flipped to 'local', and dev config refuses to boot without it.
      entries.push([`${upper}_KMS_MASTER_KEY_HEX`, mintKey()]);
    }

    for (const [envVar, value] of credentials.get(service.name) ?? []) {
      entries.push([`${upper}_${envVar}`, value]);
    }
    sections.push({ title: `${service.name} service`, entries });
  }

  // Blind-index keys are per-service and INDEPENDENT. identity's keys
  // users.email_bidx in the auth cluster and profile's keys contacts.email_bidx
  // in core; nothing compares an index across services, so sharing one value
  // would create a correlation the schema never intended.
  sections.push({
    title: 'Per-service index keys (independent by design)',
    entries: [
      ['IDENTITY_EMAIL_INDEX_KEY_HEX', mintKey()],
      ['PROFILE_EMAIL_INDEX_KEY_HEX', mintKey()],
      ['PLAID_ITEM_INDEX_KEY_HEX', mintKey()],
      ['DOCUMENTS_SEARCH_INDEX_KEY_HEX', mintKey()],
    ],
  });

  sections.push({
    title: 'Adapter selection — every external dependency is REAL',
    note: 'Only Plaid stays stubbed: production requires PLAID_MODE=live and no credentials exist.',
    entries: [
      ['DOCUMENTS_OBJECT_STORE_MODE', 's3'],
      ['DOCUMENTS_SCANNER_MODE', 'clamd'],
      ['DOCUMENTS_CLAMD_HOST', NETWORK.clamdHost],
      ['DOCUMENTS_OCR_MODE', 'tesseract'],
      ['DOCUMENTS_OCR_URL', NETWORK.ocrUrl],
      ['PLAID_MODE', production ? 'live' : 'stub'],
    ],
  });

  sections.push({
    title: 'WebAuthn relying party',
    note: 'The stack is addressed as http://localhost:3000 — see the README.',
    entries: [
      ['RP_ID', 'localhost'],
      ['RP_ORIGIN', 'http://localhost:3000'],
      ['RP_NAME', 'Estate Platform (local stack)'],
    ],
  });

  const entries = sections.flatMap((section) => section.entries);
  return { sections, entries };
}

/** Filesystem seam, so the overwrite guard is testable without touching disk. */
export interface EnvFileIo {
  exists(path: string): boolean;
  write(path: string, contents: string): void;
}

export type WriteOutcome =
  | { readonly status: 'written'; readonly path: string }
  | { readonly status: 'refused'; readonly message: string };

/**
 * Write the stack environment, refusing to clobber an existing one.
 *
 * The refusal is not tidiness. Regenerating mints new KMS master keys and new
 * blind-index keys, so every ciphertext already sitting in the stack's Postgres
 * and LocalStack volumes becomes permanently unreadable — and the symptom is
 * not an error at generation time but decrypt failures later, in a stack that
 * looks freshly set up. Losing a scratch database is cheap; spending an hour
 * on why every read broke is not.
 */
export function writeStackEnv(
  options: GenerateOptions & { readonly target: string; readonly force: boolean },
  io: EnvFileIo,
): WriteOutcome {
  if (io.exists(options.target) && !options.force) {
    return {
      status: 'refused',
      message:
        `${options.target} already exists. Regenerating mints new keys, which orphans every ciphertext in the stack's volumes.\n` +
        'Pass --force if you mean it, and run `docker compose -f docker-compose.stack.yml down -v` to clear the data it could no longer decrypt.',
    };
  }
  const generated = generateEnv({ mode: options.mode });
  io.write(options.target, renderEnvFile(generated, { mode: options.mode }));
  return { status: 'written', path: options.target };
}

/** Render the generated environment as a dotenv file. */
export function renderEnvFile(
  generated: { sections: readonly Section[] },
  options: GenerateOptions,
): string {
  const lines: string[] = [
    '# GENERATED by `pnpm stack:env` — do not commit, do not hand-edit.',
    '#',
    '# Every credential here is freshly random and local-only. The three service',
    '# credentials are derived from packages/auth-guard/src/credential-graph.ts,',
    '# so each is shared by exactly the services that graph entitles to it.',
    '#',
    `# Mode: ${options.mode}`,
    options.mode === 'production'
      ? '# Production rehearsal: settlement intake, review-approve and every vault\n# emergency-access route answer 503 on the stub notifier. That is the control\n# firing, not a failure — see the stack README.'
      : '# Development: every flow runs, against entirely real dependencies.',
    '',
  ];
  for (const section of generated.sections) {
    lines.push(`# --- ${section.title} ---`);
    if (section.note) {
      for (const noteLine of section.note.split('\n')) {
        lines.push(`# ${noteLine}`);
      }
    }
    for (const [key, value] of section.entries) {
      lines.push(`${key}=${value}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}
