import { randomBytes } from 'node:crypto';
import { SERVICE_CREDENTIAL_GRAPH } from '@estate/auth-guard';
import { parseEnvFile } from './env-file';
import {
  databaseUrl,
  kmsKeyIdFor,
  networkFor,
  SERVICES,
  tlsCaPathFor,
  type Addressing,
} from './topology';

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
  /**
   * 'compose' (default): processes run as containers on the compose network.
   * 'host': processes run on the host against the published infra ports —
   * CI's fast gate and the local inner loop. Same secrets, same invariants;
   * only the addresses differ.
   */
  readonly addressing?: Addressing;
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
    // An edge with NO holders gets NO secret. The graph records such an edge
    // (documents' legal hold) as deliberately unprovisioned — nothing in the
    // repo can call the route — and minting an inbound value anyway would be
    // the aspirational grant the graph module exists to forbid. The callee's
    // guard fails closed on the empty slot, which is the documented state.
    if (edge.holders.length === 0) {
      continue;
    }
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
  const addressing = options.addressing ?? 'compose';
  const network = networkFor(addressing, options.mode);
  const credentials = assignCredentials(mintSecret);
  const sections: Section[] = [];

  sections.push({
    title: 'Shared infrastructure',
    note:
      addressing === 'host'
        ? 'HOST addressing: processes on the host reach infra via published ports.'
        : 'In-network addresses. The 5433-5438 host ports exist only for host tooling.',
    entries: [
      ['STACK_MODE', options.mode],
      ['STACK_ADDRESSING', addressing],
      ['KAFKA_BROKERS', network.kafkaBrokers],
      ['AWS_REGION', network.region],
      ['AWS_ENDPOINT_URL', network.awsEndpoint],
      ['AWS_ACCESS_KEY_ID', DUMMY_AWS_ACCESS_KEY_ID],
      ['AWS_SECRET_ACCESS_KEY', DUMMY_AWS_SECRET_ACCESS_KEY],
      ['OBJECT_STORE_BUCKET', network.objectStoreBucket],
      // Production reaches AWS over TLS, so the services must TRUST the
      // proxy's generated CA. Node verifies against it; nothing anywhere sets
      // NODE_TLS_REJECT_UNAUTHORIZED, which would be the guard weakened by
      // another name. Empty in development, where the endpoint is plain http.
      ['NODE_EXTRA_CA_CERTS', production ? tlsCaPathFor(addressing) : ''],
    ],
  });

  for (const service of SERVICES) {
    const entries: Array<readonly [string, string]> = [];
    const upper = service.name.toUpperCase();
    entries.push([`${upper}_DATABASE_URL`, databaseUrl(service.cluster, addressing)]);

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
      ['DOCUMENTS_CLAMD_HOST', network.clamdHost],
      ['DOCUMENTS_OCR_MODE', 'tesseract'],
      ['DOCUMENTS_OCR_URL', network.ocrUrl],
      // The M9 carrier path is real in BOTH modes: vault and settlement speak
      // HTTP to the notifications service, which speaks SES v1 to LocalStack —
      // the same API real AWS serves, and the e2e reads the message back
      // through LocalStack's /_aws/ses endpoint. This is what retired the
      // production rehearsal's 503 notifications_unavailable answers.
      ['VAULT_NOTIFY_MODE', 'http'],
      ['SETTLEMENT_NOTIFY_MODE', 'http'],
      ['NOTIFICATIONS_EMAIL_MODE', 'ses'],
      ['SES_FROM_ADDRESS', 'no-reply@stack.estate.local'],
      ['PLAID_MODE', production ? 'live' : 'stub'],
      // Which compose profile the plaid CONTAINER belongs to. In production it
      // is a name nothing activates: PLAID_MODE=live needs credentials that do
      // not exist, so the container would fail fast at boot and crash-loop.
      // `plannedServices` skips it for the host-mode supervisor for the same
      // reason; this keeps compose and the supervisor agreeing.
      ['PLAID_PROFILE', production ? 'plaid-requires-live-credentials' : 'plaid'],
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

/**
 * The keys whose values are decided by ADDRESSING rather than by secrets.
 *
 * Computed, not listed: generate the same environment twice with constant key
 * generators and see which values move. A hand-written list would go stale the
 * first time a service gained a URL, and the failure would be silent in the
 * direction that matters (a secret quietly re-minted).
 */
export function addressingDependentKeys(mode: GenerateOptions['mode']): ReadonlySet<string> {
  const constant = (): string => 'constant';
  const render = (addressing: Addressing): Map<string, string> =>
    new Map(generateEnv({ mode, addressing }, constant, constant).entries);
  const compose = render('compose');
  const host = render('host');
  const moved = new Set<string>();
  for (const [key, value] of compose) {
    if (host.get(key) !== value) {
      moved.add(key);
    }
  }
  return moved;
}

export type DeriveOutcome =
  | { readonly status: 'derived'; readonly generated: { sections: readonly Section[] } }
  | { readonly status: 'refused'; readonly message: string };

/**
 * Re-address an EXISTING environment without touching its secrets.
 *
 * Two addressings of one stack are two views of the SAME data: the same
 * Postgres volumes, the same LocalStack keys, the same S3 objects. Generating
 * the second view from scratch mints a new KMS master key and new blind-index
 * and search-index keys, so a search index written by the composed stack is
 * unreadable to the host-mode processes reading the very same rows — no error,
 * just wrong answers. `writeStackEnv`'s overwrite refusal exists for exactly
 * this hazard; deriving is how you get a second view without it.
 *
 * Everything that is not addressing-dependent is copied verbatim, and a source
 * missing any expected key is refused rather than silently filled in.
 */
export function deriveEnv(
  source: ReadonlyMap<string, string>,
  options: GenerateOptions,
): DeriveOutcome {
  const sourceMode = source.get('STACK_MODE');
  if (sourceMode !== options.mode) {
    return {
      status: 'refused',
      message: `source environment is mode '${String(sourceMode)}', not '${options.mode}'. The two profiles differ in more than addressing (adapter selection, TLS, notifier gates) — generate the other mode instead of re-addressing this one.`,
    };
  }

  const dependent = addressingDependentKeys(options.mode);
  const fresh = generateEnv(options);
  const missing: string[] = [];
  const sections = fresh.sections.map((section) => ({
    ...section,
    entries: section.entries.map(([key, value]): readonly [string, string] => {
      if (dependent.has(key)) {
        return [key, value];
      }
      const carried = source.get(key);
      if (carried === undefined) {
        missing.push(key);
        return [key, value];
      }
      return [key, carried];
    }),
  }));

  if (missing.length > 0) {
    return {
      status: 'refused',
      message: `source environment is missing ${missing.length} key(s) this stack needs: ${missing.join(', ')}. Deriving would mint fresh values for them, which is the orphaned-ciphertext hazard the overwrite guard exists to prevent.`,
    };
  }
  return { status: 'derived', generated: { sections } };
}

/** Filesystem seam, so the overwrite guard is testable without touching disk. */
export interface EnvFileIo {
  exists(path: string): boolean;
  read(path: string): string;
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
  options: GenerateOptions & {
    readonly target: string;
    readonly force: boolean;
    /**
     * Re-address this existing environment rather than minting a new one. Its
     * secrets are carried over verbatim — see `deriveEnv`.
     */
    readonly from?: string;
  },
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
  const generateOptions: GenerateOptions = {
    mode: options.mode,
    ...(options.addressing ? { addressing: options.addressing } : {}),
  };

  if (options.from !== undefined) {
    if (!io.exists(options.from)) {
      return { status: 'refused', message: `${options.from} not found — nothing to re-address.` };
    }
    const derived = deriveEnv(parseEnvFile(io.read(options.from)), generateOptions);
    if (derived.status === 'refused') {
      return derived;
    }
    io.write(options.target, renderEnvFile(derived.generated, { mode: options.mode }));
    return { status: 'written', path: options.target };
  }

  io.write(options.target, renderEnvFile(generateEnv(generateOptions), { mode: options.mode }));
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
    '# Every credential here is freshly random and local-only. The service',
    '# credentials are derived from packages/auth-guard/src/credential-graph.ts,',
    '# so each is shared by exactly the services that graph entitles to it.',
    '#',
    `# Mode: ${options.mode}`,
    options.mode === 'production'
      ? '# Production rehearsal: full fail-fast config over TLS, with the REAL\n# carrier path (M9): notifications speaks SES v1 to LocalStack, so the old\n# 503 notifications_unavailable answers are retired. Plaid alone stays\n# absent (no live credentials exist).'
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
