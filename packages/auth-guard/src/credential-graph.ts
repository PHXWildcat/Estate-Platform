/**
 * THE SERVICE-TO-SERVICE CREDENTIAL GRAPH, DECLARED.
 *
 * `ServiceCredentialGuard` lets a service say "the caller presented the secret
 * I expect". It cannot say anything about WHICH services should hold that
 * secret — and that question is the whole security property. The M7 security
 * review found the answer had quietly become "all four of them": settlement
 * used one config field as both its inbound-expected and its
 * outbound-presented credential, which transitively forced identity,
 * settlement, vault and documents onto a single shared string, so whoever held
 * the Zone A service's copy could drive identity's irreversible account-lock
 * API and reach docs/03 §5.1's Critical outcome with no case, no operator and
 * no waiting period.
 *
 * Nothing caught it because the trust graph existed only as prose, and the
 * prose was wrong — the guard's own docstring said "two services" while it was
 * four. This module is that graph as DATA, so it can be checked instead of
 * believed. The precedent is `packages/authz/policies/*.cedar`: one shared
 * in-repo declaration covering every service, reviewed as code.
 *
 * THE RULE — one secret per CALLEE, per direction:
 *   1. Every credential is named for the service whose routes it OPENS, never
 *      for the caller that presents it. `IDENTITY_INTERNAL_TOKEN` is "the key
 *      to identity", held by whoever must call identity.
 *   2. A service NEVER reuses its own inbound credential as an outbound one.
 *      That single aliasing is what collapsed the graph in M7.
 *   3. `holders` is exhaustive and minimal. Holding a credential is a granted
 *      capability, so adding a name here is a security decision.
 *
 * WHAT ENFORCES WHAT. `packages/auth-guard/test/credential-graph.spec.ts`
 * scans source and fails the build when the code disagrees with this table:
 * it derives the service list from the filesystem, checks the naming rule,
 * pins where each credential may be MENTIONED at all, anchors on
 * `provide: SERVICE_CREDENTIAL` rather than on variable names, forbids a
 * service presenting its own inbound credential outbound, and requires every
 * `ServiceCredentialGuard`-protected route to appear in `opens` below. The
 * complementary runtime half lives in each service's own
 * `test/config.spec.ts`, which loads that service's real config with every
 * credential in the environment and asserts it picks up EXACTLY the ones this
 * table grants it — the check that proves vault would not use identity's key
 * even when handed it. (It lives there, not in a shared suite, because every
 * service depends on this package: a suite here that imported services would
 * put a cycle in the workspace graph.)
 *
 * WHAT IS NOT ENFORCED — recorded rather than implied:
 *   · WHO A CREDENTIAL IS PRESENTED TO. The fence constrains which secret a
 *     service holds, not the URL it sends it to. Pointing vault's settlement
 *     client at identity's base URL would still send vault's credential to
 *     identity — rejected there (wrong value), so the callee's guard is the
 *     control, not this table.
 *   · CROSS-SERVICE PROVISIONING. Settlement refuses to boot when its own two
 *     credentials are equal, but nothing verifies that vault's
 *     `SETTLEMENT_INTERNAL_TOKEN` really is settlement's inbound value. An
 *     operator pasting identity's secret into vault's slot re-creates the M7
 *     collapse at deploy time with every service booting cleanly. Closing that
 *     needs the secrets store, or the mesh below.
 *   · `grants` is prose for reviewers. `opens` is enforced; `grants` is not.
 *
 * These are static shared secrets: a bearer of the value IS the service as far
 * as the callee can tell. They are interim scaffolding until the mesh
 * (mTLS/SPIFFE, docs/01 §3) supplies verifiable peer identity, at which point
 * this graph becomes an authorization policy over real identities rather than
 * a secrets-distribution plan. Until then the blast radius of each secret IS
 * its `holders` list, which is why it is written down and checked.
 */

/**
 * Every deployable service. Not free-form: the fence asserts this equals the
 * directories under `apps/services/` that have a `src/config.ts`, so a ninth
 * service cannot appear without being considered here.
 */
export const SERVICE_NAMES = [
  'assets',
  'audit',
  'documents',
  'identity',
  'notifications',
  'plaid',
  'profile',
  'settlement',
  'vault',
] as const;

export type ServiceName = (typeof SERVICE_NAMES)[number];

/** One credential: what it opens, and exactly who may hold it. */
export interface ServiceCredentialEdge {
  /**
   * The environment variable carrying it. Always `<CALLEE>_INTERNAL_TOKEN` —
   * the naming IS the control, so the fence derives the expected name from
   * `callee` rather than trusting this string.
   */
  readonly envVar: string;
  /** The service that EXPECTS this value on its own internal routes. */
  readonly callee: ServiceName;
  /**
   * Services that legitimately present it. Exhaustive and minimal; never
   * includes `callee` (a service does not authenticate to itself). An empty
   * list is meaningful and safe: nobody in-repo can call those routes.
   */
  readonly holders: readonly ServiceName[];
  /**
   * The exact internal surface it unlocks. ENFORCED: the fence extracts the
   * routes of every `ServiceCredentialGuard`-protected controller and requires
   * this list to match them exactly, so a new internal route cannot be added
   * without restating what the credential now opens.
   */
  readonly opens: readonly string[];
  /**
   * What a holder can DO — the blast radius, in plain language. Reviewed, not
   * enforced. If this sentence is alarming, `holders` deserves a second look.
   */
  readonly grants: string;
}

export const SERVICE_CREDENTIAL_GRAPH: readonly ServiceCredentialEdge[] = [
  {
    envVar: 'IDENTITY_INTERNAL_TOKEN',
    callee: 'identity',
    // Settlement alone. This is the only lock-capable credential in the
    // product, and the one the M7 review found leaking to vault and documents.
    holders: ['settlement'],
    opens: [
      'PUT /internal/v1/settlement-lock/:userId',
      'GET /internal/v1/settlement-lock/:userId/liveness',
    ],
    grants:
      "Move a user's account between active, deceased_pending and settlement, and revoke every one of their sessions. Reaching 'settlement' is irreversible through this API and locks the owner out of their own account, so a holder can accomplish docs/03 §5.1's Critical outcome directly — bypassing the case, the operator review, the waiting period and the owner-void window that exist to prevent exactly that.",
  },
  {
    envVar: 'SETTLEMENT_INTERNAL_TOKEN',
    callee: 'settlement',
    // Vault only. It asks the docs/03 §6a question at emergency-access request
    // AND release. It must be a service credential rather than the grantee's
    // bearer, because the question is about the OWNER's estate and a grantee's
    // token must not be able to mint the answer. Documents is named as a
    // holder by several prose docs; it is not one, and never was — documents
    // reaches settlement by forwarding the operator's own bearer.
    holders: ['vault'],
    opens: ['GET /v1/settlement/authority/vault-release'],
    grants:
      "Read whether an owner's estate is in settlement and whether the vault access stage is approved. Read-only and narrow: it writes nothing, exposes no case contents, and cannot move a case forward. A holder learns one boolean about one user.",
  },
  {
    envVar: 'DOCUMENTS_INTERNAL_TOKEN',
    callee: 'documents',
    // DELIBERATELY EMPTY. The route is guarded and ready, but no in-repo client
    // calls it: settlement declares no documents credential and has no
    // documents port. docs/04, CLAUDE.md and the settlement README described
    // legal hold as having "gained its writer"; it gained a writer ROUTE. The
    // M4 gap is not closed — nothing in the repo can set or clear a hold, and
    // because this variable is not production-required, a default deploy has
    // documents refusing every legal-hold call. Recorded as [] rather than
    // aspirationally as ['settlement'] because an unenforced grant in this
    // table is exactly the prose-vs-reality gap the module exists to close.
    // Add 'settlement' in the same change that adds the client, never before.
    holders: [],
    opens: ['PUT /internal/v1/legal-hold'],
    grants:
      "Set or clear the legal hold on an owner's documents, which blocks deletion. It grants no read access to content and decrypts nothing; misuse means denying a legitimate deletion, or silently lifting a hold that litigation requires.",
  },
  {
    envVar: 'NOTIFICATIONS_INTERNAL_TOKEN',
    callee: 'notifications',
    // Three holders, one domain. Vault and settlement send (their M6/M7
    // waiting-period notifications); identity feeds the recipient store at
    // registration and login — the two moments the user themselves supplies
    // the plaintext address, which is why no service anywhere needs an
    // email-ciphertext read path. Every route this opens is
    // notification-domain: no lock power, no data reads, no case movement.
    holders: ['identity', 'settlement', 'vault'],
    opens: ['POST /internal/v1/notifications/send', 'PUT /internal/v1/notifications/recipients'],
    grants:
      "Make the platform send a content-free template email to a user, and register/refresh the address it goes to. Misuse means notification spam (desensitization — the M6 review attacked and held this) or pointing a user's notifications at an attacker address, which the versions history and the notification.recipient.updated audit trail record; it exposes no stored address and no estate data.",
  },
];

/** The mandated variable name for a service's own inbound credential. */
export function expectedEnvVarFor(service: ServiceName): string {
  return `${service.toUpperCase()}_INTERNAL_TOKEN`;
}

/** The credential a service EXPECTS on its own routes, if it has any. */
export function inboundCredentialFor(service: ServiceName): ServiceCredentialEdge | undefined {
  return SERVICE_CREDENTIAL_GRAPH.find((edge) => edge.callee === service);
}

/** Every credential a service may hold and present to a peer. */
export function outboundCredentialsFor(service: ServiceName): readonly ServiceCredentialEdge[] {
  return SERVICE_CREDENTIAL_GRAPH.filter((edge) => edge.holders.includes(service));
}

/**
 * Every credential env var a service may legitimately have configured — its own
 * inbound one plus each outbound one. Services assert their real config holds
 * exactly this set: no more (the M7 collapse) and no fewer (a silently unwired
 * gate). Sorted so it compares cleanly with `credentialsHeldIn`.
 */
export function credentialEnvVarsFor(service: ServiceName): string[] {
  const inbound = inboundCredentialFor(service);
  return [
    ...(inbound ? [inbound.envVar] : []),
    ...outboundCredentialsFor(service).map((edge) => edge.envVar),
  ].sort();
}

/**
 * A recognisable stand-in value for one credential, used to trace which
 * secrets a service actually absorbs from its environment.
 *
 * Self-identifying, so the value found inside a loaded config reveals which
 * variable produced it — that is what lets one assertion cover both "holds the
 * right credentials" and "named them correctly". Comfortably over the 32-char
 * production minimum so the same fixture works in either NODE_ENV, and
 * obviously not a secret so it can never be mistaken for one in a log.
 */
export function credentialSentinel(envVar: string): string {
  return `credential-graph-sentinel::${envVar}::not-a-real-secret`;
}

/** Every credential in the graph, set to its own sentinel. Spread into a test env. */
export function credentialSentinelEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const edge of SERVICE_CREDENTIAL_GRAPH) {
    env[edge.envVar] = credentialSentinel(edge.envVar);
  }
  return env;
}

/**
 * Which graph credentials a loaded config object actually holds.
 *
 * Deep — a credential folded into a nested port config (the shape this repo
 * already uses for `kms`, `objectStore`, `scanner`) must not escape notice, and
 * Buffer-valued fields are searched too. The comparison is substring rather
 * than equality so a credential embedded in a composed string is still caught;
 * the fence asserts no sentinel contains another, which keeps that sound.
 */
export function credentialsHeldIn(config: unknown): string[] {
  const found = new Set<string>();
  const sentinels = SERVICE_CREDENTIAL_GRAPH.map((edge) => ({
    envVar: edge.envVar,
    value: credentialSentinel(edge.envVar),
  }));
  const seen = new Set<object>();

  const scanText = (text: string): void => {
    for (const { envVar, value } of sentinels) {
      if (text.includes(value)) {
        found.add(envVar);
      }
    }
  };

  const visit = (value: unknown): void => {
    if (typeof value === 'string') {
      scanText(value);
      return;
    }
    if (value === null || typeof value !== 'object') {
      return;
    }
    if (seen.has(value)) {
      return;
    }
    seen.add(value);
    if (Buffer.isBuffer(value)) {
      scanText(value.toString('utf8'));
      return;
    }
    for (const nested of Object.values(value as Record<string, unknown>)) {
      visit(nested);
    }
  };

  visit(config);
  return [...found].sort();
}
