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
 * directories under `apps/services/` that have a `src/config.ts`, so a tenth
 * service cannot appear without being considered here.
 *
 * `ai-assistant` appears in NO edge below, in either direction, and that is
 * deliberate rather than pending: it authenticates its callers on their own
 * bearer and forwards that same bearer to the peers it reads, so it needs no
 * secret and must not be handed one. Its own `test/config.spec.ts` asserts the
 * empty holding, which is what keeps this a property rather than a comment.
 */
export const SERVICE_NAMES = [
  'ai-assistant',
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
   * The environment variable carrying it. Always begins `<CALLEE>_` and ends
   * `_INTERNAL_TOKEN` — the naming IS the control, so the fence derives the
   * prefix from `callee` rather than trusting this string. A callee with more
   * than one internal SURFACE qualifies the middle (see `guard`), because two
   * capabilities on one service must not share one secret.
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
   * The guard class and DI token that enforce this edge, as SOURCE NAMES —
   * the fence greps for them.
   *
   * Most callees have exactly one internal surface and use the shared
   * `ServiceCredentialGuard` / `SERVICE_CREDENTIAL` pair. A callee whose
   * internal routes fall into capability classes with DIFFERENT legitimate
   * holders needs one credential per class, and therefore one guard per class
   * — a guard binds a single token, so the token IS the partition. The M9
   * security review found the alternative the hard way: notifications' send
   * and recipient-upsert routes shared one secret, so vault and settlement,
   * which only ever send, also held the power to repoint any user's
   * notification address.
   */
  readonly guard: {
    /** Guard class named in the controller's `@UseGuards(...)`. */
    readonly className: string;
    /** DI token the callee's app.module binds to this credential. */
    readonly token: string;
  };
  /**
   * The exact internal surface it unlocks. ENFORCED: the fence extracts the
   * routes of every controller guarded by `guard.className` and requires this
   * list to match exactly, so a new internal route cannot be added without
   * restating what the credential now opens.
   */
  readonly opens: readonly string[];
  /**
   * What a holder can DO — the blast radius, in plain language. Reviewed, not
   * enforced. If this sentence is alarming, `holders` deserves a second look.
   */
  readonly grants: string;
}

/** The shared guard/token pair, used by every single-surface callee. */
const SHARED_GUARD = {
  className: 'ServiceCredentialGuard',
  token: 'SERVICE_CREDENTIAL',
} as const;

export const SERVICE_CREDENTIAL_GRAPH: readonly ServiceCredentialEdge[] = [
  {
    envVar: 'IDENTITY_INTERNAL_TOKEN',
    callee: 'identity',
    // Settlement alone. This is the only lock-capable credential in the
    // product, and the one the M7 review found leaking to vault and documents.
    holders: ['settlement'],
    guard: SHARED_GUARD,
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
    guard: SHARED_GUARD,
    opens: ['GET /v1/settlement/authority/vault-release'],
    grants:
      "Read whether an owner's estate is in settlement and whether the vault access stage is approved. Read-only and narrow: it writes nothing, exposes no case contents, and cannot move a case forward. A holder learns one boolean about one user.",
  },
  {
    envVar: 'DOCUMENTS_INTERNAL_TOKEN',
    callee: 'documents',
    // Settlement alone (M9 PR2 — the change that closed the M4 zero-callers
    // gap). This edge sat deliberately EMPTY from M7 until the client existed:
    // recording ['settlement'] before settlement actually presented the
    // credential would have been an aspirational grant, exactly the
    // prose-vs-reality drift this module exists to forbid. The holder was
    // added in the SAME change as `documents-hold.ts` and the config that
    // absorbs the secret, and the variable became production-required on the
    // documents side in that change too.
    holders: ['settlement'],
    guard: SHARED_GUARD,
    opens: ['PUT /internal/v1/legal-hold'],
    grants:
      "Set or clear the legal hold on an owner's documents, which blocks deletion. It grants no read access to content and decrypts nothing; misuse means denying a legitimate deletion, or silently lifting a hold that litigation requires.",
  },
  {
    envVar: 'NOTIFICATIONS_INTERNAL_TOKEN',
    callee: 'notifications',
    // ESTATE SENDS ONLY. Vault and settlement send their M6/M7 waiting-period
    // notifications; profile joined in M13 to tell an owner that somebody
    // CLAIMED a link to one of their contacts (docs/03 §6g — a claim is the
    // moment that person becomes able to open a death case, so a silent claim
    // is the failure this notification exists to prevent).
    //
    // Identity is deliberately NOT here, and M14 made that a statement about
    // capability rather than about traffic. Identity now DOES make the platform
    // mail somebody — exactly one kind, its own address-verification code, on
    // its own edge below. What it must not gain is the power to fire an ESTATE
    // notification: a holder of this credential chooses which of ten
    // owner-facing alarms rings and when, and the service that mints sessions
    // has no business ringing "a death report was filed on your account".
    // SYSTEM_NOTIFICATION_KINDS is excluded from this route's schema for the
    // mirror-image reason.
    holders: ['profile', 'settlement', 'vault'],
    guard: SHARED_GUARD,
    opens: ['POST /internal/v1/notifications/send'],
    grants:
      'Make the platform send a content-free template email to the address already on file for a user. The wire has no text field and the template registry is closed, so a holder chooses WHICH of ten estate notifications fires and WHEN, never what it says and never where it goes. Misuse means notification spam (desensitization — the M6 review attacked this and the design held), not disclosure: it exposes no stored address, no estate data, no delivery state, and cannot redirect delivery. Reading whether an address is verified is a DIFFERENT edge (below) precisely so this sentence stays true of this credential.',
  },
  {
    envVar: 'NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN',
    callee: 'notifications',
    // IDENTITY ALONE, and this is the security-relevant half of the split.
    // Identity feeds the store at registration and login — the two moments
    // the user themselves supplies the plaintext address, which is why no
    // service anywhere needs an email-ciphertext read path.
    //
    // The M9 security review found these two routes sharing ONE secret, so
    // vault and settlement — which only ever send — also held the power to
    // repoint any user's notifications at an attacker's mailbox. That is
    // strictly worse than it sounds: it is CROSS-DOMAIN. Vault's copy could
    // silence settlement's §5.1 death-case alerts, and settlement's could
    // silence vault's §5.2 emergency-access alerts, in each case removing the
    // one signal the owner gets during the waiting period that exists to
    // catch exactly that attack. Splitting the edge is what makes the
    // module's own rule 3 ("holders is exhaustive and MINIMAL") true here.
    holders: ['identity'],
    guard: { className: 'RecipientsCredentialGuard', token: 'RECIPIENTS_CREDENTIAL' },
    opens: [
      'PUT /internal/v1/notifications/recipients',
      // M14. Vouching for an address is the SAME capability class as setting
      // one — both decide what the delivery store believes about how to reach a
      // user — so it belongs on this credential rather than a fifth. A holder
      // able to repoint an address gains nothing by also being able to mark it
      // verified; a holder able ONLY to mark verified would be strictly weaker,
      // and no such holder exists.
      'PUT /internal/v1/notifications/recipients/:userId/verified',
    ],
    grants:
      "Set the address a user's notifications are delivered to, and declare that the user proved they own it. A holder can silently redirect every future owner alert — including the §5.1 death-case contact sweep and the §5.2 emergency-access waiting-period alerts — to a mailbox they control, defeating the waiting period by removing the owner's only signal, and can vouch for that mailbox so M14's arming gates (escrow configure, link-code mint) stop refusing. It reads nothing: the stored address is never returned by any route, and the change is recorded (prior ciphertext retained in the versions table) though NOT attributed to a caller, so the audit trail proves that an address changed, never who changed it.",
  },
  {
    envVar: 'NOTIFICATIONS_VERIFY_INTERNAL_TOKEN',
    callee: 'notifications',
    // IDENTITY ALONE (M14). Identity mints an address-verification code, keeps
    // only its sha256, and needs the platform to mail it — but must not join
    // the SEND holders above to do so, because that credential fires estate
    // alarms and this one cannot.
    //
    // Separate from the RECIPIENTS edge despite having the identical holder,
    // and the reason is what a stolen copy buys. RECIPIENTS can REPOINT an
    // address; this can only mail a code to whatever address is already on
    // file. Folding them together would mean that the first future holder of
    // "resend my code" — a support tool, a BFF-side resend — inherits the power
    // the M9 review split out. Splitting now costs one secret and makes that
    // grant possible later without re-litigating it.
    holders: ['identity'],
    guard: { className: 'VerificationCredentialGuard', token: 'VERIFICATION_CREDENTIAL' },
    opens: ['POST /internal/v1/notifications/verification'],
    grants:
      "Mail one address-verification code, of the platform's own choosing of words, to the address already on file for a user. It is the one route whose payload carries a variable that is not a date (docs/03 §6c records the deviation), but the variable is opaque, platform-authored and single-use: a holder cannot choose the recipient, cannot see the address, cannot fire any estate notification, and cannot make the code valid. Misuse means mailing a user a code they did not ask for, which they can simply ignore — and, at volume, sender-reputation damage.",
  },
  {
    envVar: 'NOTIFICATIONS_STATUS_INTERNAL_TOKEN',
    callee: 'notifications',
    // M14. Identity reads it to decide whether to mint a code at login;
    // PR2 adds vault and profile, which read it at the two ARMING gates
    // (escrow configure, link-code mint) — and, per the M9 PR2 rule, those
    // holders are added in the SAME change as the clients that present it,
    // never before.
    //
    // Settlement holds SEND and is deliberately NOT here: its gates PROCEED on
    // an unverified recipient and record the fact, so it never asks the
    // question. That is what makes `holders` minimal rather than "everyone who
    // talks to notifications".
    holders: ['identity'],
    guard: { className: 'RecipientStatusCredentialGuard', token: 'RECIPIENT_STATUS_CREDENTIAL' },
    opens: ['GET /internal/v1/notifications/recipients/:userId/status'],
    grants:
      'Read one boolean about one named user: whether the delivery store holds an address that user has proved they own. It returns no address, no timestamp, no estate fact, and writes nothing. The residual is an oracle — a holder learns whether a given user id has completed verification — bounded by user ids being unguessable UUIDs that this route never enumerates.',
  },
];

/**
 * The mandated name shape for a credential opening `service`'s routes:
 * `<SERVICE>_…_INTERNAL_TOKEN`, with an optional capability qualifier in the
 * middle for a callee that has more than one internal surface. The prefix is
 * the control — a credential named for its CALLER is what rule 1 forbids.
 */
export function envVarPrefixFor(service: ServiceName): string {
  // A service name is a directory name and may contain a hyphen; an
  // environment-variable key may not. Normalizing here keeps the derived
  // prefix a legal identifier for a name like `ai-assistant`, which would
  // otherwise mandate the unusable `AI-ASSISTANT_…_INTERNAL_TOKEN`. A no-op
  // for every single-word service, and it does not loosen the rule: the
  // prefix is still DERIVED from the callee rather than trusted from `envVar`.
  return `${service.toUpperCase().replace(/-/g, '_')}_`;
}

/**
 * Every credential a service EXPECTS on its own routes. Usually one; a callee
 * whose internal routes split into capability classes with different holders
 * has one per class (notifications: send vs recipient-upsert).
 */
export function inboundCredentialsFor(service: ServiceName): readonly ServiceCredentialEdge[] {
  return SERVICE_CREDENTIAL_GRAPH.filter((edge) => edge.callee === service);
}

/** Every credential a service may hold and present to a peer. */
export function outboundCredentialsFor(service: ServiceName): readonly ServiceCredentialEdge[] {
  return SERVICE_CREDENTIAL_GRAPH.filter((edge) => edge.holders.includes(service));
}

/**
 * Every credential env var a service may legitimately have configured — its own
 * inbound one(s) plus each outbound one. Services assert their real config holds
 * exactly this set: no more (the M7 collapse) and no fewer (a silently unwired
 * gate). Sorted so it compares cleanly with `credentialsHeldIn`.
 */
export function credentialEnvVarsFor(service: ServiceName): string[] {
  return [
    ...inboundCredentialsFor(service).map((edge) => edge.envVar),
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
