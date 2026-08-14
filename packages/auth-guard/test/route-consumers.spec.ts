/**
 * THE ROUTE↔CONSUMER FENCE (M19 PR1).
 *
 * Zero-callers is this repo's most-repeated defect class: M4's legal hold
 * shipped with a writer and no caller (closed M9 PR2); M6 wrote
 * `wrapped_private_key` and no route ever served it back, so emergency access
 * could not complete (found M15 PR3); M7 PR2's executor estate read shipped
 * with zero callers AND zero tests and never executed once (found scoping
 * M19); M17 shipped six account-recovery/address-change routes no product
 * code calls. Each time, the gap survived because the route↔consumer
 * relationship existed only as an assumption. This fence makes it DATA, the
 * credential-graph precedent: every non-internal route either names a
 * verified product consumer or carries a reviewed exemption saying WHY it
 * may stand unconsumed — and a new route is a red suite until its author
 * writes one or the other.
 *
 * SCOPE AND LIMITS, stated rather than implied:
 *  - Routes behind a credential-graph guard class (ServiceCredentialGuard
 *    and the per-capability notification guards) are EXCLUDED: the
 *    credential graph's `opens` rule already fences those against their
 *    declared holders, and holding them here would be a second copy.
 *  - Classification reads CLASS-LEVEL `@UseGuards` only, matching how every
 *    internal controller in the repo is written. A handler-level credential
 *    guard would surface here as a route DEMANDING a consumer entry — the
 *    failure direction that asks a human, never the one that hides a route.
 *  - Matching is PATH-based: two methods sharing one path are covered by one
 *    literal (a client that GETs `/v1/vault/keyset` "covers" the PUT too).
 *    The imprecision is accepted for v1 and recorded here; the alternative
 *    is parsing each client's transport options, which is a different fence.
 *  - "Consumer" means a product code path (BFF client, peer-service client,
 *    the vault edge, the extension). Tests and e2e suites are deliberately
 *    NOT consumers — a route only tests can reach is exactly what this
 *    fence exists to surface.
 *
 * Source scanning uses readFileSync only (no workspace package edge — the
 * vault-crypto fence precedent), with the walk/strip helpers duplicated from
 * credential-graph.spec.ts because a spec cannot import another spec.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { SERVICE_CREDENTIAL_GRAPH } from '../src/credential-graph';

const REPO_ROOT = join(__dirname, '..', '..', '..');
const SERVICES_DIR = join(REPO_ROOT, 'apps', 'services');

// ---------------------------------------------------------------------------
// Derivation: every controller route in apps/services/*, classified by the
// class-level guards its controller carries.
// ---------------------------------------------------------------------------

function walk(dir: string): string[] {
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      return entry === 'dist' || entry === 'node_modules' ? [] : walk(full);
    }
    return full.endsWith('.ts') ? [full] : [];
  });
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

function read(file: string): string {
  return stripComments(readFileSync(file, 'utf8'));
}

/** Guard classes the credential graph owns; their routes are its fence. */
const INTERNAL_GUARD_CLASSES = new Set(
  SERVICE_CREDENTIAL_GRAPH.map((edge) => edge.guard.className),
);

interface DerivedRoute {
  service: string;
  method: string;
  path: string;
  internal: boolean;
}

function serviceNames(): string[] {
  return readdirSync(SERVICES_DIR)
    .filter((entry) => existsSync(join(SERVICES_DIR, entry, 'src', 'config.ts')))
    .sort();
}

function deriveRoutes(): DerivedRoute[] {
  const routes: DerivedRoute[] = [];
  for (const service of serviceNames()) {
    for (const file of walk(join(SERVICES_DIR, service, 'src'))) {
      const source = read(file);
      const chunks = source.split(/(?=@Controller\()/).slice(1);
      for (const chunk of chunks) {
        const classIdx = chunk.indexOf('export class');
        const header = classIdx >= 0 ? chunk.slice(0, classIdx) : chunk;
        const guards = [...header.matchAll(/@UseGuards\(([^)]*)\)/g)]
          .flatMap((m) => (m[1] as string).split(','))
          .map((g) => g.trim())
          .filter(Boolean);
        const internal = guards.some((g) => INTERNAL_GUARD_CLASSES.has(g));
        const prefix = /@Controller\(\s*'([^']*)'/.exec(chunk)?.[1] ?? '';
        for (const m of chunk.matchAll(/@(Get|Put|Post|Patch|Delete)\(\s*(?:'([^']*)')?\s*\)/g)) {
          const segment = m[2] ? `${prefix}/${m[2]}` : prefix;
          routes.push({
            service,
            method: (m[1] as string).toUpperCase(),
            path: `/${segment}`,
            internal,
          });
        }
      }
    }
  }
  return routes;
}

const DERIVED = deriveRoutes();
const routeKey = (r: DerivedRoute): string => `${r.service} ${r.method} ${r.path}`;

// ---------------------------------------------------------------------------
// Consumer-side extraction: URL path templates out of a consumer file, with
// `${…}` interpolations collapsed to `:p` so `/v1/assets/${id}/events`
// becomes the wildcard template `/v1/assets/:p/events`.
// ---------------------------------------------------------------------------

function extractTemplates(file: string): string[] {
  const absolute = join(REPO_ROOT, file);
  if (!existsSync(absolute)) {
    return [];
  }
  // Collapse interpolations FIRST: an `${encodeURIComponent(\n …\n)}` spans
  // lines, and extracting before collapsing would truncate the template at
  // the newline (measured against documents-client.ts).
  const collapsed = read(absolute).replace(/\$\{[^}]*\}/g, ':p');
  const templates = new Set<string>();
  for (const m of collapsed.matchAll(/\/(?:v1|internal|api)\/[A-Za-z0-9_/.:-]*/g)) {
    templates.add(m[0]);
  }
  return [...templates];
}

/** Segment-wise match where `:name` / `:p` on either side is a wildcard. */
function templateMatchesPath(template: string, path: string): boolean {
  const t = template.split('/');
  const p = path.split('/');
  if (t.length !== p.length) {
    return false;
  }
  return t.every((seg, i) => {
    const other = p[i] as string;
    return seg === other || seg.startsWith(':') || other.startsWith(':');
  });
}

/**
 * The vault origin's edge is a consumer whose literals are `/api/…` paths;
 * server.ts maps them to service paths (M15's allowlist + the vault tree
 * rewrite). Templates are additionally tried under these rewrites, and a
 * dedicated test below asserts each pair really exists in server.ts source —
 * so a rewritten match is never a free-text claim.
 */
const EDGE_REWRITES: ReadonlyArray<{ from: string; to: string }> = [
  { from: '/api/vault/', to: '/v1/vault/' },
  { from: '/api/auth/', to: '/v1/auth/' },
  { from: '/api/grantee-candidates', to: '/v1/contacts/grantee-candidates' },
];

function fileMatchesPath(file: string, path: string): boolean {
  const templates = extractTemplates(file);
  for (const template of templates) {
    if (templateMatchesPath(template, path)) {
      return true;
    }
    for (const rewrite of EDGE_REWRITES) {
      if (template.startsWith(rewrite.from)) {
        const rewritten = rewrite.to + template.slice(rewrite.from.length);
        if (templateMatchesPath(rewritten, path)) {
          return true;
        }
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// THE REGISTRY. Key: `<service> <METHOD> <path>` exactly as derived. Value:
// verified consumer files, or an exemption whose reason is the review.
// ---------------------------------------------------------------------------

type RouteDecl = { readonly consumers: readonly string[] } | { readonly exempt: string };

const consumed = (...files: string[]): RouteDecl => ({ consumers: files });

/**
 * Exemption reasons are GROUPED constants: each names the decision that
 * leaves the routes unconsumed, so flipping one exemption to a consumer is a
 * one-line diff the PR that lands the consumer carries (the M9 PR2
 * holders-flip pattern).
 */
const EXEMPT_M19_PR3 =
  'M19 PR3 lands the step-up beneficiary-designation ceremony as the BFF/web consumer; ' +
  'designation routes have been step-up-gated since M3 and are int-test-proven only until then.';
const EXEMPT_EXECUTOR_SURFACE =
  'Executor reads resolve through settlement staged grants (M7 PR2, docs/03 §5.1 control 5); ' +
  'the executor-facing product surface is its own milestone. First-ever route tests landed in ' +
  'M19 PR1 for assets; profile’s executor contact reads are covered by its int suites.';
const EXEMPT_SETTLEMENT_REPORTING =
  'Reporter/owner-facing settlement surface (report a death, follow a case, attach evidence, ' +
  'void, waiting-period settings) has no UI milestone yet; the settlement e2e drives the flows ' +
  'end to end against real services (docs/03 §5.1).';
const EXEMPT_TB7_OPERATOR =
  'Operator-facing: the TB7 operator platform is deliberately deferred (docs/03 §6b — operators ' +
  'are CLI-managed as an interim); building an operator UI before TB7’s controls exist would be ' +
  'the wrong order, and the settlement/documents e2e suites exercise the routes.';
const EXEMPT_PLAID_UI =
  'M3 PR2 shipped the Plaid isolate deliberately backend-only (decision log 2026-07-21); the ' +
  'account-linking UI is a later milestone and the plaid e2e drives link/sync/revoke end to end.';
const EXEMPT_EXTERNAL_WEBHOOK =
  'Called by Plaid itself, never by product code: the ES256-verified webhook ingress ' +
  '(decision log 2026-07-22 — alg pinned, kid via gateway, constant-time body hash).';
const EXEMPT_RECOVERY_SURFACE =
  'M17 shipped the password-change/reset and email-change ceremonies service-side with their ' +
  'copy decisions taken, but the account-recovery/address-change frontend slice never landed — ' +
  'found by this fence’s first run (M19 PR1); the surface is a pending frontend milestone.';

const BFF = 'apps/bff/src';
const AI = 'apps/services/ai-assistant/src/clients';
const VW = 'apps/vault-web/src';
const VX = 'apps/vault-extension/src';

const ROUTE_CONSUMERS: Readonly<Record<string, RouteDecl>> = {
  // ------------------------------------------------------------ ai-assistant
  'ai-assistant GET /v1/analysis/beneficiary-conflicts': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant GET /v1/analysis/estate-tax': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant GET /v1/analysis/funding': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant GET /v1/analysis/missing-documents': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant GET /v1/consents': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant PUT /v1/consents/:scope': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant DELETE /v1/consents/:scope': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant GET /v1/conversations': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant POST /v1/conversations': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant GET /v1/conversations/:conversationId': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant DELETE /v1/conversations/:conversationId': consumed(`${BFF}/assistant-client.ts`),
  'ai-assistant POST /v1/conversations/:conversationId/turns': consumed(
    `${BFF}/assistant-client.ts`,
  ),

  // ------------------------------------------------------------------ assets
  'assets POST /v1/assets': consumed(`${BFF}/assets-client.ts`),
  'assets GET /v1/assets': consumed(`${BFF}/assets-client.ts`, `${AI}/assets.client.ts`),
  'assets GET /v1/net-worth': consumed(`${BFF}/assets-client.ts`, `${AI}/assets.client.ts`),
  'assets GET /v1/assets/:assetId/beneficiaries': consumed(`${AI}/assets.client.ts`),
  // M19 PR2 flipped these six from EXEMPT("pending M19 PR2") to consumers in
  // the same change as the client — the M9 PR2 holders-flip pattern.
  'assets GET /v1/assets/:assetId': consumed(`${BFF}/assets-client.ts`),
  'assets GET /v1/assets/:assetId/events': consumed(`${BFF}/assets-client.ts`),
  'assets PATCH /v1/assets/:assetId': consumed(`${BFF}/assets-client.ts`),
  'assets POST /v1/assets/:assetId/valuations': consumed(`${BFF}/assets-client.ts`),
  'assets POST /v1/assets/:assetId/ownership': consumed(`${BFF}/assets-client.ts`),
  'assets POST /v1/assets/:assetId/retire': consumed(`${BFF}/assets-client.ts`),
  'assets POST /v1/assets/:assetId/beneficiaries': { exempt: EXEMPT_M19_PR3 },
  'assets DELETE /v1/assets/:assetId/beneficiaries/:contactId': { exempt: EXEMPT_M19_PR3 },
  'assets GET /v1/estates/:ownerUserId/assets': { exempt: EXEMPT_EXECUTOR_SURFACE },

  // --------------------------------------------------------------- documents
  'documents GET /v1/documents': consumed(
    `${BFF}/documents-client.ts`,
    `${AI}/documents.client.ts`,
  ),
  'documents GET /v1/documents/:documentId': consumed(`${BFF}/documents-client.ts`),
  'documents GET /v1/documents/:documentId/versions': consumed(`${BFF}/documents-client.ts`),
  'documents GET /v1/documents/:documentId/versions/:version/content': consumed(
    `${BFF}/documents-client.ts`,
  ),
  'documents POST /v1/documents/:documentId/status': consumed(`${BFF}/documents-client.ts`),
  'documents POST /v1/documents/:documentId/versions': consumed(`${BFF}/documents-client.ts`),
  'documents POST /v1/documents/generate': consumed(`${BFF}/documents-client.ts`),
  'documents POST /v1/documents/search': consumed(
    `${BFF}/documents-client.ts`,
    `${AI}/documents.client.ts`,
  ),
  'documents POST /v1/documents/upload': consumed(`${BFF}/documents-client.ts`),
  'documents DELETE /v1/documents/:documentId': consumed(`${BFF}/documents-client.ts`),
  'documents GET /v1/templates': consumed(`${BFF}/documents-client.ts`),
  'documents GET /v1/evidence/:documentId/versions/:version/content': {
    exempt: EXEMPT_TB7_OPERATOR,
  },

  // ---------------------------------------------------------------- identity
  'identity GET /v1/auth/session': consumed(
    `${BFF}/identity-client.ts`,
    'packages/auth-guard/src/verifier.ts',
    `${VW}/server.ts`,
  ),
  'identity GET /v1/auth/sessions': consumed(`${BFF}/identity-client.ts`),
  'identity DELETE /v1/auth/sessions/:sessionId': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/login': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/register': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/refresh': consumed(`${BFF}/identity-client.ts`, `${VW}/server.ts`),
  'identity POST /v1/auth/logout': consumed(`${BFF}/identity-client.ts`, `${VW}/server.ts`),
  'identity POST /v1/auth/logout/refresh': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/stepup': consumed(`${BFF}/identity-client.ts`, `${VW}/server.ts`),
  'identity POST /v1/auth/totp/enroll': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/totp/verify': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/webauthn/register/options': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/webauthn/register/verify': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/webauthn/authenticate/options': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/webauthn/authenticate/verify': consumed(`${BFF}/identity-client.ts`),
  'identity GET /v1/auth/webauthn/credentials': consumed(`${BFF}/identity-client.ts`),
  'identity PATCH /v1/auth/webauthn/credentials/:id': consumed(`${BFF}/identity-client.ts`),
  'identity DELETE /v1/auth/webauthn/credentials/:id': consumed(`${BFF}/identity-client.ts`),
  'identity GET /v1/auth/email/verification': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/email/verification/resend': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/email/verification/verify': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/export-demo': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/handoff': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/handoff/redeem': consumed(`${VW}/upstream.ts`),
  'identity POST /v1/auth/extension/pairing': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/extension/pairing/redeem': consumed(
    `${VW}/server.ts`,
    `${VX}/session.ts`,
  ),
  'identity POST /v1/auth/password': { exempt: EXEMPT_RECOVERY_SURFACE },
  'identity POST /v1/auth/password/reset': { exempt: EXEMPT_RECOVERY_SURFACE },
  'identity POST /v1/auth/password/reset/request': { exempt: EXEMPT_RECOVERY_SURFACE },
  'identity POST /v1/auth/email/change': { exempt: EXEMPT_RECOVERY_SURFACE },
  'identity POST /v1/auth/email/change/request': { exempt: EXEMPT_RECOVERY_SURFACE },
  'identity DELETE /v1/auth/email/change': { exempt: EXEMPT_RECOVERY_SURFACE },

  // ------------------------------------------------------------------- plaid
  'plaid POST /v1/plaid/link-token': { exempt: EXEMPT_PLAID_UI },
  'plaid POST /v1/plaid/items': { exempt: EXEMPT_PLAID_UI },
  'plaid GET /v1/plaid/items': { exempt: EXEMPT_PLAID_UI },
  'plaid POST /v1/plaid/items/:id/sync': { exempt: EXEMPT_PLAID_UI },
  'plaid DELETE /v1/plaid/items/:id': { exempt: EXEMPT_PLAID_UI },
  'plaid GET /v1/accounts': { exempt: EXEMPT_PLAID_UI },
  'plaid POST /v1/plaid/webhook': { exempt: EXEMPT_EXTERNAL_WEBHOOK },

  // ----------------------------------------------------------------- profile
  'profile GET /v1/profile': consumed(`${BFF}/profile-client.ts`, `${AI}/profile.client.ts`),
  'profile PUT /v1/profile': consumed(`${BFF}/profile-client.ts`),
  'profile GET /v1/profile/family': consumed(`${BFF}/profile-client.ts`, `${AI}/profile.client.ts`),
  'profile POST /v1/profile/family': consumed(`${BFF}/profile-client.ts`),
  'profile PUT /v1/profile/family/:id': consumed(`${BFF}/profile-client.ts`),
  'profile DELETE /v1/profile/family/:id': consumed(`${BFF}/profile-client.ts`),
  'profile GET /v1/contacts': consumed(`${BFF}/profile-client.ts`),
  'profile POST /v1/contacts': consumed(`${BFF}/profile-client.ts`),
  'profile GET /v1/contacts/:id': consumed(`${BFF}/profile-client.ts`),
  'profile PUT /v1/contacts/:id': consumed(`${BFF}/profile-client.ts`),
  'profile DELETE /v1/contacts/:id': consumed(`${BFF}/profile-client.ts`),
  'profile POST /v1/contacts/:id/link-invitation': consumed(`${BFF}/profile-client.ts`),
  'profile DELETE /v1/contacts/:id/link-invitation': consumed(`${BFF}/profile-client.ts`),
  'profile DELETE /v1/contacts/:id/link': consumed(`${BFF}/profile-client.ts`),
  'profile POST /v1/contact-links/redeem': consumed(`${BFF}/profile-client.ts`),
  'profile GET /v1/contacts/grantee-candidates': consumed(`${VW}/server.ts`),
  'profile GET /v1/role-assignments': consumed(`${BFF}/profile-client.ts`),
  'profile POST /v1/role-assignments': consumed(`${BFF}/profile-client.ts`),
  'profile DELETE /v1/role-assignments/:id': consumed(`${BFF}/profile-client.ts`),
  'profile GET /v1/role-assignments/:id/permissions': consumed(`${BFF}/profile-client.ts`),
  'profile POST /v1/role-assignments/:id/permissions': consumed(`${BFF}/profile-client.ts`),
  'profile DELETE /v1/role-assignments/:id/permissions/:grantId': consumed(
    `${BFF}/profile-client.ts`,
  ),
  'profile GET /v1/profiles/:ownerUserId/contacts': { exempt: EXEMPT_EXECUTOR_SURFACE },
  'profile GET /v1/profiles/:ownerUserId/contacts/:contactId': {
    exempt: EXEMPT_EXECUTOR_SURFACE,
  },

  // -------------------------------------------------------------- settlement
  'settlement GET /v1/settlement/authority/stage-access': consumed(
    'packages/settlement-client/src/client.ts',
  ),
  'settlement GET /v1/settlement/authority/evidence-read': consumed(
    'packages/settlement-client/src/client.ts',
  ),
  'settlement GET /v1/settlement/reportable-estates': { exempt: EXEMPT_SETTLEMENT_REPORTING },
  'settlement POST /v1/settlement/cases': { exempt: EXEMPT_SETTLEMENT_REPORTING },
  'settlement GET /v1/settlement/cases': { exempt: EXEMPT_SETTLEMENT_REPORTING },
  'settlement GET /v1/settlement/cases/:caseId': { exempt: EXEMPT_SETTLEMENT_REPORTING },
  'settlement POST /v1/settlement/cases/:caseId/evidence': {
    exempt: EXEMPT_SETTLEMENT_REPORTING,
  },
  'settlement POST /v1/settlement/cases/:caseId/void': { exempt: EXEMPT_SETTLEMENT_REPORTING },
  'settlement GET /v1/settlement/settings': { exempt: EXEMPT_SETTLEMENT_REPORTING },
  'settlement PUT /v1/settlement/settings': { exempt: EXEMPT_SETTLEMENT_REPORTING },
  'settlement POST /v1/settlement/cases/report-provider': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement GET /v1/settlement/queue': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/cases/:caseId/review/start': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/cases/:caseId/review': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/cases/:caseId/verify': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/cases/:caseId/close': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement GET /v1/settlement/cases/:caseId/timeline': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement GET /v1/settlement/cases/:caseId/tasks': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/tasks/:taskId/completion': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement GET /v1/settlement/cases/:caseId/stages': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/cases/:caseId/stages': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/stages/:stageId/decision': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/stages/:stageId/revoke': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement GET /v1/settlement/cases/:caseId/distributions': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/cases/:caseId/distributions': { exempt: EXEMPT_TB7_OPERATOR },
  'settlement POST /v1/settlement/distributions/:distributionId/approval': {
    exempt: EXEMPT_TB7_OPERATOR,
  },
  'settlement POST /v1/settlement/distributions/:distributionId/status': {
    exempt: EXEMPT_TB7_OPERATOR,
  },

  // ------------------------------------------------------------------- vault
  'vault GET /v1/vault/keyset': consumed(`${VW}/client/vault-session.ts`, `${VX}/popup.ts`),
  'vault POST /v1/vault/keyset': consumed(`${VW}/client/vault-session.ts`),
  'vault PUT /v1/vault/keyset': consumed(`${VW}/client/vault-session.ts`),
  'vault POST /v1/vault/srp/start': consumed(
    `${VW}/client/vault-session.ts`,
    `${VX}/vault-host.ts`,
  ),
  'vault POST /v1/vault/srp/verify': consumed(
    `${VW}/client/vault-session.ts`,
    `${VX}/vault-host.ts`,
  ),
  'vault POST /v1/vault/lock': consumed(`${VW}/client/vault-session.ts`, `${VX}/vault-host.ts`),
  'vault GET /v1/vault/items': consumed(`${VW}/client/vault-session.ts`, `${VX}/vault-host.ts`),
  'vault POST /v1/vault/items': consumed(`${VW}/client/vault-session.ts`, `${VX}/vault-host.ts`),
  'vault GET /v1/vault/items/:itemId': consumed(`${VW}/client/vault-session.ts`),
  'vault PUT /v1/vault/items/:itemId': consumed(
    `${VW}/client/vault-session.ts`,
    `${VX}/vault-host.ts`,
  ),
  'vault DELETE /v1/vault/items/:itemId': consumed(`${VW}/client/vault-session.ts`),
  'vault POST /v1/vault/reset': consumed(`${VW}/client/vault-session.ts`),
  'vault GET /v1/vault/recovery-key': consumed(`${VW}/client/emergency.ts`),
  'vault POST /v1/vault/recovery-key': consumed(`${VW}/client/emergency.ts`),
  'vault GET /v1/vault/recovery-key/:granteeUserId': consumed(`${VW}/client/emergency.ts`),
  'vault GET /v1/vault/emergency-access': consumed(`${VW}/client/emergency.ts`),
  'vault POST /v1/vault/emergency-access': consumed(`${VW}/client/emergency.ts`),
  'vault GET /v1/vault/emergency-access/granted-to-me': consumed(`${VW}/client/emergency.ts`),
  'vault DELETE /v1/vault/emergency-access/:policyId': consumed(`${VW}/client/emergency.ts`),
  'vault POST /v1/vault/emergency-access/:policyId/deny': consumed(`${VW}/client/emergency.ts`),
  'vault POST /v1/vault/emergency-access/:policyId/rearm': consumed(`${VW}/client/emergency.ts`),
  'vault POST /v1/vault/emergency-access/:policyId/request': consumed(`${VW}/client/emergency.ts`),
  'vault POST /v1/vault/emergency-access/:policyId/release': consumed(`${VW}/client/emergency.ts`),
};

// ---------------------------------------------------------------------------
// The fence.
// ---------------------------------------------------------------------------

describe('route↔consumer fence (every non-internal route is consumed or exempted)', () => {
  const nonInternal = DERIVED.filter((r) => !r.internal);
  const internal = DERIVED.filter((r) => r.internal);

  it('derives a real route surface (anti-vacuity)', () => {
    // A derivation that stops matching goes green with an empty registry —
    // the 2026-08-07 fence lesson. These floors are the current counts with
    // slack for refactors, never for absence.
    expect(DERIVED.length).toBeGreaterThanOrEqual(120);
    expect(internal.length).toBeGreaterThanOrEqual(10);
    const servicesWithRoutes = new Set(nonInternal.map((r) => r.service));
    expect(servicesWithRoutes.size).toBeGreaterThanOrEqual(8);
  });

  it('every non-internal route has exactly one registry entry', () => {
    const missing = nonInternal.map(routeKey).filter((k) => !(k in ROUTE_CONSUMERS));
    expect(missing).toEqual([]);
  });

  it('every registry entry names a route that still exists (no stale entries)', () => {
    const known = new Set(nonInternal.map(routeKey));
    const stale = Object.keys(ROUTE_CONSUMERS).filter((k) => !known.has(k));
    expect(stale).toEqual([]);
  });

  it('internal routes stay out of the registry (they are the credential graph’s)', () => {
    const internalKeys = new Set(internal.map(routeKey));
    const misfiled = Object.keys(ROUTE_CONSUMERS).filter((k) => internalKeys.has(k));
    expect(misfiled).toEqual([]);
  });

  it('every declared consumer file exists and really addresses its route', () => {
    const failures: string[] = [];
    for (const [key, decl] of Object.entries(ROUTE_CONSUMERS)) {
      if (!('consumers' in decl)) {
        continue;
      }
      const path = key.split(' ')[2] as string;
      expect(decl.consumers.length).toBeGreaterThan(0);
      for (const file of decl.consumers) {
        if (!existsSync(join(REPO_ROOT, file))) {
          failures.push(`${key}: consumer file does not exist: ${file}`);
        } else if (!fileMatchesPath(file, path)) {
          failures.push(`${key}: ${file} contains no URL template addressing ${path}`);
        }
      }
    }
    expect(failures).toEqual([]);
  });

  it('a consumer-backed floor holds (the fence is not all exemptions)', () => {
    const consumedCount = Object.values(ROUTE_CONSUMERS).filter((d) => 'consumers' in d).length;
    expect(consumedCount).toBeGreaterThanOrEqual(80);
  });

  it('every exemption reason is substantive', () => {
    for (const [key, decl] of Object.entries(ROUTE_CONSUMERS)) {
      if ('exempt' in decl) {
        expect(`${key}: ${decl.exempt}`.length).toBeGreaterThanOrEqual(80);
        expect(decl.exempt.length).toBeGreaterThanOrEqual(60);
      }
    }
  });

  it('the edge rewrites the matcher relies on exist in server.ts source', () => {
    // A rewritten match is only honest while the rewrite is real: the vault
    // tree pair, and the exact-entry targets for every /api/auth/… and the
    // grantee-candidates projection, must all appear in the edge's source.
    const server = read(join(REPO_ROOT, 'apps/vault-web/src/server.ts'));
    expect(server).toContain("'/api/vault/'");
    expect(server).toContain("'/v1/vault/'");
    expect(server).toContain("'/v1/auth/session'");
    expect(server).toContain("'/v1/auth/stepup'");
    expect(server).toContain("'/v1/auth/logout'");
    expect(server).toContain("'/v1/auth/refresh'");
    expect(server).toContain("'/v1/auth/extension/pairing/redeem'");
    expect(server).toContain("'/v1/contacts/grantee-candidates'");
  });

  it('template extraction sees a real corpus (anti-vacuity)', () => {
    const consumerFiles = new Set(
      Object.values(ROUTE_CONSUMERS).flatMap((d) => ('consumers' in d ? [...d.consumers] : [])),
    );
    const total = [...consumerFiles].reduce((acc, f) => acc + extractTemplates(f).length, 0);
    expect(total).toBeGreaterThanOrEqual(100);
  });
});
