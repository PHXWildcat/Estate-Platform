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

/**
 * EVERY Nest HTTP method decorator, not the five that happened to be in use.
 * `@All`/`@Head`/`@Options`/`@Search` were absent from the old alternation,
 * so a handler using one derived no route at all — invisible to both halves of
 * the fence.
 */
const ROUTE_VERBS = 'Get|Put|Post|Patch|Delete|All|Head|Options|Search';
const ROUTE_DECORATOR = new RegExp(`@(${ROUTE_VERBS})\\(\\s*(?:'([^']*)')?\\s*\\)`, 'g');
const ROUTE_DECORATOR_OPENER = new RegExp(`@(?:${ROUTE_VERBS})\\(`, 'g');

/** Route decorators the parser above could not read; asserted empty below. */
const unparseable: string[] = [];

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
        for (const m of chunk.matchAll(ROUTE_DECORATOR)) {
          const segment = m[2] ? `${prefix}/${m[2]}` : prefix;
          routes.push({
            service,
            method: (m[1] as string).toUpperCase(),
            path: `/${segment}`,
            internal,
          });
        }
        // A decorator this parser cannot read must be LOUD, not skipped. The
        // regex demands a bare single-quoted path, so `@Get(['a','b'])`, a
        // template literal, a constant, and the multi-line trailing-comma form
        // were all invisible in BOTH directions — no route derived, so no
        // registry entry demanded and no stale-entry pressure either, while
        // the file header promised "a new route is a red suite until its
        // author writes one or the other" (M19 PR4 review, measured: three
        // such routes could be added and DERIVED never moved).
        for (const m of chunk.matchAll(ROUTE_DECORATOR_OPENER)) {
          const at = m.index ?? 0;
          const window = chunk.slice(at, at + 200);
          if (!new RegExp(`^${ROUTE_DECORATOR.source}`).test(window)) {
            unparseable.push(`${service}: ${window.split('\n')[0]?.trim() ?? window.slice(0, 60)}`);
          }
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

/**
 * Segment-wise match. THE WILDCARD IS ONE-DIRECTIONAL, and that is the whole
 * correctness of the consumer half (M19 PR4 review).
 *
 * A consumer's `:p` stands for an INTERPOLATION — `${assetId}` — so it may
 * only line up with a route's own PARAMETER segment. Letting it match a
 * LITERAL route segment is what made the fence inert: `/v1/documents/:p`,
 * produced by any `getDocument`-shaped call, is three segments like
 * `/v1/documents/export`, so one parameterised call site in a declared
 * consumer certified every sibling route of the same arity. Measured on this
 * tree before the fix: twelve declared routes stayed GREEN with their real
 * call site deleted, including `POST /v1/documents/generate`,
 * `POST /v1/documents/upload` and `DELETE /v1/vault/emergency-access/:policyId`
 * — precisely the routes for which a zero-caller regression matters.
 *
 * The reverse (a route parameter against a consumer literal) stays allowed: a
 * consumer addressing a specific id through a constant is unusual but honest,
 * and it names the route it means.
 */
function templateMatchesPath(template: string, path: string, enumerated = false): boolean {
  const t = template.split('/');
  const p = path.split('/');
  if (t.length !== p.length) {
    return false;
  }
  return t.every((seg, i) => {
    const other = p[i] as string;
    if (seg === other) {
      return true;
    }
    // A route parameter accepts whatever the consumer wrote there.
    if (other.startsWith(':')) {
      return true;
    }
    // …and a consumer wildcard reaches a LITERAL route segment only where the
    // route DECLARED that its consumer enumerates route names there.
    return enumerated && seg.startsWith(':');
  });
}

interface EdgeRewrite {
  readonly edge: string;
  readonly from: string;
  readonly to: string;
}

/**
 * The isolated origins, each named by the source its rewrites are read out of.
 * DECLARED as data so a third one arrives with an entry or contributes nothing
 * and trips the per-edge floor below — rather than being silently absent, which
 * is the failure this list exists to stop.
 */
const EDGE_SERVERS: ReadonlyArray<{ edge: string; source: string }> = [
  { edge: 'vault-web', source: 'apps/vault-web/src/server.ts' },
  { edge: 'operator-web', source: 'apps/operator-web/src/server.ts' },
];

/**
 * An isolated origin's edge is a consumer whose literals are `/api/…` paths;
 * its `server.ts` maps them to service paths. Templates are additionally tried
 * under these rewrites, and a dedicated test below asserts each pair really
 * exists in that source — so a rewritten match is never a free-text claim.
 *
 * TWO EDGES NOW (M21 PR3a), and the second is why this is a list rather than a
 * constant. Deriving from the vault edge alone was faithful while it was the
 * only one, and would have gone green over the operator edge for a reason that
 * has nothing to do with correctness: the operator edge happens to map
 * `/api/auth/session` to the same place the vault edge does, so a template
 * scraped from it would resolve through the WRONG EDGE'S table and land on the
 * right answer by coincidence. The moment the two disagreed about a path — or
 * the operator edge grew a route the vault edge does not have — the fence would
 * be certifying a call the edge would answer 404. A fence whose input is
 * narrower than its claim goes green for the same reason it is wrong.
 */
const EDGE_REWRITES: ReadonlyArray<EdgeRewrite> = deriveEdgeRewrites();

/**
 * DERIVED FROM THE EDGE'S OWN TABLES, never hand-written (M19 PR4 review).
 *
 * The hand-written version carried `{ from: '/api/auth/', to: '/v1/auth/' }` —
 * a PREFIX rewrite the edge deliberately does not implement. `PROXY_ROUTES`
 * enumerates three exact identity entries with `tree: false` precisely so
 * `/v1/auth/handoff` stays unreachable, and a fence claiming the prefix would
 * certify every `/v1/auth/<anything>` route from any `/api/auth/<anything>`
 * literal in a declared consumer — measured: it retired a correct
 * EXEMPT_RECOVERY_SURFACE exemption on the strength of a call the edge would
 * answer 404. The docstring above it promised a test asserted each pair, and
 * the test asserted neither that pair nor the grantee-candidates one: unchecked
 * free text under a sentence saying it was checked.
 *
 * Deriving removes the class. A pair exists here only because it exists there,
 * `tree` decides prefix-versus-exact, and the assertions below pin that the
 * scrape found real tables rather than silently nothing.
 */
function deriveEdgeRewrites(): ReadonlyArray<EdgeRewrite> {
  const rewrites: EdgeRewrite[] = [];
  for (const { edge, source } of EDGE_SERVERS) {
    const server = read(join(REPO_ROOT, source));
    /*
     * TWO TABLE SHAPES, because the two edges genuinely have two.
     *
     * The vault edge's rows carry `tree`, since one of them IS a tree (the
     * vault's `/items/:id`). The operator edge's carry none, because every one
     * of its routes is an exact match and the absence of the field is asserted
     * by its own fence. Matching both shapes here rather than normalising one
     * of them keeps this scan a reader of what is written, not a claim about
     * what ought to be.
     */
    for (const m of server.matchAll(
      /\{\s*prefix:\s*'([^']+)',[^}]*rewriteTo:\s*'([^']+)',\s*tree:\s*(true|false)\s*\}/g,
    )) {
      rewrites.push({ edge, from: m[1] as string, to: m[2] as string });
    }
    for (const m of server.matchAll(
      /\{\s*path:\s*'([^']+)',\s*upstream:\s*'[^']+',\s*rewriteTo:\s*'([^']+)'\s*\}/g,
    )) {
      rewrites.push({ edge, from: m[1] as string, to: m[2] as string });
    }
    // PASS_THROUGH_ROUTES: credential-free upstream calls. The vault edge has
    // two (extension pairing redemption, refresh); the operator edge has none,
    // and its own fence asserts that absence.
    for (const m of server.matchAll(/\{\s*path:\s*'([^']+)',\s*upstreamPath:\s*'([^']+)'\s*\}/g)) {
      rewrites.push({ edge, from: m[1] as string, to: m[2] as string });
    }
    // The one projection with its own constant rather than a table row.
    const grantee = /GRANTEE_CANDIDATES_PATH\s*=\s*'([^']+)'/.exec(server)?.[1];
    if (grantee !== undefined && server.includes("'/v1/contacts/grantee-candidates'")) {
      rewrites.push({ edge, from: grantee, to: '/v1/contacts/grantee-candidates' });
    }
  }
  return rewrites;
}

function fileMatchesPath(file: string, path: string, enumerated = false): boolean {
  const templates = extractTemplates(file);
  for (const template of templates) {
    if (templateMatchesPath(template, path, enumerated)) {
      return true;
    }
    for (const rewrite of EDGE_REWRITES) {
      if (template.startsWith(rewrite.from)) {
        const rewritten = rewrite.to + template.slice(rewrite.from.length);
        if (templateMatchesPath(rewritten, path, enumerated)) {
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

type RouteDecl =
  | { readonly consumers: readonly string[]; readonly enumerated?: string }
  | { readonly exempt: string };

const consumed = (...files: string[]): RouteDecl => ({ consumers: files });

/**
 * A consumer that addresses this route through an INTERPOLATION WHOSE VALUES
 * ARE THE ROUTE NAMES — not an id. `templateMatchesPath` refuses a consumer
 * `:p` against a literal route segment (one parameterised call site would
 * otherwise certify every sibling route of the same arity, which is what made
 * this fence inert before the M19 PR4 review), and that refusal is right for
 * `/v1/documents/${documentId}` and wrong for `/v1/analysis/${name}` where
 * `name` is a closed union of the four analysis names.
 *
 * The two are the same STRING and different FACTS, so the difference cannot be
 * matched — it is declared, with the reason, exactly as this repo declares
 * every other exception to a fence. The reason must name what bounds the
 * interpolation; an id never does.
 */
const consumedByName = (reason: string, ...files: string[]): RouteDecl => ({
  consumers: files,
  enumerated: reason,
});

/**
 * Exemption reasons are GROUPED constants: each names the decision that
 * leaves the routes unconsumed, so flipping one exemption to a consumer is a
 * one-line diff the PR that lands the consumer carries (the M9 PR2
 * holders-flip pattern).
 */
/**
 * The one enumerated-interpolation reason in the repo today. `analysis(name)`
 * takes `AnalysisName`, a closed union of exactly these four route names, so
 * `/v1/analysis/${name}` really does address all four — unlike
 * `/v1/documents/${documentId}`, whose interpolation is an id and names no
 * route at all.
 */
const ANALYSIS_BY_NAME =
  'apps/bff/src/assistant-client.ts calls `/v1/analysis/${name}` where `name: AnalysisName` is a ' +
  'CLOSED union of exactly these four route names — the interpolation enumerates routes, not ids, ' +
  'so the one call site genuinely addresses each of them.';

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
// EXEMPT_RECOVERY_SURFACE is GONE (M20 PR3): the six recovery routes this
// fence's first run found unreachable (M19 PR1) all have product consumers
// now — the password change (M20 PR1), the three address-change legs (PR2)
// and the two reset legs (PR3), each flipped in the same change as its own
// client. Deleting the constant rather than leaving it for the next milestone
// is deliberate: an unused exemption reason is a sentence about the world that
// has stopped being true, sitting where the next person will reach for it.

const BFF = 'apps/bff/src';
const AI = 'apps/services/ai-assistant/src/clients';
const VW = 'apps/vault-web/src';
const VX = 'apps/vault-extension/src';
const OW = 'apps/operator-web/src';

/**
 * Where a consumer of a service route can live. Used by the stale-exemption
 * check to sweep the TREE rather than the declarations — see the comment there
 * for why that direction matters.
 */
const CONSUMER_ROOTS = [BFF, AI, VW, VX, OW];

/** Every `.ts` under a root, recursively, excluding tests and build output. */
function sweepTs(root: string): string[] {
  const absolute = join(REPO_ROOT, root);
  if (!existsSync(absolute)) {
    return [];
  }
  const out: string[] = [];
  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue;
      out.push(...sweepTs(`${root}/${entry.name}`));
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.spec.ts')) {
      out.push(`${root}/${entry.name}`);
    }
  }
  return out;
}

const ROUTE_CONSUMERS: Readonly<Record<string, RouteDecl>> = {
  // ------------------------------------------------------------ ai-assistant
  'ai-assistant GET /v1/analysis/beneficiary-conflicts': consumedByName(
    ANALYSIS_BY_NAME,
    `${BFF}/assistant-client.ts`,
  ),
  'ai-assistant GET /v1/analysis/estate-tax': consumedByName(
    ANALYSIS_BY_NAME,
    `${BFF}/assistant-client.ts`,
  ),
  'ai-assistant GET /v1/analysis/funding': consumedByName(
    ANALYSIS_BY_NAME,
    `${BFF}/assistant-client.ts`,
  ),
  'ai-assistant GET /v1/analysis/missing-documents': consumedByName(
    ANALYSIS_BY_NAME,
    `${BFF}/assistant-client.ts`,
  ),
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
  'assets GET /v1/assets/:assetId/beneficiaries': consumed(
    `${AI}/assets.client.ts`,
    `${BFF}/assets-client.ts`,
  ),
  // M19 PR2 flipped these six from EXEMPT("pending M19 PR2") to consumers in
  // the same change as the client — the M9 PR2 holders-flip pattern.
  'assets GET /v1/assets/:assetId': consumed(`${BFF}/assets-client.ts`),
  'assets GET /v1/assets/:assetId/events': consumed(`${BFF}/assets-client.ts`),
  'assets PATCH /v1/assets/:assetId': consumed(`${BFF}/assets-client.ts`),
  'assets POST /v1/assets/:assetId/valuations': consumed(`${BFF}/assets-client.ts`),
  'assets POST /v1/assets/:assetId/ownership': consumed(`${BFF}/assets-client.ts`),
  'assets POST /v1/assets/:assetId/retire': consumed(`${BFF}/assets-client.ts`),
  // M19 PR3 flipped the two designation routes from EXEMPT("pending M19
  // PR3") to consumers in the same change as the ceremony's client.
  'assets POST /v1/assets/:assetId/beneficiaries': consumed(`${BFF}/assets-client.ts`),
  'assets DELETE /v1/assets/:assetId/beneficiaries/:contactId': consumed(`${BFF}/assets-client.ts`),
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
  // M21 PR3a. A SECOND mint route rather than an audience argument on the
  // first, so the route is the selector and nothing on the wire could name an
  // audience. Its consumer is the same BFF client, one method over.
  'identity POST /v1/auth/handoff/operator': consumed(`${BFF}/identity-client.ts`),
  // Redemption is audience-blind by construction — the audience travels on the
  // `auth_handoffs` row, written by whichever mint route was called — so BOTH
  // isolated origins spend a code through this one route.
  'identity POST /v1/auth/handoff/redeem': consumed(`${VW}/upstream.ts`, `${OW}/upstream.ts`),
  'identity POST /v1/auth/extension/pairing': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/extension/pairing/redeem': consumed(
    `${VW}/server.ts`,
    `${VX}/session.ts`,
  ),
  // M17's six recovery routes, all consumed as of M20 PR3 — password change
  // (PR1), the three address-change legs (PR2), the two reset legs (PR3) —
  // each flipped in the same change as its own client, the M9 PR2 rule.
  'identity POST /v1/auth/password': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/password/reset': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/password/reset/request': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/email/change': consumed(`${BFF}/identity-client.ts`),
  'identity POST /v1/auth/email/change/request': consumed(`${BFF}/identity-client.ts`),
  'identity DELETE /v1/auth/email/change': consumed(`${BFF}/identity-client.ts`),

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

  it('every route decorator in the repo is one this parser can read', () => {
    // The failure mode being closed: an UNREADABLE decorator used to derive
    // nothing, so the route existed with no entry demanded and no stale
    // pressure — silently outside the fence that claims to cover it. Anything
    // this parser cannot read now names itself here, and the remedy is to
    // write the route in the plain form or to teach the parser deliberately.
    expect(unparseable).toEqual([]);
  });

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
        } else if (!fileMatchesPath(file, path, decl.enumerated !== undefined)) {
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

  it('every declared reason is substantive — exemptions AND enumerations', () => {
    // M20 PR1: this used to guard on `'exempt' in decl` alone, so the OTHER
    // kind of reason — `consumedByName`'s `enumerated` — was checked by
    // nothing. That string is not decoration: its mere PRESENCE widens
    // `templateMatchesPath`'s wildcard to reach literal route segments, which
    // is the relaxation the M19 PR4 review added deliberately and narrowly. An
    // empty string bought the relaxation and stayed green.
    let checked = 0;
    for (const [key, decl] of Object.entries(ROUTE_CONSUMERS)) {
      const reason = 'exempt' in decl ? decl.exempt : decl.enumerated;
      if (reason === undefined) continue;
      checked += 1;
      expect(`${key}: ${reason}`.length).toBeGreaterThanOrEqual(80);
      expect(reason.length).toBeGreaterThanOrEqual(60);
    }
    // Anti-vacuity: both kinds exist on this tree, so a predicate that stopped
    // matching either would show up here rather than pass silently.
    expect(checked).toBeGreaterThanOrEqual(20);
    expect(
      Object.values(ROUTE_CONSUMERS).filter((d) => 'enumerated' in d).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('no exemption is STALE — an exempt route that a consumer really addresses must be flipped', () => {
    // The hole this closes, found while wiring M20 PR1: nothing ever read an
    // exempt entry's route against the consumer corpus, so shipping the client
    // for a route while leaving its `{ exempt: … }` in place left the fence
    // GREEN. That is precisely the zero-callers claim the fence exists to make,
    // inverted — it would go on asserting "no product consumer" about a route
    // the product had started calling.
    //
    // M20 lands the six recovery routes one PR at a time, so this is the check
    // that makes flipping each entry mandatory rather than remembered.
    // THE CORPUS IS SWEPT FROM DISK, NOT TAKEN FROM THE DECLARATIONS — the M20
    // PR5 finding. Building it from `d.consumers` meant only files ALREADY
    // named as somebody's consumer could ever be searched, so a BRAND-NEW
    // client module calling an exempt route was invisible to the check whose
    // whole job is to notice exactly that. The staleness this catches is a fact
    // about the tree, so the tree has to be the input (the 2026-08-06 rule).
    //
    // The roots are the four directories consumers live in, plus the two
    // individually-declared files outside them. Sweeping is what makes the next
    // client module arrive inside the check rather than beside it.
    const corpus = [
      ...new Set([
        ...CONSUMER_ROOTS.flatMap((root) => sweepTs(root)),
        ...Object.values(ROUTE_CONSUMERS).flatMap((d) => ('consumers' in d ? d.consumers : [])),
      ]),
    ];
    const templatesByFile = new Map(corpus.map((f) => [f, extractTemplates(f)]));

    const stale: string[] = [];
    for (const [key, decl] of Object.entries(ROUTE_CONSUMERS)) {
      if (!('exempt' in decl)) continue;
      const path = key.slice(key.lastIndexOf(' ') + 1);
      for (const [file, templates] of templatesByFile) {
        // `enumerated: false` — the narrow matcher. A wildcard reaching a
        // literal here would accuse an exemption of being stale because some
        // unrelated call site happens to share its arity, which is the exact
        // inertness the M19 PR4 review removed.
        if (templates.some((t) => templateMatchesPath(t, path))) {
          stale.push(`${key} is addressed by ${file} — flip it to consumed()`);
        }
      }
    }
    expect(stale).toEqual([]);

    // Anti-vacuity: the corpus really was read. Without this a bad path or an
    // empty extraction would make "no stale exemptions" vacuously true.
    expect(corpus.length).toBeGreaterThanOrEqual(10);
    expect([...templatesByFile.values()].flat().length).toBeGreaterThanOrEqual(50);

    // …and the SWEEP really widened it. A `sweepTs` that silently returned
    // nothing would leave this check reading only the declared consumers again
    // — the exact blindness it was rewritten to remove, restored without a
    // single assertion noticing.
    const declared = new Set(
      Object.values(ROUTE_CONSUMERS).flatMap((d) => ('consumers' in d ? d.consumers : [])),
    );
    const swept = corpus.filter((f) => !declared.has(f));
    expect(swept.length).toBeGreaterThanOrEqual(10);
  });

  it('the edge rewrites are DERIVED from each server.ts, and the scrape really found them', () => {
    // Anti-vacuity: a regex that stops matching would empty this table and
    // silently narrow the fence rather than fail it. The pairs are asserted by
    // SHAPE (each is a real /api/… → /v1/… mapping) and by count, and the one
    // pair the hand-written table invented — the `/api/auth/` PREFIX — is
    // asserted ABSENT, because both edges enumerate exact identity routes so
    // that `/v1/auth/handoff` cannot be reached from either origin.
    expect(EDGE_REWRITES.length).toBeGreaterThanOrEqual(9);
    for (const { from, to } of EDGE_REWRITES) {
      expect(from.startsWith('/api/')).toBe(true);
      expect(to.startsWith('/v1/')).toBe(true);
    }
    const froms = EDGE_REWRITES.map((r) => r.from);
    expect(froms).toContain('/api/vault/');
    expect(froms).toContain('/api/auth/session');
    expect(froms).toContain('/api/grantee-candidates');
    expect(froms).not.toContain('/api/auth/');
    // And NO derived pair reaches any handoff route from either edge — not the
    // two mints, and not redemption either. Redemption happens server-side in
    // `upstream.redeemHandoff`, which is not a proxy entry at all: a browser on
    // an isolated origin never speaks to identity's handoff surface, in either
    // direction.
    for (const { to } of EDGE_REWRITES) {
      expect(to.startsWith('/v1/auth/handoff')).toBe(false);
    }
  });

  it('EVERY declared edge contributed rewrites — no edge is silently unscanned', () => {
    /*
     * THE PER-EDGE FLOOR, and it is the point of the list existing.
     *
     * A total count cannot see a second edge going missing: the vault edge
     * alone clears any global floor, so a shape the scan cannot read — a table
     * written `{ path, upstream, rewriteTo }` where the regex wants
     * `{ prefix, rewriteTo, tree }` — would contribute ZERO and the fence would
     * stay green while knowing nothing about that origin. Then its `/api/…`
     * literals resolve through the OTHER edge's table, which is how a fence
     * certifies a call that would be answered 404.
     *
     * Asserting per edge is the same anti-vacuity habit applied one level down,
     * which is the 2026-08-17 lesson: a check on a total is not a check on each
     * of its parts.
     */
    for (const { edge, source } of EDGE_SERVERS) {
      const derived = EDGE_REWRITES.filter((r) => r.edge === edge);
      expect({ edge, source, count: derived.length > 0 }).toEqual({
        edge,
        source,
        count: true,
      });
    }
    // And each one really maps its own identity routes, so the operator edge is
    // not passing on the vault edge's table by coincidence.
    const operator = EDGE_REWRITES.filter((r) => r.edge === 'operator-web').map((r) => r.from);
    expect(operator).toEqual(['/api/auth/session', '/api/auth/stepup', '/api/auth/logout']);
  });

  it('template extraction sees a real corpus (anti-vacuity)', () => {
    const consumerFiles = new Set(
      Object.values(ROUTE_CONSUMERS).flatMap((d) => ('consumers' in d ? [...d.consumers] : [])),
    );
    const total = [...consumerFiles].reduce((acc, f) => acc + extractTemplates(f).length, 0);
    expect(total).toBeGreaterThanOrEqual(100);
  });
});
