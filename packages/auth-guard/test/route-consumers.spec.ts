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

import { routeDecorator, routeDecoratorOpener } from './nest-routes';
import { stripComments } from './source-text';
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
// The nine-verb list that used to live here was short by the seven WebDAV
// verbs Nest 11 also ships. It is derived now — see ./nest-routes.
const ROUTE_DECORATOR = routeDecorator();
const ROUTE_DECORATOR_OPENER = routeDecoratorOpener();

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
  const source = read(absolute);
  /*
   * RESOLVE FILE-LOCAL PATH CONSTANTS BEFORE COLLAPSING.
   *
   * A client that writes `${CASES}/${id}/timeline` has a template this scan
   * cannot see: the constant collapses to `:p` like any other interpolation,
   * so the whole prefix disappears and the row reads as "addresses nothing".
   * That direction is the safe one — it fails the fence rather than passing it
   * — but it is still a fence going red for a reason that is not the property,
   * which is how an escape hatch gets widened. Only same-file `const X = '…'`
   * string literals are substituted, so this cannot reach across modules and
   * cannot invent a path the file does not contain.
   */
  const constants = new Map<string, string>();
  for (const m of source.matchAll(/const\s+([A-Z][A-Z0-9_]*)\s*=\s*'([^']*)'/g)) {
    constants.set(m[1] as string, m[2] as string);
  }
  const resolved = source.replace(
    /\$\{([A-Z][A-Z0-9_]*)\}/g,
    (whole, name: string) => constants.get(name) ?? whole,
  );
  // Collapse the REST of the interpolations: an `${encodeURIComponent(\n …\n)}`
  // spans lines, and extracting before collapsing would truncate the template
  // at the newline (measured against documents-client.ts).
  const collapsed = resolved.replace(/\$\{[^}]*\}/g, ':p');
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
  /**
   * The HTTP method the row grants, where the edge declares one.
   *
   * The vault edge's rows are prefix TREES and forward whatever method arrives,
   * so theirs is null and every method-aware check treats them as covering all
   * of them — which is what they do. The operator edge names a method per row,
   * because two settlement routes there share a path and differ only by verb.
   */
  readonly method: string | null;
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
 * The same rows, named for what the method-aware checks below use them as: the
 * complete set of (method, upstream path) pairs any isolated origin can
 * address.
 */
const EDGE_ROWS = EDGE_REWRITES;

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
      rewrites.push({ edge, method: null, from: m[1] as string, to: m[2] as string });
    }
    /*
     * The operator edge's rows are read as BLOCKS rather than as one
     * field-ordered alternation, and that is a fix for a hole the shape had
     * from birth: the original regex required the row to close immediately
     * after `rewriteTo`, so adding ANY field — which M21 PR3b did, giving each
     * row a `method` — made it match nothing. A derivation that silently stops
     * reading is the 2026-08-07 lesson, and the completeness assertion below is
     * the other half of closing it.
     */
    for (const block of server.matchAll(/\{[^{}]*\}/g)) {
      const text = block[0];
      const from = /\bpath:\s*'([^']+)'/.exec(text)?.[1];
      const to = /\brewriteTo:\s*'([^']+)'/.exec(text)?.[1];
      if (from !== undefined && to !== undefined) {
        rewrites.push({ edge, method: /\bmethod:\s*'([A-Z]+)'/.exec(text)?.[1] ?? null, from, to });
      }
    }
    // PASS_THROUGH_ROUTES: credential-free upstream calls. The vault edge has
    // two (extension pairing redemption, refresh); the operator edge has none,
    // and its own fence asserts that absence.
    for (const m of server.matchAll(/\{\s*path:\s*'([^']+)',\s*upstreamPath:\s*'([^']+)'\s*\}/g)) {
      rewrites.push({ edge, method: null, from: m[1] as string, to: m[2] as string });
    }
    // The one projection with its own constant rather than a table row.
    const grantee = /GRANTEE_CANDIDATES_PATH\s*=\s*'([^']+)'/.exec(server)?.[1];
    if (grantee !== undefined && server.includes("'/v1/contacts/grantee-candidates'")) {
      rewrites.push({ edge, method: null, from: grantee, to: '/v1/contacts/grantee-candidates' });
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
      // A PREFIX rewrite (the vault edge's trees) — string surgery, as before.
      if (template.startsWith(rewrite.from)) {
        const rewritten = rewrite.to + template.slice(rewrite.from.length);
        if (templateMatchesPath(rewritten, path, enumerated)) {
          return true;
        }
      }
      /*
       * A TEMPLATE rewrite (the operator edge's parameterised rows).
       * `startsWith` cannot see these: the edge writes `:caseId` where a
       * caller's interpolation collapses to `:p`, so the two strings never
       * share a prefix past `cases/`. Matching the consumer's template against
       * the edge's `from` SEGMENT-WISE is the same one-directional rule used
       * everywhere else — a consumer wildcard lines up with an edge parameter
       * and never with an edge literal — and the edge's `to` is then the
       * template compared against the route.
       */
      if (rewrite.from.includes('/:') && templateMatchesPath(template, rewrite.from)) {
        if (templateMatchesPath(rewrite.to, path, enumerated)) {
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
  | { readonly exempt: string }
  | { readonly pathSharedWith: string; readonly reason: string };

const consumed = (...files: string[]): RouteDecl => ({ consumers: files });

/**
 * A route with NO consumer of its own, whose PATH is addressed by a consumer of
 * a SIBLING route — same path, different method.
 *
 * This fence matches by PATH (its header says so: "two methods sharing one path
 * are covered by one literal"), and until M21 PR3b that imprecision cost
 * nothing, because no consumer had ever addressed one verb of a shared path
 * while the other stayed unconsumed. The operator edge does exactly that:
 * `GET cases/:caseId/stages` is proxied to the console and `POST` on the same
 * path is the EXECUTOR's request, which the operator audience does not admit
 * and the edge's table does not carry.
 *
 * The two honest answers were both wrong. `consumed()` would claim a caller
 * that does not exist. `{ exempt }` would be flagged STALE, because the
 * sibling's literal really is in the corpus — correctly, since the check cannot
 * see a method. So the collision is DECLARED, with the sibling named, and three
 * assertions make the declaration checkable rather than a way out: the sibling
 * must exist, must share the path, must differ in method and must really be
 * consumed — and no edge table may name THIS method on THIS path, which is the
 * property that makes the route genuinely unreachable rather than merely
 * undeclared. That last one is the `consumedByName` precedent: a declared
 * exception with a checked reason, never a matcher loosened globally.
 */
const pathSharedWith = (sibling: string, reason: string): RouteDecl => ({
  pathSharedWith: sibling,
  reason,
});

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
  'Profile\u2019s two CROSS-OWNER contact reads \u2014 the docs/03 \u00a75.5 ABAC demonstrator, ' +
  'resolved through `effectiveContactReadGrants`: a permission the owner handed out WHILE LIVING, ' +
  'to a role-holder who is not necessarily an executor. No product surface asks them; the People ' +
  'screen reads the caller\u2019s own contacts. THIS REASON USED TO SAY THEY RESOLVE THROUGH ' +
  'SETTLEMENT\u2019S STAGED GRANT BEHIND THE DOCUMENTS RUNG. That was false when written (M23 PR2) ' +
  'and is the defect M23 PR4a was opened to fix: the grant query filters ' +
  '`effective_condition = \u2018immediate\u2019`, which an executor\u2019s `on_death_verified` ' +
  'designation never satisfies, so no ladder had any bearing on these two routes at all. The ' +
  'executor now has a route of his own \u2014 `GET /v1/estates/:ownerUserId/contacts`, consumed ' +
  'below \u2014 and these two stay what they always were. Profile\u2019s int suites cover both.'; // EXEMPT_SETTLEMENT_REPORTING is GONE (M22 PR4c), and it left on the terms it
// set for itself: "when PR4 lands, this constant goes with its last entry."
// All seven settlement routes it once covered now name a consumer — four to
// PR3 (the case list, the kill switch, both settings routes) and the last
// three here. The EXEMPT_TB7_OPERATOR/EXEMPT_RECOVERY_SURFACE precedent is
// that a constant deleted with its final entry cannot be quietly reused for a
// route it was never written about, which is how a reviewer ends up reading a
// true sentence about the wrong thing.;
// EXEMPT_TB7_OPERATOR is GONE (M21 PR4c). It said the operator platform was
// deferred and that building its UI "would be the wrong order" — true when it
// was written, false since M21 PR3b (#117) shipped the console, which consumes
// thirteen settlement routes named `consumed(OW_CLIENT)` about forty lines
// below. Its five routes were never one category, and the single reason hid
// that: a reviewer checking whether they were still legitimately unconsumed was
// told the operator platform does not exist. Same standard as the
// EXEMPT_RECOVERY_SURFACE note below — except the sentence had stopped being
// true while the constant was still in use, which is the harder case to notice.
const EXEMPT_EVIDENCE_CONTENT =
  'Documents\u2019 own surface, not the console\u2019s: the operator reads a case timeline, never ' +
  'document bytes. Its consumer is the M21 PR5 slot (docs/04 — documents evidence content plus ' +
  'the legal-hold lift ceremony); the documents e2e drives the versioned read end to end.';
const EXEMPT_PROVIDER_INTAKE =
  'Machine-to-machine intake: a death signal arrives from the data-provider isolate, never from ' +
  'a person\u2019s browser, which is why `reportProvider` is deliberately absent from the operator ' +
  'audience list. No single source triggers anything — mandatory human review follows it.';
const EXEMPT_EXECUTOR_CASEWORK =
  'The distribution ladder \u2014 recording what an estate paid out and moving it through ' +
  'approval. NARROWED TWICE NOW. M23 PR2 took the stage ladder and the inventory out of this ' +
  'reason; M23 PR3 took the CHECKLIST out, and the checklist was the half this constant was ' +
  'named for. What is left is the money, which is M23 PR4\u2019s slice and the last of it: when ' +
  'the two distribution routes find their consumer, delete this constant rather than leave it ' +
  'for the next milestone. The reason no longer cites docs/04\u2019s "3 routes", which was ' +
  'wrong \u2014 count them from the entries that name this constant instead. The operator ' +
  'console deliberately does not carry them: an executor is a grieving family member, not a ' +
  'platform operator, and the two surfaces have different ceremonies.';

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
 * The console's ONE settlement call site. Named alongside `server.ts` on every
 * route it reaches, because the edge and the client are two different claims: a
 * path in `PROXY_ROUTES` says the edge WOULD forward it, and a template here
 * says something actually asks. Slice 3 flipped these routes on the edge alone
 * and the second half arrives with the screens, which is the M9 PR2 rule (a
 * capability and its callers ship together) applied inside one milestone.
 */
const OW_CLIENT = `${OW}/client/settlement.ts`;

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
  // FLIPPED IN M23 PR2, in the same change as the screen that reads it. This
  // was the FIRST entry `EXEMPT_EXECUTOR_SURFACE` was ever written about (M19
  // PR1), and the staged-access mechanism behind it — docs/03 §5.1 control 5 —
  // had never executed outside a test until now.
  'assets GET /v1/estates/:ownerUserId/assets': consumed(`${BFF}/assets-client.ts`),

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
    exempt: EXEMPT_EVIDENCE_CONTENT,
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
  'profile GET /v1/contact-links/estates': consumed(`${BFF}/profile-client.ts`),
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
  // THE EXECUTOR'S OWN ROUTE (M23 PR4a) — a different authority (settlement's
  // staged grant, not a permission grant), a different audit action
  // (`contact.estate.viewed`), and a different reason to exist (docs/03 §5.4's
  // verified contact cards). Modelled on assets' `GET /v1/estates/:id/assets`,
  // which split for the same reason rather than branching inside the owner path.
  'profile GET /v1/estates/:ownerUserId/contacts': consumed(`${BFF}/profile-client.ts`),
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
  'settlement GET /v1/settlement/reportable-estates': consumed('apps/bff/src/settlement-client.ts'),
  // BACK TO `consumed` FROM `pathSharedWith` (M22 PR4c). The declaration existed
  // because the BFF addressed the GET on this path and not the POST — it had no
  // report method and the SDL had no mutation for one to sit behind. Both exist
  // now (`reportCase`, `reportDeath`), so the weaker claim is retired rather
  // than left standing: a `pathSharedWith` that has become untrue reads as a
  // route still waiting for its consumer.
  'settlement POST /v1/settlement/cases': consumed('apps/bff/src/settlement-client.ts'),
  'settlement GET /v1/settlement/cases': consumed('apps/bff/src/settlement-client.ts'),
  'settlement GET /v1/settlement/cases/:caseId': consumed(`${OW}/server.ts`, OW_CLIENT),
  'settlement POST /v1/settlement/cases/:caseId/evidence': consumed(
    'apps/bff/src/settlement-client.ts',
  ),
  'settlement POST /v1/settlement/cases/:caseId/void': consumed(
    'apps/bff/src/settlement-client.ts',
  ),
  'settlement GET /v1/settlement/settings': consumed('apps/bff/src/settlement-client.ts'),
  'settlement PUT /v1/settlement/settings': consumed('apps/bff/src/settlement-client.ts'),
  'settlement POST /v1/settlement/cases/report-provider': { exempt: EXEMPT_PROVIDER_INTAKE },
  'settlement GET /v1/settlement/queue': consumed(`${OW}/server.ts`, OW_CLIENT),
  'settlement GET /v1/settlement/administrable': consumed(`${OW}/server.ts`, OW_CLIENT),
  // The EXECUTOR's worklist, shipped with its consumer in one change (M23 PR2).
  // Deliberately not a widened `administrable`, which is the console's listing
  // of the same estates from the other side — two audiences, two routes,
  // neither borrowing the other's answer.
  'settlement GET /v1/settlement/executor-cases': consumed(`${BFF}/settlement-client.ts`),
  'settlement POST /v1/settlement/cases/:caseId/review/start': consumed(
    `${OW}/server.ts`,
    OW_CLIENT,
  ),
  'settlement POST /v1/settlement/cases/:caseId/review': consumed(`${OW}/server.ts`, OW_CLIENT),
  'settlement POST /v1/settlement/cases/:caseId/verify': consumed(`${OW}/server.ts`, OW_CLIENT),
  'settlement POST /v1/settlement/cases/:caseId/close': consumed(`${OW}/server.ts`, OW_CLIENT),
  'settlement GET /v1/settlement/cases/:caseId/timeline': consumed(`${OW}/server.ts`, OW_CLIENT),
  // THE CHECKLIST, CONSUMED (M23 PR3). Both halves in one change: reading the
  // list and ticking an item are the same surface, and shipping the read alone
  // would have left a mutation nobody calls — the gap this fence exists for.
  //
  // NEITHER IS ON THE CONSOLE, and that is not an omission. A task is
  // procedural state about an administration, so it needs no access stage; it
  // is also nobody's business but the estate's, so an operator has no reason to
  // read one and no route to tick one.
  'settlement GET /v1/settlement/cases/:caseId/tasks': consumed(`${BFF}/settlement-client.ts`),
  'settlement POST /v1/settlement/tasks/:taskId/completion': consumed(
    `${BFF}/settlement-client.ts`,
  ),
  // TWO SURFACES, and the route was built for both: `assertCaseVisible` admits
  // the operator console AND the estate's executor. M23 PR2 added the second.
  'settlement GET /v1/settlement/cases/:caseId/stages': consumed(
    `${OW}/server.ts`,
    OW_CLIENT,
    `${BFF}/settlement-client.ts`,
  ),
  // BACK TO `consumed` FROM `pathSharedWith` (M23 PR2) — the M22 PR4c move on
  // `POST /cases`, for the same reason. The weaker claim was true only while
  // nothing asked. The console still proxies the GET on this path and not the
  // POST, which has not changed; what changed is that `requestEstateAccess`
  // exists, and a `pathSharedWith` that has become untrue reads as a route
  // still waiting for its consumer.
  'settlement POST /v1/settlement/cases/:caseId/stages': consumed(`${BFF}/settlement-client.ts`),
  'settlement POST /v1/settlement/stages/:stageId/decision': consumed(`${OW}/server.ts`, OW_CLIENT),
  'settlement POST /v1/settlement/stages/:stageId/revoke': consumed(`${OW}/server.ts`, OW_CLIENT),
  'settlement GET /v1/settlement/cases/:caseId/distributions': consumed(
    `${OW}/server.ts`,
    OW_CLIENT,
  ),
  'settlement POST /v1/settlement/cases/:caseId/distributions': pathSharedWith(
    'settlement GET /v1/settlement/cases/:caseId/distributions',
    'Recording a distribution is the executor write; the console proxies the GET on this path ' +
      'and approves through distributions/:distributionId/approval, which is a path of its own.',
  ),
  'settlement POST /v1/settlement/distributions/:distributionId/approval': consumed(
    `${OW}/server.ts`,
    OW_CLIENT,
  ),
  'settlement POST /v1/settlement/distributions/:distributionId/status': {
    exempt: EXEMPT_EXECUTOR_CASEWORK,
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

  it('every pathSharedWith names a real, consumed sibling on the same path', () => {
    /*
     * The declaration is only honest if all four of its parts are true, so all
     * four are checked. Without them it would be a way to silence the fence by
     * pointing at a name.
     */
    let checked = 0;
    for (const [key, decl] of Object.entries(ROUTE_CONSUMERS)) {
      if (!('pathSharedWith' in decl)) continue;
      checked += 1;
      const sibling = ROUTE_CONSUMERS[decl.pathSharedWith];
      expect({ key, siblingExists: sibling !== undefined }).toEqual({ key, siblingExists: true });
      // Same PATH, different METHOD — which is the whole claim.
      const path = key.slice(key.lastIndexOf(' ') + 1);
      const siblingPath = decl.pathSharedWith.slice(decl.pathSharedWith.lastIndexOf(' ') + 1);
      expect({ key, path, siblingPath }).toEqual({ key, path, siblingPath: path });
      expect({ key, sameKey: decl.pathSharedWith === key }).toEqual({ key, sameKey: false });
      // …and the sibling really is CONSUMED. Pointing at another exemption, or
      // at another pathSharedWith, would be a chain with nothing at the end.
      expect({ key, siblingConsumed: sibling !== undefined && 'consumers' in sibling }).toEqual({
        key,
        siblingConsumed: true,
      });
    }
    // ONE LEFT (M23 PR2 flipped `POST /cases/:caseId/stages` to `consumed`).
    // A floor of one still catches the failure this guards — a predicate that
    // stopped matching gives zero — and when the last entry goes, the
    // `pathSharedWith` MECHANISM goes with it, on the
    // EXEMPT_SETTLEMENT_REPORTING precedent: a declaration form with no
    // instances is a shape the next person reaches for without a reason to.
    expect(checked).toBeGreaterThanOrEqual(1);
  });

  it('NO EDGE TABLE NAMES A pathSharedWith ROUTE — the method really is unreachable', () => {
    /*
     * The property that makes the declaration a fact rather than a convenience.
     * `pathSharedWith` says "no consumer of MY method"; the corpus check cannot
     * see a method, but the edge tables DO carry one, so an edge row naming
     * this exact (method, path) is the one way the claim could be false while
     * every other assertion passed.
     */
    const claims: string[] = [];
    for (const [key, decl] of Object.entries(ROUTE_CONSUMERS)) {
      if (!('pathSharedWith' in decl)) continue;
      const method = key.slice(key.indexOf(' ') + 1, key.lastIndexOf(' '));
      const path = key.slice(key.lastIndexOf(' ') + 1);
      for (const row of EDGE_ROWS) {
        if (row.method === method && templateMatchesPath(row.to, path)) {
          claims.push(`${key} is proxied by ${row.edge} — it has a consumer, so flip it`);
        }
      }
    }
    expect(claims).toEqual([]);
    // Anti-vacuity: the rows really were read, and they really carry methods.
    expect(EDGE_ROWS.length).toBeGreaterThanOrEqual(16);
    expect(EDGE_ROWS.filter((r) => r.method !== null).length).toBeGreaterThanOrEqual(16);
  });

  it('EVERY REWRITE ROW IN EVERY EDGE SOURCE WAS READ (completeness, not a floor)', () => {
    /*
     * The per-edge floor below asks whether an edge contributed ANYTHING. This
     * asks whether it contributed EVERYTHING, and the difference is exactly the
     * hole M21 PR3b found: the operator-shape regex required a row to close
     * right after `rewriteTo`, so giving each row a `method` would have made it
     * read zero of sixteen while the vault edge's rows kept the floor green and
     * the operator edge kept a non-empty count from its three unchanged
     * identity rows. A floor cannot see a partial read.
     *
     * Counting the `rewriteTo:` and `upstreamPath:` occurrences in the source
     * is a second, deliberately dumber derivation. Two readings of one file
     * that must agree is the compose-parity mechanism.
     */
    for (const { edge, source } of EDGE_SERVERS) {
      const text = read(join(REPO_ROOT, source));
      const declared =
        (text.match(/\brewriteTo:\s*'/g) ?? []).length +
        (text.match(/\bupstreamPath:\s*'/g) ?? []).length +
        (/GRANTEE_CANDIDATES_PATH\s*=\s*'/.test(text) ? 1 : 0);
      const derived = EDGE_REWRITES.filter((r) => r.edge === edge).length;
      expect({ edge, declared, derived }).toEqual({ edge, declared, derived: declared });
      // …and neither number is zero, or they would agree vacuously.
      expect({ edge, declared: declared > 0 }).toEqual({ edge, declared: true });
    }
  });

  it('every declared reason is substantive — exemptions AND enumerations', () => {
    // M20 PR1: this used to guard on `'exempt' in decl` alone, so the OTHER
    // kind of reason — `consumedByName`'s `enumerated` — was checked by
    // nothing. `pathSharedWith`'s reason joined them in M21 PR3b for the same
    // reason: it is what a reader has instead of a consumer file. That string is not decoration: its mere PRESENCE widens
    // `templateMatchesPath`'s wildcard to reach literal route segments, which
    // is the relaxation the M19 PR4 review added deliberately and narrowly. An
    // empty string bought the relaxation and stayed green.
    let checked = 0;
    for (const [key, decl] of Object.entries(ROUTE_CONSUMERS)) {
      const reason =
        'exempt' in decl ? decl.exempt : 'pathSharedWith' in decl ? decl.reason : decl.enumerated;
      if (reason === undefined) continue;
      checked += 1;
      expect(`${key}: ${reason}`.length).toBeGreaterThanOrEqual(80);
      expect(reason.length).toBeGreaterThanOrEqual(60);
    }
    // Anti-vacuity, as SETS rather than as a total. The comment above says the
    // claim is that BOTH KINDS are covered, and a count cannot say that: 19
    // exemptions and no `pathSharedWith` clears any floor a mixed corpus does.
    // Stated this way it also stops eroding — M23 PR2 flipped two routes to
    // consumers and a bare number had to be edited down, which is the ratchet
    // running the wrong way.
    const kinds = new Set(
      Object.values(ROUTE_CONSUMERS).map((decl) =>
        'exempt' in decl ? 'exempt' : 'pathSharedWith' in decl ? 'pathSharedWith' : 'enumerated',
      ),
    );
    kinds.delete('enumerated');
    expect([...kinds].sort()).toEqual(['exempt', 'pathSharedWith']);
    expect(checked).toBeGreaterThanOrEqual(10);
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
    // Its own identity routes, read from its own table — not the vault edge's
    // by coincidence. The COUNT is deliberately not asserted here: the settlement
    // half of that table is derived and checked against real handler metadata by
    // `apps/services/settlement/test/session-audience.spec.ts`, and a second copy
    // of a number is free to drift from the one that derives it (M21 PR2.5).
    expect(operator.filter((from) => from.startsWith('/api/auth/'))).toEqual([
      '/api/auth/session',
      '/api/auth/stepup',
      '/api/auth/logout',
    ]);
    expect(operator.filter((from) => from.startsWith('/api/settlement/')).length).toBeGreaterThan(
      0,
    );
    expect(operator).toHaveLength(
      operator.filter(
        (from) => from.startsWith('/api/auth/') || from.startsWith('/api/settlement/'),
      ).length,
    );
  });

  it('template extraction sees a real corpus (anti-vacuity)', () => {
    const consumerFiles = new Set(
      Object.values(ROUTE_CONSUMERS).flatMap((d) => ('consumers' in d ? [...d.consumers] : [])),
    );
    const total = [...consumerFiles].reduce((acc, f) => acc + extractTemplates(f).length, 0);
    expect(total).toBeGreaterThanOrEqual(100);
  });
});
