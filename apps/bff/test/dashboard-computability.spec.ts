import { Kind, parse } from 'graphql';
import type { DocumentNode, FieldDefinitionNode, ObjectTypeDefinitionNode } from 'graphql';
import { typeDefs } from '../src/schema';

/**
 * M24 PR0 — the dashboard computability fence.
 *
 * docs/00 names thirteen dashboard surfaces. docs/04's M24 section splits them
 * into a computable subset — every tile backed by an operation that exists
 * today — and an OUT list, each absence with a reason. Both halves are claims
 * about THIS schema, and a claim about the tree beside a tree that grows is a
 * test nobody runs. So the split lives here as data, checked against the SDL
 * the BFF actually serves (`typeDefs`, the string the executable schema is
 * built from), never against a mirror of it.
 *
 * Which layer this proves: the mapping against the SDL. The thirteen names are
 * a transcription of docs/00 §"Cross-cutting features" — prose this spec
 * cannot derive — so the transcription itself is a citation, not an assertion.
 *
 * A red OUT probe means the platform has GROWN a backing for something the
 * scope calls uncomputable: revisit docs/04's M24 scope and move the item.
 * Never delete the assertion to get green.
 */

const doc: DocumentNode = parse(typeDefs);

function objectType(name: string): ObjectTypeDefinitionNode | undefined {
  for (const def of doc.definitions) {
    if (def.kind === Kind.OBJECT_TYPE_DEFINITION && def.name.value === name) {
      return def;
    }
  }
  return undefined;
}

function fieldOf(typeName: string, fieldName: string): FieldDefinitionNode | undefined {
  return objectType(typeName)?.fields?.find((f) => f.name.value === fieldName);
}

function hasField(typeName: string, fieldName: string): boolean {
  return fieldOf(typeName, fieldName) !== undefined;
}

/** One (type, field) pair a tile reads. */
interface Backing {
  readonly type: string;
  readonly field: string;
}

/**
 * Why an item is OUT — a closed vocabulary, so a new reason is a visible
 * decision rather than a free-text shrug.
 */
type OutReason =
  /** Nothing anywhere in the platform models or computes it. */
  | 'no_data_model'
  /** Zone A is zero-knowledge: the server CANNOT compute it, by design. */
  | 'zone_boundary'
  /** Exists, but only inside an executor's settlement case. */
  | 'settlement_context_only'
  /** A later milestone owns the backing (M30, the in-app feed). */
  | 'owned_by_m30';

interface InItem {
  readonly item: string;
  readonly decision: 'in';
  readonly backing: readonly Backing[];
}

interface OutItem {
  readonly item: string;
  readonly decision: 'out';
  readonly reason: OutReason;
  /** Root Query fields whose ABSENCE is what keeps the reason true. */
  readonly absentQueryFields: readonly string[];
}

type DashboardItem = InItem | OutItem;

/** docs/00's thirteen dashboard surfaces, in docs/00's own order. */
const DASHBOARD: readonly DashboardItem[] = [
  {
    item: 'net worth',
    decision: 'in',
    backing: [
      { type: 'Query', field: 'netWorth' },
      // Money is a decimal STRING end to end; the tile renders through
      // @estate/money and never parses it to a float.
      { type: 'NetWorth', field: 'totalValue' },
      { type: 'NetWorth', field: 'valuedAssetCount' },
    ],
  },
  {
    item: 'assets',
    decision: 'in',
    backing: [
      { type: 'Query', field: 'assets' },
      { type: 'NetWorth', field: 'assetCount' },
    ],
  },
  {
    item: 'liabilities',
    decision: 'out',
    reason: 'no_data_model',
    absentQueryFields: ['liabilities'],
  },
  {
    // As the data model has it: three asset CATEGORIES (life_insurance,
    // ltc_insurance, annuity — the assets_view CHECK owns that vocabulary; the
    // SDL deliberately carries `category` as a String rather than a mirror).
    // A policy-level tile — coverage, premiums, term — has no model and is not
    // in scope; see docs/04's M24 section.
    item: 'insurance',
    decision: 'in',
    backing: [
      { type: 'Query', field: 'assets' },
      { type: 'Asset', field: 'category' },
      { type: 'Asset', field: 'estValue' },
    ],
  },
  {
    item: 'estate funding %',
    decision: 'in',
    backing: [
      // assets_view.in_trust exists to drive this metric — its DDL says so.
      { type: 'NetWorth', field: 'inTrustValue' },
      { type: 'NetWorth', field: 'totalValue' },
      { type: 'Readiness', field: 'funding' },
    ],
  },
  {
    item: 'document completion %',
    decision: 'in',
    backing: [
      { type: 'Query', field: 'documents' },
      { type: 'Document', field: 'executionStatus' },
      { type: 'Readiness', field: 'missingDocuments' },
    ],
  },
  {
    item: 'beneficiary health',
    decision: 'in',
    backing: [
      { type: 'Readiness', field: 'beneficiaryConflicts' },
      { type: 'Analysis', field: 'status' },
    ],
  },
  {
    // Rendered as the four analyses and their statuses, NEVER folded into an
    // invented composite number (docs/06, 2026-08-21).
    item: 'estate readiness score',
    decision: 'in',
    backing: [
      { type: 'Query', field: 'readiness' },
      { type: 'Readiness', field: 'funding' },
      { type: 'Readiness', field: 'missingDocuments' },
      { type: 'Readiness', field: 'beneficiaryConflicts' },
      { type: 'Readiness', field: 'estateTax' },
      { type: 'Analysis', field: 'status' },
    ],
  },
  {
    // FACTS, not a score (docs/06, 2026-08-21): MFA level, step-up state,
    // passkey and session inventories, address verification. An invented
    // weighting is a number nobody can defend.
    item: 'security score',
    decision: 'in',
    backing: [
      { type: 'Query', field: 'session' },
      { type: 'Session', field: 'mfaLevel' },
      { type: 'Session', field: 'stepUpFresh' },
      { type: 'Query', field: 'passkeys' },
      { type: 'Query', field: 'sessions' },
      { type: 'Query', field: 'emailVerification' },
    ],
  },
  {
    // Zone A is zero-knowledge; a server-side password-health read would BE
    // the boundary violation. The probe below is a tripwire, not the control —
    // the control is the architecture.
    item: 'password health',
    decision: 'out',
    reason: 'zone_boundary',
    absentQueryFields: ['passwordHealth'],
  },
  {
    // `estateTasks` exists and is deliberately not a backing: it is an
    // executor's per-case worklist, not an owner task system. Its own named
    // test below pins the boundary this reason decides.
    item: 'outstanding tasks',
    decision: 'out',
    reason: 'settlement_context_only',
    absentQueryFields: ['tasks'],
  },
  {
    item: 'notifications',
    decision: 'out',
    reason: 'owned_by_m30',
    absentQueryFields: ['notifications'],
  },
  {
    item: 'timeline',
    decision: 'out',
    reason: 'no_data_model',
    absentQueryFields: ['timeline'],
  },
];

describe('M24 dashboard computability (docs/04 M24 scope vs the SDL the BFF serves)', () => {
  it('covers exactly the thirteen docs/00 dashboard surfaces, once each', () => {
    expect(DASHBOARD).toHaveLength(13);
    expect(new Set(DASHBOARD.map((d) => d.item)).size).toBe(13);
  });

  it('gives every item a non-empty backing or a non-empty absence probe', () => {
    // The data-shape floor: an entry with nothing to check is an entry this
    // fence has silently stopped fencing.
    for (const entry of DASHBOARD) {
      if (entry.decision === 'in') {
        expect(entry.backing.length).toBeGreaterThan(0);
      } else {
        expect(entry.absentQueryFields.length).toBeGreaterThan(0);
      }
    }
  });

  it('finds every IN backing in the SDL', () => {
    const declared = DASHBOARD.filter((d): d is InItem => d.decision === 'in').flatMap((d) =>
      d.backing.map((b) => ({ item: d.item, ...b })),
    );
    const missing = declared.filter((b) => !hasField(b.type, b.field));
    expect(missing).toEqual([]);
    // Anti-vacuity at the scan's own level: the loop above walked something.
    expect(declared.length).toBeGreaterThan(15);
  });

  it('finds every OUT probe still absent from Query', () => {
    const probes = DASHBOARD.filter((d): d is OutItem => d.decision === 'out').flatMap((d) =>
      d.absentQueryFields.map((field) => ({ item: d.item, reason: d.reason, field })),
    );
    const present = probes.filter((p) => hasField('Query', p.field));
    // A hit here is not a broken test: the platform grew a backing. Move the
    // item IN via docs/04's M24 scope; do not delete the probe.
    expect(present).toEqual([]);
    expect(probes.length).toBeGreaterThan(3);
  });

  it('keeps "outstanding tasks" OUT because the only task read is case-scoped', () => {
    // The boundary this reason decides: estateTasks EXISTS, and requires a
    // settlement case. An owner-scoped task query would flip the decision.
    const tasks = fieldOf('Query', 'estateTasks');
    if (!tasks) {
      throw new Error('Query.estateTasks has left the SDL — rescope "outstanding tasks"');
    }
    const caseArg = (tasks.arguments ?? []).find((a) => a.name.value === 'caseId');
    if (!caseArg) {
      throw new Error('estateTasks lost its caseId argument — it may now be owner-scoped');
    }
    expect(caseArg.type.kind).toBe(Kind.NON_NULL_TYPE);
  });

  it('keeps "password health" OUT: no Query field reads as a password fact', () => {
    const query = objectType('Query');
    if (!query) {
      throw new Error('no Query type in the SDL');
    }
    const passwordish = (query.fields ?? [])
      .map((f) => f.name.value)
      .filter((name) => /password/i.test(name));
    expect(passwordish).toEqual([]);
  });

  it('is reading a real schema (controls: the lookup can find and can fail)', () => {
    const query = objectType('Query');
    expect(query?.fields?.length ?? 0).toBeGreaterThan(30);
    // Positive control through the same helper every assertion uses…
    expect(hasField('Query', 'netWorth')).toBe(true);
    expect(hasField('NetWorth', 'inTrustValue')).toBe(true);
    // …and the negative control that proves the helper CAN answer false.
    expect(hasField('Query', 'definitelyNotAField')).toBe(false);
    expect(hasField('NotAType', 'netWorth')).toBe(false);
  });
});
