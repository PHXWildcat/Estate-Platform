/**
 * EVERY OPERATOR-GATED WRITE EITHER COUNTS TOWARD THE BREADTH BOUND OR IS
 * DECLARED EXEMPT WITH A REASON.
 *
 * WHY THIS EXISTS. The bound is only as good as its coverage, and coverage is
 * the thing that rots: a new operator verb ships, nobody remembers the ledger,
 * and the control silently stops describing what operators do. This repo's
 * most repeated defect is a hand-maintained list beside a thing that grows —
 * so the list is DERIVED. The corpus is every method of the two settlement
 * services whose body calls `this.gate.assertIn`, read out of the AST, and the
 * fence fails on a method it has never been told about in either direction.
 *
 * It caught its own first defect before it was finished: `review.approved` and
 * `verification.confirmed` were both members of PERMISSIVE_OPERATOR_ACTIONS
 * and neither was written by anything. Two of six declared kinds were dead.
 *
 * WHY THE AST AND NOT A GREP. `assertIn` and `record` are calls, and which
 * METHOD encloses a call is exactly the fact a line-oriented scan cannot see.
 * A grep would report both facts for the file and pair them wrongly.
 *
 * WHAT IT CANNOT SEE, stated so it is not over-read: it proves that a gated
 * method mentions the ledger, not that it records on the right ARM. The arms
 * — approve counts, deny and revoke do not — are proven by execution in
 * `admin.service.spec.ts`, and the SQL by `operator-breadth.int.spec.ts`.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as ts from 'typescript';

import { PERMISSIVE_OPERATOR_ACTIONS, PROTECTIVE_OPERATOR_ACTIONS } from '../src/operator-breadth';

const SRC = join(__dirname, '..', 'src');
const SERVICES = ['admin.service.ts', 'settlement.service.ts'] as const;

/**
 * Gated methods that deliberately do NOT count, each with the reason. A name
 * alone would be a list; the reason is the thing a reviewer checks.
 */
const EXEMPT: Readonly<Record<string, string>> = {
  'admin.service.ts#revokeStage':
    'PROTECTIVE. Withdrawing an executor’s access must never be the thing an ' +
    'operator runs out of budget for — that is the design rule the whole ' +
    'bound is subordinate to.',
  'settlement.service.ts#queue':
    'READ. The worklist emits its own `worklist.viewed`; breadth is about acting ' +
    'on estates, not about seeing which need acting on.',
  'settlement.service.ts#administrable':
    'READ. The second operator worklist, and the same reasoning as `queue`: it ' +
    'reports which estates are in administration and changes none of them.',
  'settlement.service.ts#reportProviderSignal':
    'INTAKE, and a KNOWN GAP rather than a clean exemption. An operator opening ' +
    'cases across many estates is squarely the pattern this bound is for, but ' +
    'this route owns no transaction — `insertCase` opens its own, shared with ' +
    'the non-operator contact path — and a ledger row written after that commit ' +
    'can be lost while the case stands, which under-counts. Under-counting is the ' +
    'fail-open direction, so it is recorded as a residual (docs/03 §6ff) rather ' +
    'than closed badly. Intake breadth is meanwhile visible in the trail: ' +
    '`case.reported` carries the operator-actor flag.',
};

interface Gated {
  readonly key: string;
  readonly records: boolean;
}

function gatedMethods(): Gated[] {
  const found: Gated[] = [];
  for (const file of SERVICES) {
    const text = readFileSync(join(SRC, file), 'utf8');
    const parsed = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const visit = (node: ts.Node): void => {
      if (ts.isMethodDeclaration(node) && node.name) {
        const body = node.getText(parsed);
        if (/this\.gate\.assertIn\s*\(/.test(body)) {
          found.push({
            key: `${file}#${node.name.getText(parsed)}`,
            records: /this\.breadth\.record\s*\(/.test(body),
          });
        }
      }
      node.forEachChild(visit);
    };
    visit(parsed);
  }
  return found;
}

describe('the breadth bound covers every operator-gated write', () => {
  const gated = gatedMethods();

  it('finds the corpus it claims to scan', () => {
    // ANTI-VACUITY, at the level and not only the total: a parse that silently
    // returned nothing would satisfy every assertion below. Both files must
    // contribute, because a scan that lost one of them looks identical to one
    // where that file simply has no gated verbs.
    expect(gated.length).toBeGreaterThanOrEqual(10);
    for (const file of SERVICES) {
      expect(gated.filter((g) => g.key.startsWith(`${file}#`)).length).toBeGreaterThan(0);
    }
  });

  it('leaves no gated method both uncounted and undeclared', () => {
    const orphans = gated.filter((g) => !g.records && EXEMPT[g.key] === undefined);
    expect(orphans.map((g) => g.key)).toEqual([]);
  });

  it('declares no exemption for a method that does not exist', () => {
    // The other direction: an exemption outliving its method is how a list
    // stops describing the tree while still reading as deliberate.
    const keys = new Set(gated.map((g) => g.key));
    expect(Object.keys(EXEMPT).filter((k) => !keys.has(k))).toEqual([]);
  });

  it('declares no exemption for a method that DOES count', () => {
    // A stale exemption beside a verb that was later wired up reads as a
    // sanctioned hole in a control that no longer has one.
    const counting = new Set(gated.filter((g) => g.records).map((g) => g.key));
    expect(Object.keys(EXEMPT).filter((k) => counting.has(k))).toEqual([]);
  });

  it('gives every exemption a reason, not just a name', () => {
    const terse = Object.entries(EXEMPT)
      .filter(([, reason]) => reason.length < 40)
      .map(([key]) => key);
    expect(terse).toEqual([]);
  });

  it('writes every declared permissive kind somewhere, and no protective one', () => {
    // The SETS, not the counts. Two of these six kinds were declared and dead
    // when this fence was written, and a total would not have shown it.
    const sources = SERVICES.map((f) => readFileSync(join(SRC, f), 'utf8')).join('\n');
    const written = (kind: string): boolean =>
      new RegExp(`record\\([^)]*'${kind.replace('.', '\\.')}'`, 's').test(sources);
    expect(PERMISSIVE_OPERATOR_ACTIONS.filter((k) => !written(k))).toEqual([]);
    expect(PROTECTIVE_OPERATOR_ACTIONS.filter((k) => written(k))).toEqual([]);
  });
});
