/**
 * WHAT A PERMISSION GRANT ACTUALLY CONFERS — declared as data, because until
 * now it was declared nowhere and the answer was "much less than the product
 * said".
 *
 * `permission_grants` accepted any lowercase token as a `resource` and one of
 * three actions, recorded the row, listed it back to the owner as an allowance
 * and audited it as `permission.granted`. Exactly ONE pair is read by anything:
 * `effectiveContactReadGrants` — profile's only grant reader, feeding the
 * docs/03 §5.5 ABAC contact boundary — filters `pg.resource = 'contact' AND
 * pg.action = 'read'` and nothing else. Every other pair was inert. MEASURED
 * against real Postgres over the six combinations the people surface offered:
 * one conferred access, five conferred nothing, and two of those five were
 * buttons a user could press.
 *
 * That is worse than a refusal. A refused grant is visible; an accepted one
 * that confers nothing tells an owner they have shared their assets with their
 * executor when they have not, and the only way to find out is to notice that
 * nothing happened. So the API refuses what it cannot honour (the M15 PR4 rule:
 * failing closed here means refusing to ARM, not refusing to read) and the
 * people surface stops offering it (the M12 rule: never offer what the server
 * would refuse — here, never offer what the server would ACCEPT and then not
 * honour, which is the same rule with a sharper edge).
 *
 * THE PAIR IS THE UNIT, not the two fields independently. `contact` is
 * enforced and `read` is enforced, and `contact`+`download` is not — so a zod
 * enum per field could never express this, which is why the check lives in the
 * service rather than in `PermissionGrantSchema`. The schema still owns SHAPE,
 * so a malformed body stays an ordinary 400 and an unenforced pair gets its own
 * refusal.
 *
 * ADDING A ROW HERE IS A CLAIM THAT SOMETHING ENFORCES IT, and
 * `test/enforced-grants.spec.ts` checks that claim against the reader's own SQL
 * in both directions. A new enforced resource therefore arrives in the same
 * change as the code that reads it — the credential-graph rule ("in the same
 * change as the callers") applied to authorization data.
 *
 * DELIBERATELY NOT A DDL CHECK. `permission_grants` is docs/02 §2 verbatim and
 * migrations are append-only, so narrowing the column would need a pre-flight
 * over rows written before the vocabulary closed — and those rows are inert by
 * construction, which is the whole finding. The API is the enforcement point;
 * the column keeps its shape, and the reader keeps ignoring anything else.
 */

/** One (resource, action) pair that some code path actually honours. */
export interface EnforcedGrant {
  readonly resource: string;
  readonly action: string;
  /** What reads it. Which pairs exist is derivable; why each is here is not. */
  readonly because: string;
}

export const ENFORCED_GRANTS: readonly EnforcedGrant[] = [
  {
    resource: 'contact',
    action: 'read',
    because:
      'RolesRepo.effectiveContactReadGrants resolves it into the grantee set the ' +
      'Cedar PEP is handed, so a linked contact holding it reads the owner’s ' +
      'contacts and family (docs/03 §5.5). The one grant in the product that ' +
      'does anything.',
  },
];

/** True when some code path honours this pair. Nothing else may be written. */
export function isEnforcedGrant(resource: string, action: string): boolean {
  return ENFORCED_GRANTS.some((g) => g.resource === resource && g.action === action);
}
