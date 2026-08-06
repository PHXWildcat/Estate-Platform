'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import { gqlRequest, type PermissionGrantInfo, type RoleAssignmentInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import {
  conditionLabel,
  conditionMeaning,
  roleLabel,
  EFFECTIVE_CONDITIONS,
  ROLES,
} from '../lib/people';
import type { StepUpRetryOutcome } from '../lib/step-up';
import { FormStatus } from './FormStatus';
import { StepUpPrompt } from './StepUpPrompt';

/**
 * Naming someone to a role, and choosing what that role may read (M13 PR2).
 *
 * THE ASYMMETRY IS THE DESIGN, and it is three-way here rather than the consent
 * surface's two.
 *
 *  - NAMING a fiduciary is step-up gated (docs/01 §5: "trustee/executor changes,
 *    beneficiary changes"), so the code prompt appears when the server says so
 *    and the same action is retried.
 *  - RETIRING one is ALSO gated, which is not a contradiction of the rule that
 *    protective actions stay easy: revoking here destroys the executor-resolution
 *    path settlement depends on and can strip the last linked contact able to
 *    report a death, so it is not purely protective. Equal, never harder.
 *  - WITHDRAWING A PERMISSION is one click with no challenge. That one only ever
 *    narrows, so the M6 rule applies in full.
 *
 * A DESIGNATION IS NOT ACCESS, and this component says so out loud rather than
 * leaving it to be assumed. A role with `on_death_verified` reads like an armed
 * switch; it confers nothing until a death is reported, reviewed by a person,
 * survives a waiting period and is separately confirmed. And even an `immediate`
 * role reads nothing until a permission below is granted — which is why the
 * permissions sit inside the role rather than on a page of their own.
 */

export interface RoleControlsProps {
  contactId: string;
  contactName: string;
  /**
   * Whether this person has a platform account, or NULL for "we do not know"
   * (the read that would have told us failed). Three values, because saying "no
   * account yet" on the strength of a failed request is a claim about someone's
   * estate, and this one decides whether a designation can ever be exercised.
   */
  linked: boolean | null;
}

/** What a role may be granted over. One entry per resource the platform has. */
const RESOURCES: ReadonlyArray<{ resource: string; label: string; description: string }> = [
  {
    resource: 'contact',
    label: 'Your estate contacts',
    description: 'The other people your plan names, and their contact details.',
  },
  {
    resource: 'asset',
    label: 'Your assets',
    description: 'What you own, what it is worth, and who is named on it.',
  },
  {
    resource: 'document',
    label: 'Your documents',
    description: 'Which documents exist and, with download, their contents.',
  },
];

const ACTIONS: ReadonlyArray<{ action: string; label: string }> = [
  { action: 'read', label: 'Read' },
  { action: 'download', label: 'Read and download' },
];

/**
 * The action a step-up is being collected FOR — carried in full, because the
 * prompt's whole contract is that it retries THE ACTION THAT WAS REFUSED.
 *
 * The M13 review found the permission-widen path folding into `{kind:'grant'}`,
 * the role-grant variant: after a genuine TOTP challenge the app then ran
 * `grantRole()` from the picker's current state, writing an executor designation
 * the owner never chose onto the settlement/§5.1 executor-resolution chain, and
 * silently dropping the permission they had actually clicked. A discriminated
 * union that carries every argument the retry needs is what makes that class of
 * mix-up unrepresentable rather than merely absent.
 */
type PendingStepUp =
  | { kind: 'grantRole' }
  | { kind: 'revokeRole'; roleAssignmentId: string }
  | { kind: 'grantPermission'; roleAssignmentId: string; resource: string; action: string }
  | null;

/** TOTAL over the union, so a new pending action cannot inherit another's words. */
const STEP_UP_HINT: Record<NonNullable<PendingStepUp>['kind'], string> = {
  grantRole:
    'Naming someone to a role in your estate needs a fresh check. Enter the six-digit code from your authenticator.',
  revokeRole:
    'Removing a role needs a fresh check too — it takes away an executor’s route into your estate, so it is protected the same way naming one is.',
  grantPermission:
    'Allowing a role to read part of your estate needs a fresh check. Enter the six-digit code from your authenticator — we will then apply exactly the permission you chose.',
};

const STEP_UP_LABEL: Record<NonNullable<PendingStepUp>['kind'], string> = {
  grantRole: 'Confirm and save',
  revokeRole: 'Confirm and remove',
  grantPermission: 'Confirm and allow',
};

export function RoleControls({ contactId, contactName, linked }: RoleControlsProps): ReactElement {
  const [roles, setRoles] = useState<RoleAssignmentInfo[] | null>(null);
  const [permissions, setPermissions] = useState<Record<string, PermissionGrantInfo[]>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stepUp, setStepUp] = useState<PendingStepUp>(null);
  const [role, setRole] = useState<string>('executor');
  const [condition, setCondition] = useState<string>('on_death_verified');

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('RoleAssignments', {});
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    setRoles(result.data.roleAssignments.filter((entry) => entry.contactId === contactId));
  }, [contactId]);

  useEffect(() => {
    void load();
  }, [load]);

  /** Permissions are fetched per role, and only for the roles on this page. */
  const loadPermissions = useCallback(async (roleAssignmentId: string): Promise<void> => {
    const result = await gqlRequest('RolePermissions', { roleAssignmentId });
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    setPermissions((current) => ({ ...current, [roleAssignmentId]: result.data.rolePermissions }));
  }, []);

  useEffect(() => {
    for (const entry of roles ?? []) {
      void loadPermissions(entry.id);
    }
  }, [roles, loadPermissions]);

  function applyRoles(next: RoleAssignmentInfo[]): void {
    setRoles(next.filter((entry) => entry.contactId === contactId));
  }

  async function grantRole(): Promise<StepUpRetryOutcome> {
    setError(null);
    setBusy(true);
    const result = await gqlRequest('GrantRole', {
      contactId,
      role,
      scopeType: 'estate',
      effectiveCondition: condition,
    });
    setBusy(false);
    if (result.ok) {
      setStepUp(null);
      applyRoles(result.data.grantRole);
      return 'applied';
    }
    if (result.code === 'STEPUP_REQUIRED') {
      setStepUp({ kind: 'grantRole' });
      // 'stale' so an OPEN prompt keeps retrying while the peer's session cache
      // expires; the first refusal (no prompt yet) simply opens one.
      return 'stale';
    }
    setError(messageFor(result.code));
    return 'applied';
  }

  async function revokeRole(roleAssignmentId: string): Promise<StepUpRetryOutcome> {
    setError(null);
    setBusy(true);
    const result = await gqlRequest('RevokeRole', { roleAssignmentId });
    setBusy(false);
    if (result.ok) {
      setStepUp(null);
      applyRoles(result.data.revokeRole);
      return 'applied';
    }
    if (result.code === 'STEPUP_REQUIRED') {
      setStepUp({ kind: 'revokeRole', roleAssignmentId });
      return 'stale';
    }
    setError(messageFor(result.code));
    return 'applied';
  }

  async function grantPermission(
    roleAssignmentId: string,
    resource: string,
    action: string,
  ): Promise<StepUpRetryOutcome> {
    setError(null);
    const result = await gqlRequest('GrantRolePermission', {
      roleAssignmentId,
      resource,
      action,
    });
    if (result.ok) {
      setStepUp(null);
      setPermissions((current) => ({
        ...current,
        [roleAssignmentId]: result.data.grantRolePermission,
      }));
      return 'applied';
    }
    if (result.code === 'STEPUP_REQUIRED') {
      // Widening a grant is gated like naming a role — but the RETRY must be
      // this permission, not a role. Carry every argument it needs.
      setStepUp({ kind: 'grantPermission', roleAssignmentId, resource, action });
      return 'stale';
    }
    setError(messageFor(result.code));
    return 'applied';
  }

  async function revokePermission(roleAssignmentId: string, grantId: string): Promise<void> {
    setError(null);
    const result = await gqlRequest('RevokeRolePermission', { roleAssignmentId, grantId });
    if (result.ok) {
      setPermissions((current) => ({
        ...current,
        [roleAssignmentId]: result.data.revokeRolePermission,
      }));
      return;
    }
    setError(messageFor(result.code));
  }

  if (roles === null) {
    return (
      <section aria-labelledby="roles-heading" className="card p-6">
        <h2 id="roles-heading" className="text-lg font-semibold">
          Their role in your estate
        </h2>
        <p className="mt-2 text-sm text-ink-muted">Loading…</p>
        <FormStatus tone="error" message={error} />
      </section>
    );
  }

  return (
    <section aria-labelledby="roles-heading" className="card p-6">
      <h2 id="roles-heading" className="text-lg font-semibold">
        Their role in your estate
      </h2>
      <p className="mt-1 max-w-prose text-sm text-ink-muted">
        Naming someone records your intent. It grants no access on its own — you choose that
        separately, under each role.
      </p>

      {linked === false ? (
        <p className="mt-3 max-w-prose rounded-[var(--radius-card)] border border-line p-3 text-[0.8125rem] text-ink-muted">
          {contactName} does not have an account on this platform yet, so nothing you grant below
          can be used by them. Their designation is still recorded.
        </p>
      ) : null}

      {roles.length === 0 ? (
        <p className="mt-4 text-sm text-ink-muted">No role recorded for {contactName} yet.</p>
      ) : (
        /* Named so it is distinguishable from the role picker below, both to a
           screen reader and to a test: the same role words appear in both. */
        <ul aria-label="Roles held" className="mt-4">
          {roles.map((entry) => {
            const grants = permissions[entry.id] ?? [];
            return (
              <li key={entry.id} className="border-b border-line py-4 last:border-b-0">
                <div className="flex flex-wrap items-start justify-between gap-3 sm:flex-nowrap">
                  <div className="min-w-0 max-w-prose flex-1">
                    <p className="text-sm font-medium">
                      {roleLabel(entry.role)}
                      <span className="chip ml-2">{conditionLabel(entry.effectiveCondition)}</span>
                    </p>
                    <p className="mt-1 text-[0.8125rem] text-ink-muted">
                      {conditionMeaning(entry.effectiveCondition)}
                    </p>
                  </div>
                  <button
                    type="button"
                    className="btn btn-secondary shrink-0"
                    disabled={busy}
                    onClick={() => {
                      void revokeRole(entry.id);
                    }}
                  >
                    Remove role
                  </button>
                </div>

                <div className="mt-3 rounded-[var(--radius-card)] border border-line p-3">
                  <p className="text-[0.8125rem] font-medium">What this role may read</p>
                  {grants.length === 0 ? (
                    <p className="mt-1 text-[0.8125rem] text-ink-muted">
                      Nothing yet. Without a permission here, this role reads none of your estate.
                    </p>
                  ) : (
                    <ul className="mt-2">
                      {grants.map((grant) => (
                        <li
                          key={grant.id}
                          className="flex flex-wrap items-center justify-between gap-2 py-1.5"
                        >
                          <span className="text-[0.8125rem]">
                            {RESOURCES.find((r) => r.resource === grant.resource)?.label ??
                              grant.resource}{' '}
                            —{' '}
                            {ACTIONS.find((a) => a.action === grant.action)?.label ?? grant.action}
                          </span>
                          {/*
                           * No step-up, no confirmation dialog: narrowing what
                           * someone may read must never be harder than widening
                           * it (the M6 rule).
                           */}
                          <button
                            type="button"
                            className="btn btn-secondary"
                            onClick={() => {
                              void revokePermission(entry.id, grant.id);
                            }}
                          >
                            Remove
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                  <div className="mt-2 flex flex-wrap gap-2">
                    {RESOURCES.filter(
                      (resource) => !grants.some((grant) => grant.resource === resource.resource),
                    ).map((resource) => (
                      <button
                        key={resource.resource}
                        type="button"
                        className="btn btn-secondary"
                        onClick={() => {
                          void grantPermission(entry.id, resource.resource, 'read');
                        }}
                      >
                        Allow: {resource.label}
                      </button>
                    ))}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <div className="mt-4 rounded-[var(--radius-card)] border border-line p-4">
        <p className="text-sm font-medium">Name {contactName} to a role</p>
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          <div>
            <label className="field-label" htmlFor="role-select">
              Role
            </label>
            <select
              id="role-select"
              className="field-input mt-1"
              value={role}
              onChange={(event) => {
                setRole(event.target.value);
              }}
            >
              {ROLES.map((token) => (
                <option key={token} value={token}>
                  {roleLabel(token)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="field-label" htmlFor="condition-select">
              When it applies
            </label>
            <select
              id="condition-select"
              className="field-input mt-1"
              value={condition}
              onChange={(event) => {
                setCondition(event.target.value);
              }}
            >
              {EFFECTIVE_CONDITIONS.map((token) => (
                <option key={token} value={token}>
                  {conditionLabel(token)}
                </option>
              ))}
            </select>
          </div>
        </div>
        <p className="field-hint mt-2 max-w-prose">{conditionMeaning(condition)}</p>
        <div className="mt-3">
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy}
            onClick={() => {
              void grantRole();
            }}
          >
            {busy ? 'Saving…' : 'Name to this role'}
          </button>
        </div>
      </div>

      {stepUp !== null ? (
        <StepUpPrompt
          idPrefix="role-stepup"
          /*
           * The wording follows the ACTION, because this prompt is where someone
           * consents to it: a hint about role changes over a retry that widens a
           * permission would be the ceremony mis-stating what it authorizes.
           */
          hint={STEP_UP_HINT[stepUp.kind]}
          submitLabel={STEP_UP_LABEL[stepUp.kind]}
          onElevated={() => {
            if (stepUp.kind === 'grantRole') {
              return grantRole();
            }
            if (stepUp.kind === 'revokeRole') {
              return revokeRole(stepUp.roleAssignmentId);
            }
            return grantPermission(stepUp.roleAssignmentId, stepUp.resource, stepUp.action);
          }}
          onCancel={() => {
            setStepUp(null);
          }}
        />
      ) : null}

      <FormStatus tone="error" message={error} />
    </section>
  );
}
