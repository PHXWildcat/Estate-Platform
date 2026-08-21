import type { SettlementCaseInfo } from '../graphql/client';

/**
 * How a settlement case is DESCRIBED to the person it concerns (M22 PR3).
 *
 * This file exists because the obvious rendering is wrong, and wrong in a way
 * that would land on the worst possible reader.
 *
 * `settlement_cases` has a DDL CHECK forcing
 * `(resolution IS NOT NULL) = (status = 'rejected_fraud')`, so BOTH terminal
 * outcomes — an operator rejecting a report, and an OWNER killing a fraudulent
 * case about themselves — leave the row with `status: 'rejected_fraud'`. A
 * surface that prints `status` therefore tells someone who has just used a
 * protective control that fraud was found against them. `resolution` is the
 * field that distinguishes the two, so resolution is read first, always.
 */

/** A case still moving: nothing has been decided and the subject can act. */
const OPEN_STATUSES = new Set(['reported', 'verifying', 'waiting_period']);

export function isOpen(settlementCase: SettlementCaseInfo): boolean {
  return OPEN_STATUSES.has(settlementCase.status);
}

/**
 * One sentence naming where a case stands, from the SUBJECT's point of view.
 *
 * Unknown statuses fall through to a deliberately vague sentence rather than
 * printing the raw token. The service's vocabulary can grow — it has twice —
 * and a surface that renders an unrecognised enum verbatim shows a person the
 * word `deceased_pending` about themselves.
 */
export function caseHeadline(settlementCase: SettlementCaseInfo): string {
  if (settlementCase.resolution === 'owner_voided') {
    return 'Closed — you confirmed you’re alive';
  }
  if (settlementCase.resolution === 'operator_rejected') {
    return 'Closed — we reviewed this and rejected it';
  }
  switch (settlementCase.status) {
    case 'reported':
      return 'Reported — waiting for our review';
    case 'verifying':
      return 'Under review by our team';
    case 'waiting_period':
      return 'In its waiting period';
    case 'verified':
    case 'active':
    case 'distributing':
    case 'closed':
      return 'Verified — your estate has been opened';
    default:
      return 'In progress';
  }
}

/** What the subject should understand about it, and what they can do. */
export function caseDetail(settlementCase: SettlementCaseInfo): string {
  if (settlementCase.resolution === 'owner_voided') {
    return 'Nothing was released, and your account is back to normal.';
  }
  if (settlementCase.resolution === 'operator_rejected') {
    return 'Nothing was released, and your account is back to normal.';
  }
  if (isOpen(settlementCase)) {
    return (
      'Nothing about your estate has been released. If you’re reading this, you can close it ' +
      'right now — that is the point of this page.'
    );
  }
  return 'If this is wrong, contact us immediately.';
}

/** How the report reached us, in words rather than the service's enum. */
export function reportSourceLabel(reportSource: string): string {
  switch (reportSource) {
    case 'trusted_contact':
      return 'Reported by someone linked to your estate';
    case 'death_certificate_upload':
      return 'Reported with a death certificate';
    case 'data_provider':
      return 'Flagged by an external records check';
    default:
      return 'Reported';
  }
}

/**
 * A CALENDAR DAY, rendered in the day it actually names.
 *
 * FOUND BY DRIVING THE APP (M23 PR3). `settlement_tasks.due_at` is a Postgres
 * `date` — a calendar day with no time and no zone — which the service widens
 * to an instant at UTC midnight before it reaches the wire. Handing that to
 * `formatDate` below renders it in the READER's zone, so a due date stored as
 * the 3rd showed as "September 2" to anyone west of UTC. Confirmed in the
 * browser at `America/Phoenix`: the wire said `2026-09-03T00:00:00.000Z` and
 * the screen said September 2.
 *
 * `formatDate` is NOT changed to match. The two functions answer different
 * questions and both answers are right: `verifiedAt` and `waitingPeriodEnds`
 * are genuine instants, and a reader in Phoenix should see those in Phoenix
 * time. A calendar day has no instant to convert.
 */
export function formatCalendarDate(iso: string | null): string | null {
  const parsed = iso === null ? Number.NaN : Date.parse(iso);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return new Date(parsed).toLocaleDateString(undefined, {
    timeZone: 'UTC',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

/** A wire timestamp as a plain date, or null when it is absent or unparseable. */
export function formatDate(iso: string | null): string | null {
  if (iso === null) {
    return null;
  }
  const parsed = Date.parse(iso);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return new Date(parsed).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}
