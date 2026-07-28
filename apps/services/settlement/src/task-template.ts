/**
 * The estate task checklist, generated once when a case reaches `verified`.
 *
 * In-repo and versioned like code — the docs/04 template-matrix precedent.
 * These are procedural prompts for an executor, NOT legal advice and NOT
 * jurisdiction-specific guidance: every entry is a generic administration step
 * whose specifics belong to the estate's attorney. A per-state matrix under
 * attorney review is a later milestone; anchoring on that here would imply a
 * legal-sign-off gate this checklist has not been through.
 *
 * Titles are template constants (never user input), so they are stored
 * plaintext like `assets_view.title`.
 *
 * `dueDays` is an offset from the VERIFICATION date. docs/03 §5.1 deliberately
 * does not have the platform record a date of death (it is not a fact the
 * platform can observe), so the checklist dates from the moment the platform
 * itself verified — see the M7 decision-log entry.
 */

export const TASK_TEMPLATE_VERSION = 1;

export interface TaskTemplateEntry {
  readonly title: string;
  readonly category: 'legal' | 'financial' | 'administrative' | 'notification';
  /** Which role_assignments role this step is aimed at. */
  readonly assignedRole: 'executor' | 'attorney' | 'cpa';
  /** Days after verification the step is due; null = no fixed due date. */
  readonly dueDays: number | null;
}

export const ESTATE_TASK_TEMPLATE: readonly TaskTemplateEntry[] = [
  {
    title: 'Obtain certified copies of the death certificate',
    category: 'legal',
    assignedRole: 'executor',
    dueDays: 14,
  },
  {
    title: 'Locate the original will and any codicils',
    category: 'legal',
    assignedRole: 'executor',
    dueDays: 14,
  },
  {
    title: 'Consult the estate attorney about opening probate',
    category: 'legal',
    assignedRole: 'attorney',
    dueDays: 30,
  },
  {
    title: 'File for letters testamentary and upload them to the case',
    category: 'legal',
    assignedRole: 'executor',
    dueDays: 45,
  },
  {
    title: 'Review the estate inventory and confirm asset ownership records',
    category: 'financial',
    assignedRole: 'executor',
    dueDays: 45,
  },
  {
    title: 'Open an estate bank account',
    category: 'financial',
    assignedRole: 'executor',
    dueDays: 60,
  },
  {
    title: 'Notify financial institutions and insurers',
    category: 'notification',
    assignedRole: 'executor',
    dueDays: 60,
  },
  {
    title: 'Notify beneficiaries named in the estate documents',
    category: 'notification',
    assignedRole: 'executor',
    dueDays: 60,
  },
  {
    title: 'Obtain date-of-death valuations for estate assets',
    category: 'financial',
    assignedRole: 'cpa',
    dueDays: 90,
  },
  {
    title: 'Identify and settle outstanding debts and final expenses',
    category: 'financial',
    assignedRole: 'executor',
    dueDays: 120,
  },
  {
    title: 'File the final personal income tax return',
    category: 'financial',
    assignedRole: 'cpa',
    dueDays: 180,
  },
  {
    title: 'Determine whether an estate tax return is required',
    category: 'financial',
    assignedRole: 'cpa',
    dueDays: 180,
  },
  {
    title: 'Record and approve distributions to beneficiaries',
    category: 'administrative',
    assignedRole: 'executor',
    dueDays: null,
  },
  {
    title: 'Prepare the final accounting for the court',
    category: 'administrative',
    assignedRole: 'executor',
    dueDays: null,
  },
];

const DAY_MS = 24 * 60 * 60 * 1000;

/** Materialize the template against a verification instant. */
export function generateTasks(
  verifiedAt: Date,
): Array<{ title: string; category: string; assignedRole: string; dueAt: Date | null }> {
  return ESTATE_TASK_TEMPLATE.map((entry) => ({
    title: entry.title,
    category: entry.category,
    assignedRole: entry.assignedRole,
    dueAt: entry.dueDays === null ? null : new Date(verifiedAt.getTime() + entry.dueDays * DAY_MS),
  }));
}
