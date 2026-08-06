/**
 * Vocabulary for the people surface: role tokens, scope tokens, effective
 * conditions and household relations, each turned into a sentence by reviewed
 * code rather than by a model (the `findings.ts` rule).
 *
 * The maps are TOTAL over the closed unions, so adding a role token without
 * wording is a compile error — and an unknown token still renders a readable
 * fallback, because a service deployed ahead of the app must not blank a page.
 */

export const ROLES = [
  'trustee',
  'successor_trustee',
  'executor',
  'beneficiary',
  'guardian',
  'agent_financial',
  'agent_medical',
  'attorney',
  'cpa',
  'financial_advisor',
  'family_member',
  'viewer',
] as const;
export type Role = (typeof ROLES)[number];

const ROLE_LABELS: Record<Role, string> = {
  trustee: 'Trustee',
  successor_trustee: 'Successor trustee',
  executor: 'Executor',
  beneficiary: 'Beneficiary',
  guardian: 'Guardian',
  agent_financial: 'Financial power of attorney',
  agent_medical: 'Medical power of attorney',
  attorney: 'Attorney',
  cpa: 'CPA',
  financial_advisor: 'Financial advisor',
  family_member: 'Family member',
  viewer: 'Viewer',
};

export function roleLabel(role: string): string {
  return ROLE_LABELS[role as Role] ?? humanize(role);
}

export const EFFECTIVE_CONDITIONS = ['immediate', 'on_incapacity', 'on_death_verified'] as const;
export type EffectiveCondition = (typeof EFFECTIVE_CONDITIONS)[number];

/**
 * What a condition MEANS, and every one of these sentences is about access
 * rather than about intent.
 *
 * DESIGNATION ALONE GRANTS NOTHING (M7), and this is the surface where a user
 * would otherwise assume otherwise. `on_death_verified` reads like a switch that
 * is armed; it is really a record of the owner's intent that confers nothing
 * until a settlement case has been reported, reviewed by a human, survived its
 * waiting period, been separately confirmed, and had a stage approved. Saying
 * "takes effect when…" would be a promise the platform deliberately does not
 * keep on its own.
 */
const CONDITION_COPY: Record<EffectiveCondition, { label: string; meaning: string }> = {
  immediate: {
    label: 'Now',
    meaning: 'Can be used straight away — but only for what you separately allow below.',
  },
  on_incapacity: {
    label: 'On incapacity',
    meaning:
      'A record of your wishes. It grants no access today, and nothing here acts on its own.',
  },
  on_death_verified: {
    label: 'After death is verified',
    meaning:
      'A record of your wishes. It grants no access today: a death has to be reported, reviewed by a person, and confirmed after a waiting period before anything opens.',
  },
};

export function conditionLabel(condition: string): string {
  return CONDITION_COPY[condition as EffectiveCondition]?.label ?? humanize(condition);
}

export function conditionMeaning(condition: string): string {
  return (
    CONDITION_COPY[condition as EffectiveCondition]?.meaning ??
    'A record of your wishes. It grants no access on its own.'
  );
}

export const RELATIONS = ['spouse', 'child', 'parent', 'sibling', 'other'] as const;
export type Relation = (typeof RELATIONS)[number];

const RELATION_LABELS: Record<Relation, string> = {
  spouse: 'Spouse or partner',
  child: 'Child',
  parent: 'Parent',
  sibling: 'Sibling',
  other: 'Other',
};

export function relationLabel(relation: string): string {
  return RELATION_LABELS[relation as Relation] ?? humanize(relation);
}

export const PROFESSIONAL_KINDS = [
  'attorney',
  'cpa',
  'financial_advisor',
  'doctor',
  'other',
] as const;

const PROFESSIONAL_LABELS: Record<string, string> = {
  attorney: 'Attorney',
  cpa: 'CPA',
  financial_advisor: 'Financial advisor',
  doctor: 'Doctor',
  other: 'Other professional',
};

export function professionalLabel(kind: string): string {
  return PROFESSIONAL_LABELS[kind] ?? humanize(kind);
}

export const MARITAL_STATUSES = [
  'single',
  'married',
  'domestic_partnership',
  'divorced',
  'widowed',
] as const;

const MARITAL_LABELS: Record<string, string> = {
  single: 'Single',
  married: 'Married',
  domestic_partnership: 'Domestic partnership',
  divorced: 'Divorced',
  widowed: 'Widowed',
};

export function maritalLabel(status: string): string {
  return MARITAL_LABELS[status] ?? humanize(status);
}

/**
 * What is on file for a contact, without having decrypted any of it.
 *
 * Built from the summary's `has` flags — the list never fetches the values, so
 * this sentence is the whole of what a row can say about them (docs/03 §6f).
 */
export function onFileSummary(contact: {
  hasEmail: boolean;
  hasPhone: boolean;
  hasAddress: boolean;
  hasNotes: boolean;
}): string {
  const parts: string[] = [];
  if (contact.hasEmail) parts.push('email');
  if (contact.hasPhone) parts.push('phone');
  if (contact.hasAddress) parts.push('address');
  if (contact.hasNotes) parts.push('notes');
  return parts.length === 0 ? 'No contact details on file' : `On file: ${parts.join(', ')}`;
}

/** `agent_financial` → `Agent financial`. Last-resort wording for a new token. */
function humanize(token: string): string {
  const spaced = token.replace(/_/g, ' ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}
