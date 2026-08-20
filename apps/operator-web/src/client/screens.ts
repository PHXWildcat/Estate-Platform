/**
 * THE CONSOLE'S SCREENS: two worklists, and one case.
 *
 * Every node is built through `dom.ts`, which has no way to parse markup — the
 * absence is what makes this origin's `trusted-types 'none'` policy
 * enforceable, and it matters more here than anywhere else in the product
 * because the strings on these screens are REPORTER-SUPPLIED and
 * PROVIDER-SUPPLIED: a case's evidence, a timeline entry's detail. Untrusted
 * input on the screen somebody reads before authorizing a lock on a living
 * person's account.
 *
 * WHAT THE SCREENS DELIBERATELY DO NOT SHOW is a name. Settlement returns user
 * IDs and enum tokens and nothing else — the PII firewall — so this console
 * shows the decedent as an opaque id. That is not a gap to fill later by
 * joining against profile: an operator surface that resolved names would put
 * the estate's people in the lowest-trust screen in the product, and the whole
 * reason a death case can be worked at all is that it does not require them.
 *
 * THE STATUS VOCABULARY IS SETTLEMENT'S OWN, rendered as a sentence rather
 * than as the DDL's word. `configured` on somebody's screen is the M15 PR3
 * lesson: a fixture that invents an enum tests the fixture, and a screen that
 * shows a column value tells a person about the schema instead of about their
 * case.
 */
import type { ApiFailure } from './api.js';
import { el, onClick } from './dom.js';
import type { CaseSummary, DistributionView, StageView, TimelineEvent } from './settlement.js';

/**
 * What went wrong, in the operator's vocabulary rather than the wire's.
 *
 * `FORBIDDEN` carries the most important sentence on this console. Minting an
 * operator handoff is ROLE-BLIND by design — any signed-in account can reach
 * this origin — so the first thing a non-operator sees is this refusal, and it
 * has to explain the model rather than say "forbidden". `NOT_FOUND` is the
 * uniform answer settlement gives for a case that does not exist AND for one
 * this caller may not see (M21 PR2 closed that oracle), so the copy must not
 * imply the id named something real.
 */
export function messageFor(code: ApiFailure): string {
  switch (code) {
    case 'UNAUTHENTICATED':
      /*
       * A 401 FROM SETTLEMENT, not from the session read — `render()` handles
       * that one by showing the signed-out screen. Reaching this branch means
       * identity still recognised the credential a moment ago and settlement
       * did not: the session expired in between (this origin's lasts 15
       * minutes and CANNOT be renewed, there being no refresh token for it by
       * construction), or it is not a credential settlement accepts at all.
       * Both have the same remedy and it is not "try again".
       *
       * It had no sentence of its own until the copy fence asked for one, and
       * fell through to "something went wrong" — an expired credential reading
       * as a fault, which is the M9 rule in the direction that wastes somebody's
       * time on a case they were told they could work.
       */
      return 'Your console session has ended, or is not accepted here. Open the operator console from Estate again.';
    case 'NETWORK':
      return 'We could not reach Estate just now. Your session has not ended — try again in a moment.';
    case 'UNAVAILABLE':
      // BOTH halves, because this one code reaches two surfaces. On a session
      // read the fact that matters is that the credential survives an outage
      // (M16 PR2a — an outage must not wear the face of a revocation); on an
      // action it is that nothing was committed. Saying only one leaves the
      // other surface reading a sentence that answers a question nobody asked.
      return 'Estate is not answering just now. Your session has not ended and nothing was changed — try again in a moment.';
    case 'TOO_MANY_ATTEMPTS':
      return 'Too many attempts. Wait a few minutes and try again.';
    case 'FORBIDDEN':
      return 'This account is not on the settlement operator list, so it cannot work cases. Reaching this console does not grant that — an operator is added by the platform team, not by signing in here.';
    case 'NOT_FOUND':
      return 'No case is available to you under that reference.';
    case 'OWNER_ALIVE':
      return 'This case has been voided: the account holder confirmed their identity, which is the check that stops a settlement from proceeding. Nothing further can be done on it.';
    case 'SEPARATION_OF_DUTIES':
      return 'A different operator has to take this step. The person who reported or requested it cannot also be the one who approves it.';
    case 'STATE_CHANGED':
      return 'This case has moved on since the page was loaded. Reload it and look again before deciding anything.';
    case 'CONFLICT':
      return 'That step is not available on this case right now. Reload it and look again.';
    case 'STEPUP_REQUIRED':
      return 'That step needs a fresh identity check.';
    case 'INVALID_REQUEST':
      return 'That request was not accepted. Reload the case and try again.';
    default:
      return 'Something went wrong. Try again in a moment.';
  }
}

const CASE_STATUS: Readonly<Record<string, string>> = {
  reported: 'Reported — waiting for an operator to pick it up',
  verifying: 'Under review',
  waiting_period: 'Waiting period running',
  verified: 'Verified',
  active: 'Settlement in progress',
  distributing: 'Distributing',
  closed: 'Closed',
  rejected: 'Rejected at review',
  disputed: 'Disputed',
  voided: 'Voided',
};

const STAGE_STATUS: Readonly<Record<string, string>> = {
  requested: 'Requested',
  approved: 'Approved',
  denied: 'Denied',
  revoked: 'Revoked',
};

const STAGE_NAME: Readonly<Record<string, string>> = {
  inventory: 'Inventory',
  documents: 'Documents',
  vault: 'Vault (Zone A)',
};

/**
 * An unknown token renders as ITSELF rather than as a blank or a guess. A
 * service deployed ahead of this client must not blank a worklist row — the
 * M10 PR4 rule — and the raw token is at least true.
 */
function label(table: Readonly<Record<string, string>>, token: string): string {
  return table[token] ?? token;
}

/** ISO instants, shown as they arrived. No locale guessing on an audit surface. */
function when(value: string | null): string {
  return value ?? '—';
}

export function statusLabel(status: string): string {
  return label(CASE_STATUS, status);
}

function fact(term: string, value: string): readonly Node[] {
  return [el('dt', {}, [term]), el('dd', {}, [value])];
}

export interface WorklistOptions {
  readonly title: string;
  readonly empty: string;
  readonly cases: readonly CaseSummary[];
  readonly onOpen: (caseId: string) => void;
}

export function worklist(options: WorklistOptions): HTMLElement {
  const rows = options.cases.map((kase) => {
    const open = el('button', { type: 'button', class: 'button' }, ['Open']);
    onClick(open, () => {
      options.onOpen(kase.caseId);
    });
    return el('li', { class: 'row' }, [
      el('dl', { class: 'facts' }, [
        ...fact('Case', kase.caseId),
        ...fact('Status', statusLabel(kase.status)),
        ...fact('Account', kase.decedentUserId),
        ...fact('Reported', when(kase.createdAt)),
        // "Taken" and "approved by" are different facts and are shown as two.
        ...fact('Taken by', kase.claimedBy ?? 'Nobody yet'),
        ...(kase.waitingPeriodEnds === null
          ? []
          : fact(
              'Waiting period ends',
              kase.eligibleForVerification
                ? `${kase.waitingPeriodEnds} — lapsed, ready to confirm`
                : kase.waitingPeriodEnds,
            )),
      ]),
      el('p', { class: 'actions' }, [open]),
    ]);
  });
  return el('section', { class: 'panel' }, [
    el('h2', { class: 'heading' }, [options.title]),
    rows.length === 0
      ? el('p', { class: 'lede' }, [options.empty])
      : el('ul', { class: 'list' }, rows),
  ]);
}

export interface CaseScreenOptions {
  readonly kase: CaseSummary;
  readonly timeline: readonly TimelineEvent[];
  readonly stages: readonly StageView[];
  readonly distributions: readonly DistributionView[];
  readonly actions: readonly HTMLElement[];
  /**
   * Per-row controls, supplied by the caller rather than decided here.
   *
   * WHICH verbs are offered is a function of the case's status and of what
   * settlement would accept, and the screen deliberately does not reimplement
   * that: it renders what it is handed. Never offering what the server would
   * refuse is the M12 rule; deciding it in two places is how the two answers
   * start to disagree.
   */
  readonly stageActions: (stage: StageView) => readonly HTMLElement[];
  readonly distributionActions: (distribution: DistributionView) => readonly HTMLElement[];
  readonly notice: string | null;
  readonly prompt: HTMLElement | null;
  readonly onBack: () => void;
}

export function caseScreen(options: CaseScreenOptions): readonly Node[] {
  const { kase } = options;
  const back = el('button', { type: 'button', class: 'button', id: 'back' }, ['Back to worklists']);
  onClick(back, options.onBack);

  const stageRows = options.stages.map((stage) => {
    // Built ONCE. Calling the slot twice — once to test it and once to render
    // it — would mount a second set of buttons and throw the first away, which
    // is harmless until a slot ever does anything but construct nodes.
    const controls = options.stageActions(stage);
    return el('li', { class: 'row' }, [
      el('dl', { class: 'facts' }, [
        ...fact('Stage', label(STAGE_NAME, stage.stage)),
        ...fact('Status', label(STAGE_STATUS, stage.status)),
        ...fact('Requested by', stage.requestedBy),
        ...fact('Requested', when(stage.requestedAt)),
        ...fact('Decided by', stage.decidedBy ?? '—'),
      ]),
      ...(controls.length > 0 ? [el('p', { class: 'actions' }, controls)] : []),
    ]);
  });

  const distributionRows = options.distributions.map((distribution) => {
    const controls = options.distributionActions(distribution);
    return el('li', { class: 'row' }, [
      el('dl', { class: 'facts' }, [
        ...fact('Beneficiary contact', distribution.beneficiaryContactId),
        ...fact('Asset', distribution.assetId ?? 'Not tied to one asset'),
        ...fact('Status', distribution.status),
        ...fact('Recorded by', distribution.createdBy),
        ...fact('Approved by', distribution.approvedBy ?? 'Not approved'),
        // The AMOUNT is never returned by settlement — recording is write-only
        // under its own KEK. Saying "an amount is recorded" is the whole truth
        // this console has, and inventing a placeholder figure would be worse.
        ...fact(
          'Amount',
          distribution.hasAmount ? 'Recorded (not readable here)' : 'None recorded',
        ),
      ]),
      ...(controls.length > 0 ? [el('p', { class: 'actions' }, controls)] : []),
    ]);
  });

  const timelineRows = options.timeline.map((event) =>
    el('li', { class: 'row' }, [
      el('dl', { class: 'facts' }, [
        ...fact('When', event.at),
        ...fact('What', event.kind),
        ...Object.entries(event.detail).flatMap(([key, value]) => fact(key, value)),
      ]),
    ]),
  );

  return [
    el('h1', { class: 'title' }, ['Settlement case']),
    ...(options.notice ? [el('p', { class: 'notice', role: 'alert' }, [options.notice])] : []),
    el('dl', { class: 'facts' }, [
      ...fact('Case', kase.caseId),
      ...fact('Status', statusLabel(kase.status)),
      ...fact('Account', kase.decedentUserId),
      ...fact('Report source', kase.reportSource),
      ...fact('Reported by', kase.reportedBy),
      ...fact('Reported', when(kase.createdAt)),
      ...fact('Taken by', kase.claimedBy ?? 'Nobody yet'),
      ...fact('Review approved by', kase.humanReviewBy ?? '—'),
      ...fact('Waiting period ends', when(kase.waitingPeriodEnds)),
      ...fact('Verified', when(kase.verifiedAt)),
      ...fact('Resolution', kase.resolution ?? '—'),
    ]),
    ...(options.prompt ? [options.prompt] : []),
    ...(options.actions.length > 0 ? [el('p', { class: 'actions' }, options.actions)] : []),
    el('section', { class: 'panel' }, [
      el('h2', { class: 'heading' }, ['Staged access']),
      stageRows.length === 0
        ? el('p', { class: 'lede' }, ['No stage has been requested on this case.'])
        : el('ul', { class: 'list' }, stageRows),
    ]),
    el('section', { class: 'panel' }, [
      el('h2', { class: 'heading' }, ['Distributions']),
      distributionRows.length === 0
        ? el('p', { class: 'lede' }, ['Nothing has been recorded for distribution.'])
        : el('ul', { class: 'list' }, distributionRows),
    ]),
    el('section', { class: 'panel' }, [
      el('h2', { class: 'heading' }, ['Timeline']),
      timelineRows.length === 0
        ? el('p', { class: 'lede' }, ['Nothing recorded yet.'])
        : el('ul', { class: 'list' }, timelineRows),
    ]),
    el('p', { class: 'actions' }, [back]),
  ];
}
