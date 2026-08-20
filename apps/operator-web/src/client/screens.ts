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
 * THAT SENTENCE WAS AN ASPIRATION UNTIL M22 PR4b. The case screen named a
 * case's evidence as the reason for the posture and did not show any: settlement
 * has returned `evidence` on every `CaseDto` since M7, and the console's parser
 * dropped it, so the mandatory human review docs/03 §5.1 leans on was conducted
 * against a status, a timeline and two ids. The Evidence panel is the field
 * itself, and `addedBy` is on every row because "the account that reported this
 * case attached this" is the fact a reviewer most needs and could not get.
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
import type {
  CaseSummary,
  DistributionView,
  EvidenceView,
  StageView,
  TimelineEvent,
} from './settlement.js';

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
    case 'INVALID_CODE':
      /*
       * A CREDENTIAL THIS CALLER SUBMITTED WAS WRONG — split out of
       * `UNAUTHENTICATED` by M21 PR4, because 401 carried that fact and "your
       * session is gone" at once and they have opposite remedies. On this
       * surface only the step-up prompt can produce it, and `stepUpMessage` has
       * the sentence that fits a form with a code field on it; this is the
       * general fallback, so it names the fact without assuming the reader is
       * looking at that form.
       */
      return 'That was not accepted. Check what you entered and try again.';
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

/**
 * `document` and `provider_match` are settlement's whole vocabulary today, and
 * `label` renders anything else as the raw token rather than as a blank — a
 * kind this build predates must still be visible to the person reviewing.
 */
const EVIDENCE_KIND: Readonly<Record<string, string>> = {
  document: 'Document',
  provider_match: 'Death-data provider match',
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
  /*
   * NULL MEANS THE READ FAILED, and it is a different fact from an empty list.
   * The case screen makes four independent requests; before M21 PR4 a refusal
   * on any of the three lists was collapsed to `[]` by the caller and rendered
   * as "No stage has been requested on this case." — an affirmative statement
   * that nothing exists, made on the strength of not knowing. `settlement.ts`
   * states the rule one file over: a response missing its fields is NO DATA,
   * never data. It matters most on the panel it reads worst on, staged access,
   * where the thing being asserted not to exist is a request for Zone A.
   */
  readonly timeline: readonly TimelineEvent[] | null;
  readonly stages: readonly StageView[] | null;
  readonly distributions: readonly DistributionView[] | null;
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

/**
 * A section body that tells "we could not read this" apart from "there is
 * nothing here". One helper rather than three copies of a ternary: the three
 * panels were identical before and the way this regresses is one of them
 * quietly not learning about `null`.
 */
function sectionBody(read: readonly unknown[] | null, rows: readonly Node[], empty: string): Node {
  if (read === null) {
    return el('p', { class: 'notice', role: 'alert' }, [
      'This could not be loaded, so what is here may be incomplete. Reopen the case to try again.',
    ]);
  }
  return rows.length === 0
    ? el('p', { class: 'lede' }, [empty])
    : el('ul', { class: 'list' }, rows);
}

export function caseScreen(options: CaseScreenOptions): readonly Node[] {
  const { kase } = options;
  const back = el('button', { type: 'button', class: 'button', id: 'back' }, ['Back to worklists']);
  onClick(back, options.onBack);

  const stageRows = (options.stages ?? []).map((stage) => {
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

  const distributionRows = (options.distributions ?? []).map((distribution) => {
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

  /**
   * WHO ATTACHED IT, said in terms this console can actually stand behind.
   *
   * The interesting distinction to a reviewer is reporter-supplied versus
   * operator-supplied, and this origin cannot make it: it is role-BLIND by
   * construction — `settlement_operators` is read inside the transaction that
   * acts, and nothing about operator-ness is on the wire here. What IS on the
   * wire is the case's `reportedBy`, so the one claim available is that this
   * entry was attached by the same account that filed the report, which is
   * exactly true and is the one worth flagging. Everything else is an id.
   */
  function attribution(entry: EvidenceView): string {
    return entry.addedBy === kase.reportedBy
      ? `${entry.addedBy} — the account that reported this case`
      : entry.addedBy;
  }

  const evidenceRows = kase.evidence.map((entry) =>
    el('li', { class: 'row' }, [
      el('dl', { class: 'facts' }, [
        ...fact('Kind', label(EVIDENCE_KIND, entry.type)),
        // Per-arm fields. An entry shows the reference it HAS; a kind this
        // build predates has neither and still shows its kind, who and when.
        ...(entry.documentId === null
          ? []
          : fact(
              'Document',
              entry.version === null
                ? entry.documentId
                : `${entry.documentId} — version ${entry.version}`,
            )),
        ...(entry.matchId === null ? [] : fact('Provider reference', entry.matchId)),
        ...fact('Attached by', attribution(entry)),
        ...fact('Attached', when(entry.addedAt)),
      ]),
    ]),
  );

  const timelineRows = (options.timeline ?? []).map((event) =>
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
      el('h2', { class: 'heading' }, ['Evidence']),
      /*
       * WHAT WAS ATTACHED, NOT WHAT IT SAYS. A document's contents live in the
       * documents service behind its own audited read (`document.evidence.
       * accessed`, authorized by settlement's evidence-read route), and this
       * console has no path to them — deliberately, for now: pulling estate
       * documents into the lowest-trust origin in the product is its own
       * decision with its own audit volume, not a detail of this panel. Saying
       * so beats a screen that lists an id and leaves a reviewer wondering
       * whether they are looking at everything.
       */
      el('p', { class: 'lede' }, [
        'What was attached to this case. Opening a document is a separate read, recorded separately — this console does not do it.',
      ]),
      /*
       * `kase.evidence` is never null: it arrives ON the case read, so a
       * failure here is no screen at all rather than an empty panel. It goes
       * through `sectionBody` anyway — one spelling for "nothing here", and the
       * day evidence moves to its own request the null arm is already right.
       */
      sectionBody(kase.evidence, evidenceRows, 'Nothing was attached to this report.'),
    ]),
    el('section', { class: 'panel' }, [
      el('h2', { class: 'heading' }, ['Staged access']),
      sectionBody(options.stages, stageRows, 'No stage has been requested on this case.'),
    ]),
    el('section', { class: 'panel' }, [
      el('h2', { class: 'heading' }, ['Distributions']),
      sectionBody(
        options.distributions,
        distributionRows,
        'Nothing has been recorded for distribution.',
      ),
    ]),
    el('section', { class: 'panel' }, [
      el('h2', { class: 'heading' }, ['Timeline']),
      sectionBody(options.timeline, timelineRows, 'Nothing recorded yet.'),
    ]),
    el('p', { class: 'actions' }, [back]),
  ];
}
