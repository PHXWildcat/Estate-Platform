import { request, type ApiFailure, type ApiResult } from './api.js';
import { el, onClick, replaceChildren, requireElement } from './dom.js';
import { caseScreen, messageFor, worklist } from './screens.js';
import * as settlement from './settlement.js';
import type {
  CaseSummary,
  DistributionView,
  RejectionReason,
  StageView,
  TimelineEvent,
} from './settlement.js';
import { REJECTION_REASONS } from './settlement.js';
import { focusStepUp, stepUpPrompt, type RetryOutcome, type StepUpHandle } from './step-up.js';

/**
 * THE OPERATOR CONSOLE (M21 PR3a shipped the boundary; PR3b the surface).
 *
 * Two worklists and one case. The review queue is the docs/03 §5.1 chain's
 * front door — reported, under review, waiting period — and the administrable
 * list is what comes after verification. Opening a case reads it four ways
 * (the case, its timeline, its staged access, its distributions) and settlement
 * records each read as an operator read on the case's own trail, which is the
 * event TB7 always owed and PR3b's first slice added.
 *
 * THE SCREEN'S FIRST JOB IS TO BE HONEST ABOUT WHAT ARRIVING HERE PROVES, which
 * is NOTHING. An `operator` audience is a RESTRICTION on where a credential may
 * be spent, not a claim about who is spending it: minting is role-blind by
 * design, so any signed-in account can reach this origin, and whether they may
 * act on a case is decided by `settlement_operators` inside the transaction
 * that would act on it. That is why a non-operator's first experience here is a
 * 403 whose copy explains the model rather than saying "forbidden".
 *
 * IT DOES NOT POLL, and the reason is the trail rather than the network. Each
 * case read emits an audit event attributed to the operator; a console that
 * refreshed itself would turn a screen left open over lunch into hundreds of
 * recorded reads of one estate's death case, which is the same
 * audited-volume-is-a-UI-constraint rule M12 applied to document decrypts. A
 * case is re-read when somebody acts on it, and not otherwise.
 */

interface SessionView {
  readonly userId: string;
  readonly sessionId: string;
  readonly audience: string;
  readonly stepupExpiresAt: string | null;
}

/**
 * A response missing its fields is NO DATA, never data (M11/M12/M15).
 *
 * The realistic failure is a version skew — this origin's client deployed ahead
 * of identity, or behind it — and the direction that matters is that a missing
 * `audience` must not render as an empty one. An empty audience would read on
 * screen as "your session type is blank", which is a claim about a credential
 * rather than an admission that we could not ask.
 */
function parseSession(payload: unknown): SessionView | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const { userId, sessionId, audience, stepupExpiresAt } = payload as Record<string, unknown>;
  if (typeof userId !== 'string' || userId.length === 0) return null;
  if (typeof sessionId !== 'string' || sessionId.length === 0) return null;
  if (typeof audience !== 'string' || audience.length === 0) return null;
  if (stepupExpiresAt !== null && typeof stepupExpiresAt !== 'string') return null;
  return { userId, sessionId, audience, stepupExpiresAt };
}

function appOrigin(): string {
  // Set by `/app/config.js`, which the edge generates from a zod-validated URL.
  const value = (globalThis as { ESTATE_APP_ORIGIN?: unknown }).ESTATE_APP_ORIGIN;
  return typeof value === 'string' ? value : '';
}

function link(href: string, label: string): HTMLAnchorElement {
  // `href` is deliberately absent from `dom.ts`'s attribute allowlist, so the
  // one place a URL becomes an attribute is here, over a value the edge
  // validated as a URL before it ever reached the browser.
  const anchor = el('a', { class: 'link' }, [label]);
  anchor.setAttribute('href', href);
  return anchor;
}

function signedOutScreen(reason: string | null): readonly Node[] {
  const origin = appOrigin();
  return [
    el('h1', { class: 'title' }, ['Operator console']),
    ...(reason ? [el('p', { class: 'notice', role: 'alert' }, [reason])] : []),
    el('p', { class: 'lede' }, [
      'You are not signed in on this origin. The console is opened from Estate: sign in there, confirm it is you, and open the operator console from your security settings.',
    ]),
    ...(origin ? [el('p', {}, [link(origin, 'Go to Estate')])] : []),
  ];
}

function sessionPanel(session: SessionView, onSignOut: () => void): HTMLElement {
  const origin = appOrigin();
  const signOut = el('button', { type: 'button', class: 'button', id: 'sign-out' }, ['Sign out']);
  onClick(signOut, onSignOut);
  return el('section', { class: 'panel' }, [
    el('h2', { class: 'heading' }, ['This credential']),
    el('dl', { class: 'facts' }, [
      el('dt', {}, ['Session type']),
      el('dd', { 'data-testid': 'audience' }, [session.audience]),
      el('dt', {}, ['Identity check']),
      el('dd', {}, [session.stepupExpiresAt ? 'Recently confirmed' : 'Not recently confirmed']),
    ]),
    /*
     * THE SENTENCE THAT KEEPS THE MODEL HONEST, and it is not decoration.
     *
     * Minting an operator handoff is role-blind — any signed-in account can
     * arrive here — so a console that opened with "welcome, operator" would
     * teach every user who reached it that arriving is the permission. It is
     * not. The allowlist decides, in settlement, inside the transaction.
     *
     * IT IS ALSO NARROWED FROM WHAT PR3a SAID, in the change that made the old
     * sentence false. "It reaches none of your own estate" was true while this
     * credential reached three identity routes and nothing else; four of the
     * thirteen settlement routes it now reaches reach a case through
     * `assertCaseVisible`, which admits the decedent, the reporter and the
     * estate's executor as well as an operator — so a console session really can
     * see the holder's own case when they are one of those people. The claim is
     * stated as a RESTRICTION rather than as an absolute, which is what an
     * audience is.
     */
    el('p', { class: 'lede' }, [
      'This credential is restricted to this origin and to settlement. It cannot reach your assets, documents, people or vault, and it cannot change your account. It grants no authority on its own: whether you may act on a case is decided when you try, against the operator allowlist.',
    ]),
    el('p', { class: 'lede' }, [
      'It expires on its own after 15 minutes and cannot be renewed. To come back, open the console from Estate again.',
    ]),
    el('p', { class: 'actions' }, [signOut, ...(origin ? [link(origin, 'Back to Estate')] : [])]),
  ]);
}

// ---------------------------------------------------------------- navigation

type View = { readonly kind: 'worklists' } | { readonly kind: 'case'; readonly caseId: string };

/**
 * WHERE THE CONSOLE IS, IN MEMORY AND NOWHERE ELSE.
 *
 * Deliberately not in the URL. A case id is opaque and reveals nothing on its
 * own, but a hash route accumulates a list of death-case references in the
 * operator's browser history and puts one in the address bar, which is the
 * part a screen-share or a screenshot catches. The cost is that a refresh
 * returns to the worklists, which is a smaller thing than the address bar of a
 * TB7 console naming whose estate is being settled.
 */
let view: View = { kind: 'worklists' };

/** The prompt currently open, if any, and the action it is gating. */
let pending: StepUpHandle | null = null;
let notice: string | null = null;
let busy = false;

function show(...children: readonly Node[]): void {
  replaceChildren(requireElement('app'), ...children);
}

function failed(code: ApiFailure): void {
  notice = messageFor(code);
}

/**
 * Run an action, and hand a `stepup_required` back to the prompt instead of
 * rendering it.
 *
 * The prompt polls, because settlement learns of an elevation through a
 * short-TTL positive introspection cache — so `stale` is a real answer and not
 * a failure, and it is the ONE code this helper does not turn into a notice.
 */
/**
 * Take the prompt off screen AND out of the ceremony.
 *
 * EVERY path that discards a prompt without pressing Cancel goes through here.
 * Clearing `pending` alone only forgets the element: the polling loop lives in
 * a closure that keeps running, and it would apply the very action the operator
 * navigated away from. Measured before this existed — pressing "Back to
 * worklists" mid-poll removed the form and closed the case two seconds later,
 * with nothing on screen to say so.
 *
 * The loop's own exits (`attempt` below, on both of its terminal outcomes) do
 * NOT use this: there the loop is clearing its own prompt and returns
 * immediately after, so aborting it would be aborting the thing that finished.
 */
function dismissPrompt(): void {
  pending?.abort();
  pending = null;
}

async function attempt<T>(run: () => Promise<ApiResult<T>>): Promise<RetryOutcome> {
  const result = await run();
  if (result.ok) {
    notice = null;
    pending = null;
    await refresh();
    return 'applied';
  }
  if (result.code === 'STEPUP_REQUIRED') {
    return 'stale';
  }
  // Anything else is a real refusal: surface it and stop the loop. The prompt
  // stays open only for the one code that means "not yet".
  failed(result.code);
  pending = null;
  await refresh();
  return 'applied';
}

/**
 * Wrap a step-up-gated action: try it once bare, and only if the server refuses
 * for want of a fresh check does the ceremony appear.
 *
 * Trying first is what keeps a freshly-elevated operator from being asked again
 * on every verb, and it costs nothing: the refusal happens before the handler
 * runs, so nothing is half-done.
 */
async function guarded<T>(
  idPrefix: string,
  hint: string,
  submitLabel: string,
  run: () => Promise<ApiResult<T>>,
): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    const outcome = await attempt(run);
    if (outcome !== 'stale') return;
    pending = stepUpPrompt({
      hint,
      submitLabel,
      idPrefix,
      onElevated: () => attempt(run),
      // Cancel: the prompt has aborted itself already, so this is only the
      // parent being told to stop showing it.
      onCancel: () => {
        pending = null;
        void render();
      },
    });
    await render();
    focusStepUp(idPrefix);
  } finally {
    busy = false;
  }
}

/** An ungated action: no ceremony, and a refusal is just a refusal. */
async function plain<T>(run: () => Promise<ApiResult<T>>): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    await attempt(run);
  } finally {
    busy = false;
  }
}

function button(label: string, id: string, onPress: () => void): HTMLButtonElement {
  const node = el('button', { type: 'button', class: 'button', id }, [label]);
  onClick(node, onPress);
  return node;
}

/**
 * The verbs a case's current status makes available.
 *
 * NEVER OFFER WHAT THE SERVER WOULD REFUSE (the M12 rule), and the statuses
 * here are settlement's own — a `reported` case can be picked up, a `verifying`
 * one decided, a `waiting_period` one confirmed ONLY once its deadline has
 * lapsed (`eligibleForVerification`, which settlement computes; a lapsed
 * deadline makes a case eligible and never advances it), and an administrable
 * one closed.
 */
function caseActions(kase: CaseSummary): readonly HTMLElement[] {
  const id = kase.caseId;
  switch (kase.status) {
    case 'reported':
      return [
        button('Start review', 'start-review', () => {
          void plain(() => settlement.startReview(id));
        }),
      ];
    case 'verifying':
      return reviewDecisionControls(id);
    case 'waiting_period':
      return kase.eligibleForVerification
        ? [
            button('Confirm verification', 'verify', () => {
              void guarded(
                'verify',
                'Confirming a verification locks this account and revokes every session it holds. It cannot be undone.',
                'Confirm verification',
                () => settlement.confirmVerification(id),
              );
            }),
          ]
        : [];
    case 'verified':
    case 'active':
    case 'distributing':
      return [
        button('Close case', 'close-case', () => {
          void guarded(
            'close',
            'Closing a case ends the settlement. Confirm it is you.',
            'Close case',
            () => settlement.closeCase(id),
          );
        }),
      ];
    default:
      return [];
  }
}

/**
 * Approve, or reject WITH A REASON — the reason is required by settlement's own
 * schema and its vocabulary is closed (enum tokens only; free-text rationale
 * deliberately has no field to land in, so none is offered here either).
 */
function reviewDecisionControls(caseId: string): readonly HTMLElement[] {
  const select = el('select', { id: 'reject-reason', class: 'input' });
  for (const reason of REJECTION_REASONS) {
    const option = el('option', {}, [reason.replace(/_/g, ' ')]);
    option.setAttribute('value', reason);
    select.append(option);
  }
  const reasonLabel = el('label', { class: 'label' }, ['Reason for rejecting']);
  reasonLabel.htmlFor = 'reject-reason';
  return [
    button('Approve review', 'approve-review', () => {
      void guarded(
        'approve',
        'Approving a review locks the account for the waiting period and notifies the account holder. Confirm it is you.',
        'Approve review',
        () => settlement.decideReview(caseId, 'approve'),
      );
    }),
    reasonLabel,
    select,
    button('Reject review', 'reject-review', () => {
      const reason = select.value as RejectionReason;
      void guarded(
        'reject',
        'Rejecting a review closes this case and restores the account. Confirm it is you.',
        'Reject review',
        () => settlement.decideReview(caseId, 'reject', reason),
      );
    }),
  ];
}

function stageControls(kase: CaseSummary): (stage: StageView) => readonly HTMLElement[] {
  return (stage) => {
    if (kase.resolution !== null) return [];
    if (stage.status === 'requested') {
      return [
        button('Approve stage', `approve-stage-${stage.stageId}`, () => {
          void guarded(
            'stage-approve',
            `Approving ${stage.stage} access grants it to the executor. Confirm it is you.`,
            'Approve stage',
            () => settlement.decideStage(stage.stageId, 'approve'),
          );
        }),
        button('Deny stage', `deny-stage-${stage.stageId}`, () => {
          void guarded(
            'stage-deny',
            'Denying a stage refuses the request. Confirm it is you.',
            'Deny stage',
            () => settlement.decideStage(stage.stageId, 'deny'),
          );
        }),
      ];
    }
    if (stage.status === 'approved') {
      return [
        button('Revoke stage', `revoke-stage-${stage.stageId}`, () => {
          void guarded(
            'stage-revoke',
            'Revoking a stage withdraws access already granted. Confirm it is you.',
            'Revoke stage',
            () => settlement.revokeStage(stage.stageId),
          );
        }),
      ];
    }
    return [];
  };
}

function distributionControls(): (distribution: DistributionView) => readonly HTMLElement[] {
  return (distribution) => {
    if (distribution.approvedBy !== null) return [];
    return [
      button('Approve distribution', `approve-distribution-${distribution.distributionId}`, () => {
        void guarded(
          'distribution',
          'Approving a distribution is the second half of a dual control: the operator who recorded it cannot be the one who approves it. Confirm it is you.',
          'Approve distribution',
          () => settlement.approveDistribution(distribution.distributionId),
        );
      }),
    ];
  };
}

// -------------------------------------------------------------------- render

async function renderWorklists(session: SessionView): Promise<void> {
  const [queue, admin] = await Promise.all([settlement.reviewQueue(), settlement.administrable()]);
  const panels: Node[] = [];
  // ONE FAILED LIST COSTS ITS OWN PANEL, never the page (the M10 PR4 rule): a
  // 403 on the queue must not hide the administrable cases, and vice versa.
  panels.push(
    queue.ok
      ? worklist({
          title: 'Review queue',
          empty: 'No case is waiting for review.',
          cases: queue.data,
          onOpen: (caseId) => {
            view = { kind: 'case', caseId };
            notice = null;
            void render();
          },
        })
      : el('section', { class: 'panel' }, [
          el('h2', { class: 'heading' }, ['Review queue']),
          el('p', { class: 'notice', role: 'alert' }, [messageFor(queue.code)]),
        ]),
  );
  panels.push(
    admin.ok
      ? worklist({
          title: 'Cases in settlement',
          empty: 'No case is in settlement.',
          cases: admin.data,
          onOpen: (caseId) => {
            view = { kind: 'case', caseId };
            notice = null;
            void render();
          },
        })
      : el('section', { class: 'panel' }, [
          el('h2', { class: 'heading' }, ['Cases in settlement']),
          el('p', { class: 'notice', role: 'alert' }, [messageFor(admin.code)]),
        ]),
  );

  show(
    el('h1', { class: 'title' }, ['Operator console']),
    ...(notice ? [el('p', { class: 'notice', role: 'alert' }, [notice])] : []),
    ...panels,
    sessionPanel(session, () => {
      void signOut();
    }),
  );
}

async function renderCase(caseId: string): Promise<void> {
  const [kase, events, stageList, distributionList] = await Promise.all([
    settlement.getCase(caseId),
    settlement.timeline(caseId),
    settlement.stages(caseId),
    settlement.distributions(caseId),
  ]);
  if (!kase.ok) {
    show(
      el('h1', { class: 'title' }, ['Settlement case']),
      el('p', { class: 'notice', role: 'alert' }, [messageFor(kase.code)]),
      backControl(),
    );
    return;
  }
  const events2: readonly TimelineEvent[] = events.ok ? events.data : [];
  const stages2: readonly StageView[] = stageList.ok ? stageList.data : [];
  const distributions2: readonly DistributionView[] = distributionList.ok
    ? distributionList.data
    : [];
  show(
    ...caseScreen({
      kase: kase.data,
      timeline: events2,
      stages: stages2,
      distributions: distributions2,
      actions: pending ? [] : caseActions(kase.data),
      stageActions: pending ? () => [] : stageControls(kase.data),
      distributionActions: pending ? () => [] : distributionControls(),
      notice,
      prompt: pending?.form ?? null,
      onBack: () => {
        view = { kind: 'worklists' };
        notice = null;
        dismissPrompt();
        void render();
      },
    }),
  );
}

function backControl(): HTMLElement {
  return el('p', { class: 'actions' }, [
    button('Back to worklists', 'back', () => {
      view = { kind: 'worklists' };
      notice = null;
      dismissPrompt();
      void render();
    }),
  ]);
}

/** Re-read whatever is on screen. Called after an action, and never on a timer. */
async function refresh(): Promise<void> {
  await render();
}

let signingOut = false;

/**
 * ONE ENTRY POINT, and it always re-reads the session first.
 *
 * The session read is what tells the screen whether the credential is still
 * alive — this origin's session lasts 15 minutes and CANNOT be renewed (there
 * is no refresh token for it by construction), so an operator who leaves the
 * console open comes back to an expired credential and must be told that
 * plainly rather than shown a worklist that 401s on every button.
 */
export async function render(): Promise<void> {
  const app = requireElement('app');
  const refused = new URL(globalThis.location.href).searchParams.get('open') === 'refused';
  const arrivalNotice = refused
    ? // ONE ANSWER FOR EVERY ARRIVAL FAILURE — unknown code, expired, already
      // spent, lost a race, identity unreachable. The edge distinguishes none
      // of them and neither does this, or the landing page becomes an oracle
      // for whether a guessed code named something real.
      'That link could not be opened. Codes are single-use and expire quickly — open the console from Estate again.'
    : null;

  const result = await request<unknown>('/api/auth/session');
  if (!result.ok) {
    if (result.code === 'UNAUTHENTICATED') {
      replaceChildren(app, ...signedOutScreen(arrivalNotice));
      return;
    }
    replaceChildren(
      app,
      el('h1', { class: 'title' }, ['Operator console']),
      el('p', { class: 'notice', role: 'alert' }, [messageFor(result.code)]),
    );
    return;
  }

  const session = parseSession(result.data);
  if (!session) {
    replaceChildren(
      app,
      el('h1', { class: 'title' }, ['Operator console']),
      el('p', { class: 'notice', role: 'alert' }, [
        'We could not read your session. Try again in a moment.',
      ]),
    );
    return;
  }

  if (view.kind === 'case') {
    await renderCase(view.caseId);
    return;
  }
  await renderWorklists(session);
}

/**
 * Sign out: REVOKE FIRST, and only then believe it (M8 PR5).
 *
 * The edge clears the cookie when — and only when — identity actually revoked
 * the session, so a failed revocation leaves the browser holding a credential
 * that still works and a screen that still says so. A "signed out" message over
 * a live session is the worse outcome of the two.
 */
async function signOut(): Promise<void> {
  if (signingOut) return;
  signingOut = true;
  try {
    const result = await request<unknown>('/api/auth/logout', { method: 'POST' });
    if (!result.ok) {
      const app = requireElement('app');
      const notice = el('p', { class: 'notice', role: 'alert' }, [
        'We could not sign you out. You are still signed in on this origin — try again in a moment.',
      ]);
      app.append(notice);
      return;
    }
    await render();
  } finally {
    signingOut = false;
  }
}
