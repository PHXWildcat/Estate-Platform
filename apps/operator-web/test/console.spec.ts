/**
 * @jest-environment jsdom
 */

/**
 * THE CONSOLE: two worklists, one case, and the verbs a status makes available.
 *
 * What is asserted here is what the screen is FOR rather than how it looks: that
 * a refused worklist costs its own panel and never the page, that opening a case
 * reads it exactly four ways and NOT ON A TIMER, that a verb is offered only
 * when settlement would accept it, and that the two refusals with a control
 * behind them — the uniform not-found and the liveness interlock — are said in
 * words an operator can act on.
 */
/**
 * THE MODULE IS RELOADED PER TEST, and that is a statement about the app rather
 * than a testing convenience: which screen the console is on lives in a
 * module-level variable and NOWHERE ELSE — deliberately not in the URL, because
 * a hash route would accumulate death-case references in an operator's browser
 * history and put one in the address bar. So a fresh page load is a fresh
 * module, and each test starts where a real arrival does: the worklists.
 */
let render: () => Promise<void>;

const SESSION = {
  userId: 'u-ada',
  sessionId: 's-1',
  audience: 'operator',
  mfaLevel: 'stepup',
  stepupExpiresAt: '2026-08-19T12:00:00.000Z',
};

const CASE_ID = '11111111-1111-4111-8111-111111111111';

/**
 * A WHOLE `CaseDto`, field for field, and never a convenient subset.
 *
 * A fixture that invents a shape tests the fixture (M15 PR3). The client
 * refuses a row it cannot fully read — deliberately, because a short worklist
 * of death reports is indistinguishable from a quiet week — so a fixture
 * missing a field would fail every row here while the real service worked, and
 * a fixture carrying a field the service does not send would do the reverse
 * silently. `settlement-client.spec.ts` pins the shape against the service's
 * own declaration; this is that shape written out.
 */
const REPORTED = {
  caseId: CASE_ID,
  decedentUserId: 'u-dec',
  status: 'reported',
  reportSource: 'family',
  reportedBy: 'u-rep',
  evidence: [],
  humanReviewBy: null,
  humanReviewAt: null,
  claimedBy: null,
  claimedAt: null,
  waitingPeriodEnds: null,
  verifiedAt: null,
  resolution: null,
  resolvedAt: null,
  createdAt: '2026-08-01T00:00:00.000Z',
  updatedAt: '2026-08-01T00:00:00.000Z',
  eligibleForVerification: false,
};

interface Reply {
  status: number;
  body: unknown;
}

let calls: string[];
let routes: Record<string, Reply | (() => Reply)>;

function transport(replies: Record<string, Reply | (() => Reply)>): void {
  calls = [];
  routes = replies;
  (globalThis as { fetch?: unknown }).fetch = (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    calls.push(`${method} ${path}`);
    const entry = routes[`${method} ${path}`] ?? routes[path];
    if (entry === undefined) return Promise.reject(new Error(`unrouted: ${method} ${path}`));
    const reply = typeof entry === 'function' ? entry() : entry;
    return Promise.resolve({
      ok: reply.status >= 200 && reply.status < 300,
      status: reply.status,
      text: () => Promise.resolve(reply.body === undefined ? '' : JSON.stringify(reply.body)),
    });
  };
}

const CASE_ROUTES = (kase: unknown): Record<string, Reply> => ({
  [`/api/settlement/cases/${CASE_ID}`]: { status: 200, body: kase },
  [`/api/settlement/cases/${CASE_ID}/timeline`]: { status: 200, body: [] },
  [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 200, body: [] },
  [`/api/settlement/cases/${CASE_ID}/distributions`]: { status: 200, body: [] },
});

const WORKLISTS = (queue: unknown[], admin: unknown[]): Record<string, Reply> => ({
  '/api/auth/session': { status: 200, body: SESSION },
  '/api/settlement/queue': { status: 200, body: queue },
  '/api/settlement/administrable': { status: 200, body: admin },
});

beforeEach(async () => {
  jest.resetModules();
  render = (await import('../src/client/app')).render;
  document.body.replaceChildren();
  const main = document.createElement('main');
  main.id = 'app';
  document.body.append(main);
  (globalThis as { ESTATE_APP_ORIGIN?: string }).ESTATE_APP_ORIGIN = 'http://localhost:3000';
  window.history.replaceState({}, '', '/');
});

const app = (): HTMLElement => document.getElementById('app') as HTMLElement;

/**
 * Start over, exactly as a reload does. Needed because the console's current
 * screen is module state by design (see the note on the import above), so a
 * test that visits two cases must arrive twice rather than navigate.
 */
async function freshLoad(): Promise<void> {
  jest.resetModules();
  render = (await import('../src/client/app')).render;
}
const copy = (): string => app().textContent ?? '';

/**
 * Settle every promise that is already resolvable, WITHOUT the event loop.
 *
 * `until()` cannot serve the one test that installs fake timers — it waits on a
 * `setTimeout` that will not fire while they are — and that test needs fake
 * timers precisely because the thing it is measuring is a two-second sleep.
 */
async function drain(): Promise<void> {
  for (let i = 0; i < 60; i += 1) await Promise.resolve();
}

async function until(condition: () => boolean): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    if (condition()) return;
    await new Promise((r) => setTimeout(r, 0));
  }
  throw new Error(`condition never held; last screen was: ${copy().slice(0, 400)}`);
}

const openCase = async (): Promise<void> => {
  (app().querySelector('.list .button') as HTMLButtonElement).click();
  await until(() => copy().includes('Settlement case'));
};

const pressing = async (label: string): Promise<void> => {
  const button = [...app().querySelectorAll('button')].find((b) => b.textContent === label);
  if (!button) throw new Error(`no button labelled ${label}; screen: ${copy().slice(0, 400)}`);
  button.click();
  await new Promise((r) => setTimeout(r, 0));
};

describe('the worklists', () => {
  it('reads BOTH lists and shows a case in each', async () => {
    transport(WORKLISTS([REPORTED], [{ ...REPORTED, status: 'active' }]));
    await render();
    expect(calls).toContain('GET /api/settlement/queue');
    expect(calls).toContain('GET /api/settlement/administrable');
    expect(copy()).toMatch(/Review queue/);
    expect(copy()).toMatch(/Cases in settlement/);
    // The status is rendered as a SENTENCE, never as the DDL's own word.
    expect(copy()).toMatch(/waiting for an operator to pick it up/i);
    expect(copy()).toMatch(/Settlement in progress/);
  });

  it('ONE REFUSED LIST COSTS ITS OWN PANEL, never the page', async () => {
    // The M10 PR4 rule: a 403 on one list must not blank the other, and it must
    // not read as an empty worklist either — a quiet week and a refusal are
    // different facts.
    transport({
      '/api/auth/session': { status: 200, body: SESSION },
      '/api/settlement/queue': { status: 403, body: { error: 'forbidden' } },
      '/api/settlement/administrable': { status: 200, body: [REPORTED] },
    });
    await render();
    expect(copy()).toMatch(/not on the settlement operator list/i);
    expect(copy()).toMatch(/Cases in settlement/);
    expect(app().querySelectorAll('.list .button')).toHaveLength(1);
  });

  it('SAYS ARRIVING PROVED NOTHING when settlement refuses everything', async () => {
    // Minting an operator handoff is role-blind, so this is the FIRST thing a
    // non-operator sees, and it has to explain the model rather than say
    // "forbidden".
    transport({
      '/api/auth/session': { status: 200, body: SESSION },
      '/api/settlement/queue': { status: 403, body: { error: 'forbidden' } },
      '/api/settlement/administrable': { status: 403, body: { error: 'forbidden' } },
    });
    await render();
    expect(copy()).toMatch(/an operator is added by the platform team, not by signing in here/i);
  });

  it('shows an empty list as an ANSWER, not as an absence', async () => {
    transport(WORKLISTS([], []));
    await render();
    expect(copy()).toMatch(/No case is waiting for review/i);
    expect(copy()).toMatch(/No case is in settlement/i);
  });

  it('FAILS THE WHOLE LIST when a row will not parse', async () => {
    // A short worklist is indistinguishable from a quiet week, so a row this
    // client cannot read must never be silently dropped from a queue of death
    // reports.
    transport(WORKLISTS([REPORTED, { caseId: CASE_ID }], []));
    await render();
    expect(copy()).toMatch(/Something went wrong/i);
    expect(copy()).not.toMatch(/waiting for an operator/i);
  });
});

describe('opening a case', () => {
  it('reads it FOUR ways, and then stops — no polling', async () => {
    transport({ ...WORKLISTS([REPORTED], []), ...CASE_ROUTES(REPORTED) });
    await render();
    await openCase();

    const caseReads = calls.filter((c) => c.includes(`/cases/${CASE_ID}`));
    expect(caseReads).toEqual([
      `GET /api/settlement/cases/${CASE_ID}`,
      `GET /api/settlement/cases/${CASE_ID}/timeline`,
      `GET /api/settlement/cases/${CASE_ID}/stages`,
      `GET /api/settlement/cases/${CASE_ID}/distributions`,
    ]);

    /*
     * AND STAYS AT FOUR. Each of these reads is an audit event attributed to
     * the operator on this estate's own death-case trail, so a console that
     * refreshed itself would turn a screen left open over lunch into hundreds
     * of recorded reads — the audited-volume-is-a-UI-constraint rule M12
     * applied to document decrypts, arriving on the surface where the subject
     * of the trail is a dead person's estate.
     */
    const settled = calls.length;
    await new Promise((r) => setTimeout(r, 60));
    expect(calls).toHaveLength(settled);
  });

  it('answers a case it may not see with the SAME sentence as one that does not exist', async () => {
    // Settlement answers a uniform 404 for both (M21 PR2 closed that oracle);
    // the copy must not imply the reference named something real.
    transport({
      ...WORKLISTS([REPORTED], []),
      [`/api/settlement/cases/${CASE_ID}`]: { status: 404, body: { error: 'not_found' } },
      [`/api/settlement/cases/${CASE_ID}/timeline`]: { status: 404, body: { error: 'not_found' } },
      [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 404, body: { error: 'not_found' } },
      [`/api/settlement/cases/${CASE_ID}/distributions`]: {
        status: 404,
        body: { error: 'not_found' },
      },
    });
    await render();
    await openCase();
    expect(copy()).toMatch(/No case is available to you under that reference/i);
    expect(copy()).not.toMatch(/exists|belongs to|permission/i);
  });

  it('KEEPS THE CASE ID OUT OF THE URL', async () => {
    // A case id is opaque and reveals nothing on its own, but a hash route
    // accumulates a list of death-case references in the operator's history and
    // puts one in the address bar, which is the part a screen-share catches.
    transport({ ...WORKLISTS([REPORTED], []), ...CASE_ROUTES(REPORTED) });
    await render();
    await openCase();
    expect(window.location.href).not.toContain(CASE_ID);
    expect(window.location.hash).toBe('');
  });

  it('goes back to the worklists without a browser navigation', async () => {
    transport({ ...WORKLISTS([REPORTED], []), ...CASE_ROUTES(REPORTED) });
    await render();
    await openCase();
    await pressing('Back to worklists');
    await until(() => copy().includes('Review queue'));
  });

  /**
   * THE AMOUNT AN OPERATOR IS ABOUT TO APPROVE (M23 PR4b).
   *
   * This test used to assert "Recorded (not readable here)" — the honest
   * rendering of a figure settlement had no route to return. That made the
   * approval below it a dual-control, step-up-gated act over a number the
   * approver could not see, which is a ceremony rather than a control.
   *
   * What survives is the property that was always the point: the console never
   * shows an amount it has not been given. It just can now ask for one, once,
   * per row.
   */
  it('shows a distribution as RECORDED until the reviewer asks for the amount', async () => {
    transport({
      ...WORKLISTS([REPORTED], []),
      ...CASE_ROUTES({ ...REPORTED, status: 'active' }),
      [`/api/settlement/cases/${CASE_ID}/distributions`]: {
        status: 200,
        body: [
          {
            distributionId: 'd-1',
            beneficiaryContactId: 'c-1',
            assetId: null,
            status: 'pending',
            createdBy: 'u-op1',
            approvedBy: null,
            hasAmount: true,
            createdAt: '2026-08-02T00:00:00.000Z',
          },
        ],
      },
      '/api/settlement/distributions/d-1/amount': { status: 200, body: { amount: '4500.00' } },
    });
    await render();
    await openCase();
    // NOT FETCHED WITH THE LIST. Every reveal is an audited decrypt on the
    // decedent's trail, so loading a case must never spend one.
    expect(copy()).toMatch(/Recorded — use Show amount/);
    expect(copy()).not.toMatch(/4500\.00/);

    await pressing('Show amount');
    await until(() => copy().includes('4500.00'));
    // A decimal STRING, rendered as it arrived — never parsed, so no float
    // ever prints `4499.999999`.
    expect(copy()).toMatch(/4500\.00/);
    // ...and the control is gone, because asking again would be another
    // audited decrypt and the answer is already on screen.
    expect(copy()).not.toMatch(/Show amount/);
  });

  it('a REFUSED reveal leaves the row saying an amount is recorded', async () => {
    transport({
      ...WORKLISTS([REPORTED], []),
      ...CASE_ROUTES({ ...REPORTED, status: 'active' }),
      [`/api/settlement/cases/${CASE_ID}/distributions`]: {
        status: 200,
        body: [
          {
            distributionId: 'd-1',
            beneficiaryContactId: 'c-1',
            assetId: null,
            status: 'pending',
            createdBy: 'u-op1',
            approvedBy: null,
            hasAmount: true,
            createdAt: '2026-08-02T00:00:00.000Z',
          },
        ],
      },
      '/api/settlement/distributions/d-1/amount': { status: 503, body: { error: 'unavailable' } },
    });
    await render();
    await openCase();
    await pressing('Show amount');
    // The row's claim is still true, and the control stays: a failed read is
    // not an answer, so the reviewer can try again.
    await until(() => copy().includes('Recorded — use Show amount'));
    expect(copy()).toMatch(/Show amount/);
  });

  it('renders an UNKNOWN status token as itself rather than blanking the row', async () => {
    // A service deployed ahead of this client must not blank a worklist (the
    // M10 PR4 rule); the raw token is at least true.
    transport(WORKLISTS([{ ...REPORTED, status: 'escheating' }], []));
    await render();
    expect(copy()).toMatch(/escheating/);
  });
});

/**
 * THE EVIDENCE A REVIEW IS CONDUCTED ON (M22 PR4b).
 *
 * `CaseDto` has carried `evidence` since M7 and this console dropped it in
 * `parseCase`, so the mandatory human review docs/03 §5.1 rests on was being
 * conducted against a status, a timeline and two opaque ids. Nothing was red:
 * the field was simply never read, which is the shape of gap that a test suite
 * cannot report because there is no assertion to fail.
 */
describe('the evidence a review is conducted on', () => {
  const DOC = {
    type: 'document',
    documentId: 'doc-7',
    version: 3,
    addedBy: 'u-rep',
    addedAt: '2026-08-01T01:00:00.000Z',
  };
  const MATCH = {
    type: 'provider_match',
    matchId: 'lexisnexis-abc',
    addedBy: 'u-op1',
    addedAt: '2026-08-02T02:00:00.000Z',
  };

  const withEvidence = async (evidence: unknown): Promise<void> => {
    await freshLoad();
    const kase = { ...REPORTED, evidence };
    transport({ ...WORKLISTS([REPORTED], []), ...CASE_ROUTES(kase) });
    await render();
    await openCase();
  };

  it('shows each entry, with the reference its kind carries', async () => {
    await withEvidence([DOC, MATCH]);
    expect(copy()).toMatch(/Document/);
    expect(copy()).toMatch(/doc-7 — version 3/);
    expect(copy()).toMatch(/Death-data provider match/);
    expect(copy()).toMatch(/lexisnexis-abc/);
  });

  it('says whose attachment came from the account that filed the report', async () => {
    /*
     * The distinction a reviewer needs and the one this origin can honestly
     * make. Reporter-vs-operator is NOT available here — the console is
     * role-blind by construction and `settlement_operators` is read inside the
     * transaction that acts — so the claim made is the narrower true one:
     * this id is the id that reported the case.
     */
    await withEvidence([DOC, MATCH]);
    expect(copy()).toMatch(/u-rep — the account that reported this case/);
    // The other entry's attacher is a bare id, with no claim attached to it.
    expect(copy()).toMatch(/u-op1/);
    expect(copy()).not.toMatch(/u-op1 — the account that reported/);
  });

  it('does not offer to open a document it cannot open', async () => {
    await withEvidence([DOC]);
    expect(copy()).toMatch(/this console does not do it/i);
    expect(app().querySelectorAll('a')).toHaveLength(0);
  });

  it('an empty list says so plainly', async () => {
    await withEvidence([]);
    expect(copy()).toMatch(/Nothing was attached to this report/i);
  });

  it('renders an evidence kind this build predates, rather than hiding the entry', async () => {
    /*
     * The reason `EvidenceView` is flat rather than a mirror of settlement's
     * discriminated union. Both alternatives are wrong on this screen: failing
     * the row removes a death case from a worklist over an evidence kind added
     * last week, and skipping the entry tells a reviewer there is one piece of
     * evidence when there are two. The entry appears, its kind is named as the
     * raw token, and who and when survive because every arm carries them.
     */
    await withEvidence([DOC, { type: 'coroner_record', addedBy: 'u-op1', addedAt: 'when' }]);
    expect(copy()).toMatch(/coroner_record/);
    expect(copy()).toMatch(/doc-7/);
    expect(app().querySelectorAll('.panel .list li')).toHaveLength(2);
  });

  it('a case with NO evidence FIELD is not a case with no evidence', async () => {
    /*
     * The failure this panel could have shipped with. A peer that stops sending
     * the field — or a rename at the service — must not render as "nothing was
     * attached to this report" on the screen where somebody decides whether to
     * lock a living person's account. The case fails to read, exactly as a
     * worklist row missing a field does.
     */
    const { evidence: _dropped, ...withoutEvidence } = REPORTED;
    await freshLoad();
    transport({ ...WORKLISTS([REPORTED], []), ...CASE_ROUTES(withoutEvidence) });
    await render();
    (app().querySelector('.list .button') as HTMLButtonElement).click();
    await until(() => copy().includes('Something went wrong'));
    expect(copy()).not.toMatch(/Nothing was attached to this report/i);
  });

  it('and neither is one whose entries cannot be read', async () => {
    // Positive control on the same mechanism: a well-formed list still renders,
    // so the assertion above is about the missing shape and not about this
    // screen refusing any case handed to it.
    await freshLoad();
    transport({
      ...WORKLISTS([REPORTED], []),
      ...CASE_ROUTES({ ...REPORTED, evidence: [{ type: 'document', documentId: 'doc-7' }] }),
    });
    await render();
    (app().querySelector('.list .button') as HTMLButtonElement).click();
    await until(() => copy().includes('Something went wrong'));

    await withEvidence([DOC]);
    expect(copy()).toMatch(/doc-7/);
  });
});

describe('the verbs a status makes available', () => {
  const withCase = async (overrides: Record<string, unknown>): Promise<void> => {
    await freshLoad();
    const kase = { ...REPORTED, ...overrides };
    transport({ ...WORKLISTS([kase], []), ...CASE_ROUTES(kase) });
    await render();
    await openCase();
  };

  const labels = (): string[] =>
    [...app().querySelectorAll('button')].map((b) => b.textContent ?? '');

  it('offers Start review on a reported case, and nothing further', async () => {
    await withCase({ status: 'reported' });
    expect(labels()).toContain('Start review');
    expect(labels()).not.toContain('Approve review');
    expect(labels()).not.toContain('Confirm verification');
  });

  it('offers Approve and Reject once a review is under way', async () => {
    await withCase({ status: 'verifying', claimedBy: 'u-ada' });
    expect(labels()).toContain('Approve review');
    expect(labels()).toContain('Reject review');
    // The reason is a CLOSED vocabulary, offered as a labelled choice.
    const select = app().querySelector('#reject-reason') as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toEqual([
      'insufficient_evidence',
      'fraud_suspected',
      'duplicate_report',
      'other',
    ]);
    expect((app().querySelector('label[for="reject-reason"]') as HTMLElement).textContent).toMatch(
      /reason/i,
    );
  });

  it('WITHHOLDS Confirm verification until the waiting period has lapsed', async () => {
    // Never offer what the server would refuse (M12). A lapsed deadline makes a
    // case ELIGIBLE; it never advances it, which is docs/03 §5.1's whole point.
    await withCase({
      status: 'waiting_period',
      waitingPeriodEnds: '2026-09-01T00:00:00.000Z',
      eligibleForVerification: false,
    });
    expect(labels()).not.toContain('Confirm verification');

    await withCase({
      status: 'waiting_period',
      waitingPeriodEnds: '2026-08-05T00:00:00.000Z',
      eligibleForVerification: true,
    });
    expect(labels()).toContain('Confirm verification');
  });

  it('offers nothing on a resolved case', async () => {
    await withCase({ status: 'closed', resolution: 'settled' });
    expect(labels().filter((l) => l !== 'Back to worklists' && l !== 'Open')).toEqual([]);
  });
});

describe('acting on a case', () => {
  it('claims a review WITHOUT a step-up — it moves nothing toward access', async () => {
    let status = 'reported';
    transport({
      '/api/auth/session': { status: 200, body: SESSION },
      '/api/settlement/queue': () => ({ status: 200, body: [{ ...REPORTED, status }] }),
      '/api/settlement/administrable': { status: 200, body: [] },
      [`/api/settlement/cases/${CASE_ID}`]: () => ({ status: 200, body: { ...REPORTED, status } }),
      [`/api/settlement/cases/${CASE_ID}/timeline`]: { status: 200, body: [] },
      [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 200, body: [] },
      [`/api/settlement/cases/${CASE_ID}/distributions`]: { status: 200, body: [] },
      [`POST /api/settlement/cases/${CASE_ID}/review/start`]: () => {
        status = 'verifying';
        return { status: 200, body: { ...REPORTED, status: 'verifying', claimedBy: 'u-ada' } };
      },
    });
    await render();
    await openCase();
    await pressing('Start review');
    await until(() => (app().textContent ?? '').includes('Under review'));
    expect(calls).not.toContain('POST /api/auth/stepup');
  });

  it('RAISES THE CEREMONY when settlement asks for a fresh check', async () => {
    transport({
      ...WORKLISTS([{ ...REPORTED, status: 'verifying' }], []),
      ...CASE_ROUTES({ ...REPORTED, status: 'verifying' }),
      [`POST /api/settlement/cases/${CASE_ID}/review`]: {
        status: 403,
        body: { error: 'stepup_required' },
      },
    });
    await render();
    await openCase();
    await pressing('Approve review');
    await until(() => document.getElementById('approve-stepup-code') !== null);
    // The hint says what is about to happen, in this surface's own words.
    expect(copy()).toMatch(/locks the account for the waiting period/i);
    // AND THE ACTIONS ARE WITHDRAWN while it is up: two "Confirm it's you"
    // fields would be indistinguishable to a person and to a query (M15 PR3),
    // so only one prompt may ever exist.
    expect(document.querySelectorAll('label[for$="-stepup-code"]')).toHaveLength(1);
    /*
     * EXACTLY ONE "Approve review" ON SCREEN, and it is the ceremony's.
     *
     * The prompt's submit deliberately carries the label of the action it is
     * gating — so the person confirming reads what they are confirming, which
     * is the M13 review's finding (a shared handler ran a different action than
     * the one refused). That makes the LABEL an ambiguous selector while the
     * action button is also on screen, which is precisely why the actions are
     * withdrawn: two identical buttons are indistinguishable to a person and to
     * a query alike.
     */
    const approves = [...app().querySelectorAll('button')].filter(
      (b) => b.textContent === 'Approve review',
    );
    expect(approves).toHaveLength(1);
    expect(approves[0]?.closest('form.prompt')).not.toBeNull();
  });

  it('says a REFUSED verification is a control firing, not a retry', async () => {
    // §5.1's liveness interlock: the owner proved they are alive and the case
    // is voided. "Try again" is the one thing this must never say.
    transport({
      ...WORKLISTS([{ ...REPORTED, status: 'waiting_period', eligibleForVerification: true }], []),
      ...CASE_ROUTES({ ...REPORTED, status: 'waiting_period', eligibleForVerification: true }),
      [`POST /api/settlement/cases/${CASE_ID}/verify`]: {
        status: 409,
        body: { error: 'owner_alive' },
      },
    });
    await render();
    await openCase();
    await pressing('Confirm verification');
    await until(() => copy().includes('voided'));
    expect(copy()).toMatch(/confirmed their identity/i);
    expect(copy()).not.toMatch(/try again/i);
  });

  it('names A DIFFERENT PERSON as the remedy for a dual-control refusal', async () => {
    transport({
      ...WORKLISTS([{ ...REPORTED, status: 'verifying' }], []),
      ...CASE_ROUTES({ ...REPORTED, status: 'verifying' }),
      [`POST /api/settlement/cases/${CASE_ID}/review`]: {
        status: 409,
        body: { error: 'reviewer_is_reporter' },
      },
    });
    await render();
    await openCase();
    await pressing('Approve review');
    await until(() => copy().includes('different operator'));
    expect(copy()).toMatch(/cannot also be the one who approves/i);
  });
});

describe('staged access', () => {
  const STAGE = {
    stageId: 'st-1',
    stage: 'vault',
    status: 'requested',
    requestedBy: 'u-exec',
    requestedAt: '2026-08-03T00:00:00.000Z',
    decidedBy: null,
    decidedAt: null,
  };

  const withStages = async (stages: unknown[]): Promise<void> => {
    await freshLoad();
    const kase = { ...REPORTED, status: 'verified', verifiedAt: '2026-08-04T00:00:00.000Z' };
    transport({
      ...WORKLISTS([], [kase]),
      ...CASE_ROUTES(kase),
      [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 200, body: stages },
    });
    await render();
    await openCase();
  };

  it('offers approve and deny on a REQUESTED stage, and names Zone A as Zone A', async () => {
    await withStages([STAGE]);
    const labels = [...app().querySelectorAll('button')].map((b) => b.textContent);
    expect(labels).toContain('Approve stage');
    expect(labels).toContain('Deny stage');
    expect(labels).not.toContain('Revoke stage');
    expect(copy()).toMatch(/Vault \(Zone A\)/);
  });

  it('offers revoke on an APPROVED stage, and neither verb on a decided one', async () => {
    await withStages([{ ...STAGE, status: 'approved', decidedBy: 'u-op2' }]);
    let labels = [...app().querySelectorAll('button')].map((b) => b.textContent);
    expect(labels).toContain('Revoke stage');
    expect(labels).not.toContain('Approve stage');

    await withStages([{ ...STAGE, status: 'denied', decidedBy: 'u-op2' }]);
    labels = [...app().querySelectorAll('button')].map((b) => b.textContent);
    expect(labels).not.toContain('Revoke stage');
    expect(labels).not.toContain('Approve stage');
  });
});

describe('every verb reaches its own route, and the gated ones ask first', () => {
  /*
   * ONE CASE PER VERB, and the assertion is the METHOD AND PATH rather than a
   * screen change: the edge allowlists per method, settlement admits the
   * `operator` audience per handler, and a verb wired to the wrong path is a
   * 404 from our own edge that reads on screen exactly like a case that is not
   * there. Which of these is step-up gated is settlement's decision, restated
   * here so a regression that stopped ASKING would be visible — the ceremony is
   * raised by the server's refusal, never guessed at by the client.
   */
  const drive = async (
    kase: Record<string, unknown>,
    extra: Record<string, Reply>,
    label: string,
  ): Promise<void> => {
    await freshLoad();
    const merged = { ...REPORTED, ...kase };
    transport({ ...WORKLISTS([merged], [merged]), ...CASE_ROUTES(merged), ...extra });
    await render();
    await openCase();
    await pressing(label);
  };

  const gated = (path: string): Record<string, Reply> => ({
    [`POST ${path}`]: { status: 403, body: { error: 'stepup_required' } },
  });

  it('CLOSES a case, behind a fresh check', async () => {
    const path = `/api/settlement/cases/${CASE_ID}/close`;
    await drive({ status: 'active' }, gated(path), 'Close case');
    expect(calls).toContain(`POST ${path}`);
    await until(() => document.getElementById('close-stepup-code') !== null);
    expect(copy()).toMatch(/ends the settlement/i);
  });

  it('REJECTS a review WITH the chosen reason, behind a fresh check', async () => {
    const path = `/api/settlement/cases/${CASE_ID}/review`;
    await freshLoad();
    const kase = { ...REPORTED, status: 'verifying' };
    transport({ ...WORKLISTS([kase], []), ...CASE_ROUTES(kase), ...gated(path) });
    await render();
    await openCase();
    (app().querySelector('#reject-reason') as HTMLSelectElement).value = 'duplicate_report';
    await pressing('Reject review');
    expect(calls).toContain(`POST ${path}`);
    await until(() => document.getElementById('reject-stepup-code') !== null);
    expect(copy()).toMatch(/closes this case and restores the account/i);
  });

  const VERIFIED = { status: 'verified', verifiedAt: '2026-08-04T00:00:00.000Z' };
  const STAGE = {
    stageId: 'st-9',
    stage: 'documents',
    status: 'requested',
    requestedBy: 'u-exec',
    requestedAt: '2026-08-03T00:00:00.000Z',
    decidedBy: null,
    decidedAt: null,
  };

  const withStage = (stage: Record<string, unknown>): Record<string, Reply> => ({
    [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 200, body: [{ ...STAGE, ...stage }] },
  });

  it.each([
    ['Approve stage', 'requested', 'st-9', '/decision'],
    ['Deny stage', 'requested', 'st-9', '/decision'],
    ['Revoke stage', 'approved', 'st-9', '/revoke'],
  ])('%s reaches the stage route, behind a fresh check', async (label, status, id, suffix) => {
    const path = `/api/settlement/stages/${id}${suffix}`;
    await drive(VERIFIED, { ...withStage({ status }), ...gated(path) }, label);
    expect(calls).toContain(`POST ${path}`);
  });

  it('APPROVES a distribution, behind a fresh check', async () => {
    const path = '/api/settlement/distributions/d-9/approval';
    await drive(
      { status: 'distributing' },
      {
        [`/api/settlement/cases/${CASE_ID}/distributions`]: {
          status: 200,
          body: [
            {
              distributionId: 'd-9',
              beneficiaryContactId: 'c-1',
              assetId: 'a-1',
              status: 'pending',
              createdBy: 'u-op1',
              approvedBy: null,
              hasAmount: false,
              createdAt: '2026-08-05T00:00:00.000Z',
            },
          ],
        },
        ...gated(path),
      },
      'Approve distribution',
    );
    expect(calls).toContain(`POST ${path}`);
    await until(() => document.getElementById('distribution-stepup-code') !== null);
    // The hint names the dual control, because that is what a refusal here means.
    expect(copy()).toMatch(/cannot be the one who approves it/i);
  });

  it('BACK TO WORKLISTS WITHDRAWS CONSENT — the loop stops and the case stays open', async () => {
    /*
     * MEASURED BEFORE THIS WAS FIXED, and it is the reason `stepUpPrompt`
     * returns a handle rather than an element. The back control cleared the
     * module's `pending` reference, which forgets the FORM and not the
     * CEREMONY: the polling loop lived on in its closure, and two seconds after
     * the operator navigated away it landed the third POST and CLOSED THE CASE
     * — an irreversible verb on a death case, applied after consent was
     * withdrawn, with nothing on screen to say it had happened.
     *
     * The M13 review's finding against the main app ("Cancel did not cancel"),
     * arriving through the one door this console has and that one did not.
     *
     * The route answers `stepup_required` twice and then 200: so a surviving
     * loop does not merely retry, it SUCCEEDS, which is the outcome worth
     * asserting against.
     */
    await freshLoad();
    try {
      const kase = { ...REPORTED, status: 'active' };
      const path = `/api/settlement/cases/${CASE_ID}/close`;
      let closes = 0;
      transport({
        ...WORKLISTS([], [kase]),
        ...CASE_ROUTES(kase),
        'POST /api/auth/stepup': { status: 200, body: { ok: true } },
        [`POST ${path}`]: () => {
          closes += 1;
          return closes < 3
            ? { status: 403, body: { error: 'stepup_required' } }
            : { status: 200, body: { status: 'closed' } };
        },
      });
      await render();
      await openCase();
      await pressing('Close case');
      await until(() => document.getElementById('close-stepup-code') !== null);
      expect(closes).toBe(1);

      // FAKE TIMERS FROM HERE, so the loop's two-second sleep is under our
      // control; everything above needs real ones and none of it sleeps.
      jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
      // A genuine code: identity accepts it and the loop starts polling.
      const field = document.getElementById('close-stepup-code') as HTMLInputElement;
      field.value = '123456';
      field.form?.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
      await drain();
      expect(closes).toBe(2);

      const back = [...app().querySelectorAll('button')].find(
        (b) => b.textContent === 'Back to worklists',
      ) as HTMLButtonElement;
      back.click();
      await drain();
      expect(document.getElementById('close-stepup-code')).toBeNull();

      // Past a full retry interval, which is when a surviving loop would land.
      jest.advanceTimersByTime(2_500);
      await drain();
      expect(closes).toBe(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it('offers NO approval on a distribution somebody has already approved', async () => {
    await freshLoad();
    const kase = { ...REPORTED, status: 'distributing' };
    transport({
      ...WORKLISTS([], [kase]),
      ...CASE_ROUTES(kase),
      [`/api/settlement/cases/${CASE_ID}/distributions`]: {
        status: 200,
        body: [
          {
            distributionId: 'd-9',
            beneficiaryContactId: 'c-1',
            assetId: null,
            status: 'approved',
            createdBy: 'u-op1',
            approvedBy: 'u-op2',
            hasAmount: true,
            createdAt: '2026-08-05T00:00:00.000Z',
          },
        ],
      },
    });
    await render();
    await openCase();
    expect([...app().querySelectorAll('button')].map((b) => b.textContent)).not.toContain(
      'Approve distribution',
    );
  });
});

describe('a case that will not load', () => {
  it('offers a way back rather than a dead screen', async () => {
    transport({
      ...WORKLISTS([REPORTED], []),
      [`/api/settlement/cases/${CASE_ID}`]: { status: 503, body: { error: 'unavailable' } },
      [`/api/settlement/cases/${CASE_ID}/timeline`]: { status: 503, body: {} },
      [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 503, body: {} },
      [`/api/settlement/cases/${CASE_ID}/distributions`]: { status: 503, body: {} },
    });
    await render();
    await openCase();
    expect(copy()).toMatch(/not answering just now/i);
    await pressing('Back to worklists');
    await until(() => copy().includes('Review queue'));
  });

  it('shows the CASE even when its timeline and stages are refused', async () => {
    // Four independent reads, four independent answers: a case whose timeline
    // is unavailable is still a case an operator may need to act on.
    transport({
      ...WORKLISTS([REPORTED], []),
      [`/api/settlement/cases/${CASE_ID}`]: { status: 200, body: REPORTED },
      [`/api/settlement/cases/${CASE_ID}/timeline`]: { status: 503, body: {} },
      [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 503, body: {} },
      [`/api/settlement/cases/${CASE_ID}/distributions`]: { status: 503, body: {} },
    });
    await render();
    await openCase();

    /*
     * REWRITTEN BY M21 PR4'S REVIEW. This asserted `/Nothing recorded yet/` —
     * i.e. it pinned the defect. The case DOES still render, which is the half
     * the name is about and is still asserted below; what it also did was
     * accept an affirmative "nothing exists" as the right answer to three reads
     * that had just 503'd.
     *
     * The staged-access line is the one that mattered: "No stage has been
     * requested on this case" is a claim that nobody has asked for access to a
     * dead person's vault, and it was being made on the strength of not
     * knowing. `settlement.ts` already states the rule — a response missing its
     * fields is NO DATA, never data.
     */
    expect(copy()).not.toMatch(/Nothing recorded yet/);
    expect(copy()).not.toMatch(/No stage has been requested/);
    expect(copy()).not.toMatch(/Nothing has been recorded for distribution/);
    expect(copy().match(/could not be loaded/g)).toHaveLength(3);
    expect([...app().querySelectorAll('button')].map((b) => b.textContent)).toContain(
      'Start review',
    );
  });

  it('an EMPTY read still says nothing is here — the two answers stay apart', async () => {
    // The other half, and the reason this is a distinction rather than a
    // blanket warning: a case that genuinely has no stages must still say so,
    // or the screen cries wolf on every ordinary case and the notice stops
    // being read (the M5 permanently-red-gate lesson).
    transport({
      ...WORKLISTS([REPORTED], []),
      [`/api/settlement/cases/${CASE_ID}`]: { status: 200, body: REPORTED },
      [`/api/settlement/cases/${CASE_ID}/timeline`]: { status: 200, body: [] },
      [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 200, body: [] },
      [`/api/settlement/cases/${CASE_ID}/distributions`]: { status: 200, body: [] },
    });
    await render();
    await openCase();

    expect(copy()).toMatch(/No stage has been requested/);
    expect(copy()).toMatch(/Nothing has been recorded for distribution/);
    expect(copy()).toMatch(/Nothing recorded yet/);
    expect(copy()).not.toMatch(/could not be loaded/);
  });

  it('ONE refused read does not make the other two claim to be unreadable', async () => {
    // Per-section, not per-screen: the panels that answered are still worth
    // reading, and a blanket banner would hide which one is missing.
    transport({
      ...WORKLISTS([REPORTED], []),
      [`/api/settlement/cases/${CASE_ID}`]: { status: 200, body: REPORTED },
      [`/api/settlement/cases/${CASE_ID}/timeline`]: { status: 200, body: [] },
      [`/api/settlement/cases/${CASE_ID}/stages`]: { status: 503, body: {} },
      [`/api/settlement/cases/${CASE_ID}/distributions`]: { status: 200, body: [] },
    });
    await render();
    await openCase();

    expect(copy().match(/could not be loaded/g)).toHaveLength(1);
    expect(copy()).not.toMatch(/No stage has been requested/);
    expect(copy()).toMatch(/Nothing has been recorded for distribution/);
    expect(copy()).toMatch(/Nothing recorded yet/);
  });
});
