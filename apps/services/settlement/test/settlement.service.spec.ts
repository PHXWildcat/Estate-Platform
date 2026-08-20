import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { auditActions, auditEvents, buildHarness, NOW, type Harness } from './support';
import {
  breadthExceeded,
  OPERATOR_BREADTH_MAX_CASES,
  PERMISSIVE_OPERATOR_ACTIONS,
} from '../src/operator-breadth';
import type { OperatorBreadthMonitor } from '../src/operator-breadth.monitor';

const DECEDENT = randomUUID();
const REPORTER = randomUUID();
const OPERATOR = randomUUID();
const SECOND_OPERATOR = randomUUID();
const STRANGER = randomUUID();
const SESSION = randomUUID();

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

function linkedHarness(): Harness {
  const h = buildHarness();
  h.coreReads.link(DECEDENT, REPORTER);
  h.operators.active.add(OPERATOR);
  h.operators.active.add(SECOND_OPERATOR);
  return h;
}

async function reportCase(h: Harness): Promise<string> {
  const dto = await h.service.report(REPORTER, SESSION, {
    decedentUserId: DECEDENT,
    source: 'trusted_contact',
    evidence: [],
  });
  return dto.caseId;
}

/**
 * The refusal a caller actually receives, as a comparable VALUE: HTTP status
 * and response body together.
 *
 * Exists because `rejects.toThrow(SomeException)` cannot express the property
 * a uniform refusal has — two refusals being the SAME — and this repo's
 * enumeration oracles have all lived in the gap between "both were refused"
 * and "both were refused identically". Throws if the call RESOLVES, so a
 * comparison can never be made between two non-refusals.
 */
async function refusalOf(call: () => Promise<unknown>): Promise<{ status: number; body: unknown }> {
  try {
    await call();
  } catch (err) {
    const http = err as HttpException;
    return { status: http.getStatus(), body: http.getResponse() };
  }
  throw new Error('expected a refusal, but the call resolved');
}

/** report → startReview → approve, leaving the case in waiting_period. */
async function approvedCase(h: Harness): Promise<string> {
  const caseId = await reportCase(h);
  await h.service.startReview(OPERATOR, SESSION, caseId);
  await h.service.decideReview(OPERATOR, SESSION, caseId, { decision: 'approve' });
  return caseId;
}

describe('intake (docs/03 §5.1: reports only OPEN a case)', () => {
  it('a linked contact opens a case: reported status, seq-0 contact, audit, notification', async () => {
    const h = linkedHarness();
    const dto = await h.service.report(REPORTER, SESSION, {
      decedentUserId: DECEDENT,
      source: 'trusted_contact',
      evidence: [],
    });
    expect(dto.status).toBe('reported');
    expect(dto.reportedBy).toBe(REPORTER);
    expect(dto.eligibleForVerification).toBe(false);
    // The report itself locks nothing and grants nothing.
    expect(h.identity.setStateCalls).toEqual([]);
    // seq 0: the owner hears immediately.
    expect(h.attempts.rows).toEqual([
      expect.objectContaining({ case_id: dto.caseId, seq: 0, channel: 'push' }),
    ]);
    expect(h.notifier.sent).toEqual([
      expect.objectContaining({ kind: 'case_opened', ownerUserId: DECEDENT }),
    ]);
    const events = auditEvents(h.producer);
    // TWO events, and the second is M14's PROCEED-AND-RECORD half. The stub
    // notifier reports an unverified recipient (it must never vouch for one),
    // so opening this case also records that the owner alert went to an address
    // nobody proved. The case still opens — refusing would deny a legitimate
    // reporter the §5.1 chain — but an operator reviewing it, or an
    // investigation reading it later, can now tell a waiting period the owner
    // could have interrupted from one they could not.
    expect(events.map((event) => event['action'])).toEqual([
      'settlement.case.reported',
      'settlement.unverified_recipient',
    ]);
    expect(events[0]).toMatchObject({
      action: 'settlement.case.reported',
      actorId: REPORTER,
      onBehalfOf: DECEDENT,
    });
    expect(events[0]?.['detail']).toMatchObject({ source: 'trusted_contact' });
    expect(events[1]).toMatchObject({
      actorType: 'system',
      onBehalfOf: DECEDENT,
      resourceId: dto.caseId,
    });
  });

  it('does NOT swallow a broker failure on the unverified-recipient evidence', async () => {
    // Round 2 of the M14 review: the restructure that moved this emit out of
    // the delivery catch shipped with nothing able to tell it from its revert.
    // The catch was written for a CARRIER failure; an audit emit failing is a
    // different fault, and the §5.1 evidence that the decedent was alerted at
    // an unproved address is exactly what an investigation reads. The vault
    // sibling propagates and the M13 rule is that an audit emit is loud.
    const h = linkedHarness();
    // WRAP rather than replace: the in-memory producer records into `messages`
    // inside `send`, so a bare override would break every other assertion in
    // the harness rather than isolate this one.
    const original = h.producer.send.bind(h.producer);
    h.producer.send = (message: { topic: string; key: string; value: string }): Promise<void> =>
      message.value.includes('settlement.unverified_recipient')
        ? Promise.reject(new Error('broker down'))
        : original(message);

    await expect(
      h.service.report(REPORTER, SESSION, {
        decedentUserId: DECEDENT,
        source: 'trusted_contact',
        evidence: [],
      }),
    ).rejects.toThrow('broker down');
  });

  it('death-certificate evidence is recorded with its attacher (the documents cross-check key)', async () => {
    const h = linkedHarness();
    const documentId = randomUUID();
    const dto = await h.service.report(REPORTER, SESSION, {
      decedentUserId: DECEDENT,
      source: 'death_certificate_upload',
      evidence: [{ type: 'document', documentId, version: 1 }],
    });
    expect(dto.evidence).toEqual([
      expect.objectContaining({ type: 'document', documentId, version: 1, addedBy: REPORTER }),
    ]);
  });

  it('an unlinked caller gets a uniform not_found (no enumeration oracle)', async () => {
    const h = buildHarness();
    await expect(
      h.service.report(STRANGER, SESSION, {
        decedentUserId: DECEDENT,
        source: 'trusted_contact',
        evidence: [],
      }),
    ).rejects.toThrow(NotFoundException);
    expect(h.cases.rows.size).toBe(0);
    expect(h.producer.messages).toHaveLength(0);
  });

  it('rejects self-reports', async () => {
    const h = buildHarness();
    h.coreReads.link(DECEDENT, DECEDENT);
    await expect(
      h.service.report(DECEDENT, SESSION, {
        decedentUserId: DECEDENT,
        source: 'trusted_contact',
        evidence: [],
      }),
    ).rejects.toThrow(BadRequestException);
  });

  it('enforces one OPEN case per decedent (409 case_exists)', async () => {
    const h = linkedHarness();
    await reportCase(h);
    await expect(reportCase(h)).rejects.toMatchObject({
      response: { error: 'case_exists' },
    });
  });

  it('refuses intake in production while only the stub notifier is wired', async () => {
    const h = buildHarness({ config: { nodeEnv: 'production' } });
    h.coreReads.link(DECEDENT, REPORTER);
    await expect(
      h.service.report(REPORTER, SESSION, {
        decedentUserId: DECEDENT,
        source: 'trusted_contact',
        evidence: [],
      }),
    ).rejects.toThrow(ServiceUnavailableException);
    expect(h.cases.rows.size).toBe(0);
  });

  it('provider signals are operator-filed only', async () => {
    const h = linkedHarness();
    await expect(
      h.service.reportProviderSignal(STRANGER, SESSION, {
        decedentUserId: DECEDENT,
        providerMatchIds: ['lexis:match:123'],
      }),
    ).rejects.toThrow(ForbiddenException);
    const dto = await h.service.reportProviderSignal(OPERATOR, SESSION, {
      decedentUserId: DECEDENT,
      providerMatchIds: ['lexis:match:123'],
    });
    expect(dto.reportSource).toBe('data_provider');
    expect(dto.evidence).toEqual([
      expect.objectContaining({ type: 'provider_match', matchId: 'lexis:match:123' }),
    ]);

    /*
     * AND THE TRAIL SAYS AN OPERATOR FILED IT. `caseReported` serves both
     * intake paths and used to hardcode `actorType: 'user'`, while its own
     * docstring said "or an operator filing provider signals" — the claim and
     * the code disagreeing inside one function.
     *
     * The fact was recoverable from `detail.source === 'data_provider'`, but
     * only as a POSITIONAL proxy: it holds while that source has exactly one
     * writer, which is the shape §6aa criticised in Cedar's literal `true`.
     * This is the §5.1 intake path that needs no linked contact — the one way
     * to open a death case against any account — so who filed it is the fact
     * the trail must not get wrong.
     *
     * The assertions above are why this was green: they read the DTO and never
     * the envelope.
     */
    const reported = auditEvents(h.producer).filter(
      (e) => e['action'] === 'settlement.case.reported',
    );
    expect(reported).toHaveLength(1);
    expect(reported[0]?.['actorType']).toBe('operator');
    expect(reported[0]?.['actorId']).toBe(OPERATOR);
  });
});

describe('review (docs/03 §5.1 control 2: mandatory human review)', () => {
  it('asks the allowlist on the TRANSACTION handle, not the pool', async () => {
    // The BEHAVIOURAL half of OperatorGate's handle contract. Until M21 PR2's
    // review, `InMemoryOperators` discarded its first argument, so nothing
    // outside the source fence could tell `assertIn(tx, u)` from
    // `assertIn(this.db, u)` — a double more permissive than the real thing,
    // which is this repository's recurring shape one layer beneath the
    // fixtures. `fakeDb()` hands the callback a DISTINCT object, which is what
    // makes the question answerable at all.
    const h = linkedHarness();
    const caseId = await reportCase(h);
    h.operators.asked.length = 0;

    await h.service.startReview(OPERATOR, SESSION, caseId);

    expect(h.operators.asked).toHaveLength(1);
    const [ask] = h.operators.asked;
    expect(ask?.userId).toBe(OPERATOR);
    expect(ask?.handle).not.toBe(h.db);
  });

  it('asks the pool where the caller owns no transaction (queue)', async () => {
    // The other side of the same contract, so the assertion above is a
    // statement about WHICH handle rather than about "not the db, ever".
    const h = linkedHarness();
    h.operators.asked.length = 0;

    await h.service.queue(OPERATOR, SESSION);

    expect(h.operators.asked).toHaveLength(1);
    expect(h.operators.asked[0]?.handle).toBe(h.db);
  });

  it('start requires the operator allowlist; approval starts the wait and locks the account', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await expect(h.service.startReview(STRANGER, SESSION, caseId)).rejects.toThrow(
      ForbiddenException,
    );
    await h.service.startReview(OPERATOR, SESSION, caseId);

    const dto = await h.service.decideReview(OPERATOR, SESSION, caseId, { decision: 'approve' });
    expect(dto.status).toBe('waiting_period');
    // Default 5 days from approval.
    expect(dto.waitingPeriodEnds).toBe(new Date(NOW.getTime() + 5 * DAY).toISOString());
    expect(h.identity.setStateCalls).toEqual([
      { userId: DECEDENT, state: 'deceased_pending', caseId },
    ]);
    expect(auditActions(h.producer)).toEqual([
      'settlement.case.reported',
      // M14: the intake notification went to an unproved address (the stub
      // never vouches), recorded rather than refused — the actor is a reporter
      // and the recipient is the decedent.
      'settlement.unverified_recipient',
      'settlement.case.review_started',
      'settlement.case.approved',
    ]);
  });

  it('honors the owner setting but never below the 5-day floor', async () => {
    const h = linkedHarness();
    h.settings.days.set(DECEDENT, 30);
    const caseId = await reportCase(h);
    await h.service.startReview(OPERATOR, SESSION, caseId);
    const dto = await h.service.decideReview(OPERATOR, SESSION, caseId, { decision: 'approve' });
    expect(dto.waitingPeriodEnds).toBe(new Date(NOW.getTime() + 30 * DAY).toISOString());
  });

  it('the reporter can never review their own report, allowlisted or not', async () => {
    const h = linkedHarness();
    h.operators.active.add(REPORTER);
    const caseId = await reportCase(h);
    await h.service.startReview(OPERATOR, SESSION, caseId);
    await expect(
      h.service.decideReview(REPORTER, SESSION, caseId, { decision: 'approve' }),
    ).rejects.toMatchObject({ response: { error: 'reviewer_is_reporter' } });
  });

  it('approve is refused outside verifying (no review-skipping)', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await expect(
      h.service.decideReview(OPERATOR, SESSION, caseId, { decision: 'approve' }),
    ).rejects.toMatchObject({ response: { error: 'invalid_transition' } });
  });

  it('an unconfirmable account lock rolls the approval back (fail closed)', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await h.service.startReview(OPERATOR, SESSION, caseId);
    h.identity.failSetState = true;
    await expect(
      h.service.decideReview(OPERATOR, SESSION, caseId, { decision: 'approve' }),
    ).rejects.toMatchObject({ response: { error: 'identity_unavailable' } });
    // In the real DB the transaction rolls back; the audit trail shows no approval.
    expect(auditActions(h.producer)).not.toContain('settlement.case.approved');
  });

  it('reject from verifying records the rejecting reviewer and preserves the reporter id', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await h.service.startReview(OPERATOR, SESSION, caseId);
    const dto = await h.service.decideReview(OPERATOR, SESSION, caseId, {
      decision: 'reject',
      reason: 'fraud_suspected',
    });
    expect(dto.status).toBe('rejected_fraud');
    expect(dto.resolution).toBe('operator_rejected');
    expect(dto.humanReviewBy).toBe(OPERATOR);
    // Never locked, so nothing to restore.
    expect(h.identity.setStateCalls).toEqual([]);
    const rejected = auditEvents(h.producer).find(
      (e) => e['action'] === 'settlement.case.rejected',
    );
    expect(rejected?.['detail']).toEqual(
      expect.objectContaining({ reason: 'fraud_suspected', reporter: REPORTER }),
    );
  });

  it('reject from waiting_period restores the account to active', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    await h.service.decideReview(SECOND_OPERATOR, SESSION, caseId, {
      decision: 'reject',
      reason: 'insufficient_evidence',
    });
    expect(h.identity.setStateCalls).toEqual([
      { userId: DECEDENT, state: 'deceased_pending', caseId },
      { userId: DECEDENT, state: 'active', caseId },
    ]);
  });
});

describe('owner void (docs/03 §5.1 control 3: the kill switch)', () => {
  it('the owner voids a pending case; the reporter is flagged; the account restores', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    const dto = await h.service.void(DECEDENT, SESSION, caseId);
    expect(dto.status).toBe('rejected_fraud');
    expect(dto.resolution).toBe('owner_voided');
    expect(h.identity.setStateCalls).toContainEqual({
      userId: DECEDENT,
      state: 'active',
      caseId,
    });
    const voided = auditEvents(h.producer).find((e) => e['action'] === 'settlement.case.voided');
    expect(voided).toMatchObject({
      actorId: DECEDENT,
      detail: { via: 'owner_route', reporter: REPORTER, reporterFlagged: true },
    });
  });

  it('only the case subject can void — not the reporter, not an operator', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await expect(h.service.void(REPORTER, SESSION, caseId)).rejects.toThrow(NotFoundException);
    await expect(h.service.void(OPERATOR, SESSION, caseId)).rejects.toThrow(NotFoundException);
  });

  /**
   * THE ORACLE THIS ROUTE CARRIED UNTIL M22 PR3, and the reason no existing
   * test saw it: the two assertions above pinned the exception TYPE, which was
   * `ForbiddenException`, and a type assertion is green whether or not the
   * answer distinguishes anything. The property is not "a stranger is refused"
   * — it is "the refusal a stranger gets is BYTE-IDENTICAL to the one an absent
   * case gets", and nothing compared the two answers.
   *
   * Compared as VALUES, both arms, in one assertion: status and body together.
   * A version that checked only the status would go green against a 404 whose
   * body still said `forbidden`.
   */
  it('void answers one uniform 404 for "not yours" and "no such case" alike', async () => {
    const h = linkedHarness();
    const realCase = await reportCase(h);
    const absent = randomUUID();

    const notYours = await refusalOf(() => h.service.void(STRANGER, SESSION, realCase));
    const noSuchCase = await refusalOf(() => h.service.void(STRANGER, SESSION, absent));

    expect(notYours).toEqual(noSuchCase);
    expect(notYours).toEqual({ status: 404, body: { error: 'not_found' } });
  });

  /**
   * POSITIVE CONTROL for the assertion above. The uniformity test alone is
   * equally consistent with a `void` that refuses EVERYONE — including the
   * owner — which is the failure this repo calls out by name ("fail closed
   * means DE-ESCALATE, not refuse everything"). This says the protective path
   * still works, so the pair can only be green when the oracle is closed AND
   * the kill switch is live.
   */
  it('...and the owner it protects can still void (the refusal is not universal)', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await expect(h.service.void(DECEDENT, SESSION, caseId)).resolves.toMatchObject({
      resolution: 'owner_voided',
    });
  });

  it('void is refused post-verification (rescue becomes an operator ceremony)', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    await h.service.confirmVerification(OPERATOR, SESSION, caseId);
    await expect(h.service.void(DECEDENT, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'invalid_transition' },
    });
  });
});

/**
 * THE SECOND MEMBER OF `void`'s CATEGORY (M22 PR3), and the reason it needed
 * asking for: it reads like an operator path and is not one. The three genuine
 * operator writes call `OperatorGate.assertIn`, which REFUSES a non-operator
 * before any row is fetched — so a stranger never learns whether the id was
 * real. `addEvidence` calls `gate.is`, which MEASURES operator-ness into a
 * boolean and refuses nobody, so a stranger reaches the Cedar decision with a
 * located row behind it.
 *
 * Nothing here had ever exercised an `addEvidence` refusal — the whole suite
 * was green either way, which is the warning this milestone was told to expect.
 * Its consumer arrives in PR4; the oracle was reachable now.
 */
describe('evidence attach refuses uniformly (void’s category, second member)', () => {
  const EVIDENCE = { type: 'provider_match', matchId: 'm-1' } as const;

  it('answers one uniform 404 for "not yours" and "no such case" alike', async () => {
    const h = linkedHarness();
    const realCase = await reportCase(h);
    const absent = randomUUID();

    const notYours = await refusalOf(() =>
      h.service.addEvidence(STRANGER, SESSION, realCase, EVIDENCE),
    );
    const noSuchCase = await refusalOf(() =>
      h.service.addEvidence(STRANGER, SESSION, absent, EVIDENCE),
    );

    expect(notYours).toEqual(noSuchCase);
    expect(notYours).toEqual({ status: 404, body: { error: 'not_found' } });
  });

  /** Positive control — the reporter this route exists for still reaches it. */
  it('...and the reporter who filed the case can still attach (not universal)', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await expect(h.service.addEvidence(REPORTER, SESSION, caseId, EVIDENCE)).resolves.toMatchObject(
      {
        evidence: [expect.objectContaining({ type: 'provider_match', addedBy: REPORTER })],
      },
    );
  });
});

describe('verification (timer expiry is necessary, never sufficient)', () => {
  it('refuses before the waiting period lapses', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 4 * DAY);
    await expect(h.service.confirmVerification(OPERATOR, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'waiting_period_active' },
    });
  });

  it('verifies after the lapse: status, verified_at, and the settlement lock', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    const dto = await h.service.confirmVerification(OPERATOR, SESSION, caseId);
    expect(dto.status).toBe('verified');
    expect(dto.verifiedAt).toBe(h.clock.value.toISOString());
    expect(h.identity.setStateCalls.map((c) => [c.userId, c.state, c.caseId])).toEqual([
      [DECEDENT, 'deceased_pending', caseId],
      [DECEDENT, 'settlement', caseId],
    ]);
    // Only the terminal transition carries the liveness watermark.
    expect(h.identity.setStateCalls[0]?.livenessNotAfter).toBeUndefined();
    expect(h.identity.setStateCalls[1]?.livenessNotAfter).toBeInstanceOf(Date);
    expect(auditActions(h.producer)).toContain('settlement.case.verified');
  });

  it('an owner step-up during the wait voids the case at confirmation time', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    // The owner stepped up two days into the wait.
    h.identity.livenessAnswer = {
      status: 'deceased_pending',
      lastStepUpAt: new Date(NOW.getTime() + 2 * DAY),
    };
    await expect(h.service.confirmVerification(OPERATOR, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'owner_alive' },
    });
    const row = h.cases.rows.get(caseId);
    expect(row?.status).toBe('rejected_fraud');
    expect(row?.resolution).toBe('owner_voided');
    expect(h.identity.setStateCalls).toContainEqual({
      userId: DECEDENT,
      state: 'active',
      caseId,
    });
    const voided = auditEvents(h.producer).find((e) => e['action'] === 'settlement.case.voided');
    expect(voided?.['detail']).toEqual(
      expect.objectContaining({ via: 'liveness_check', reporterFlagged: true }),
    );
    expect(auditActions(h.producer)).not.toContain('settlement.case.verified');
  });

  it('passes the case-opening watermark so identity can re-check liveness atomically', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    const opened = h.cases.rows.get(caseId)?.created_at;
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    await h.service.confirmVerification(OPERATOR, SESSION, caseId);
    const settle = h.identity.setStateCalls.find((c) => c.state === 'settlement');
    expect(settle?.livenessNotAfter).toEqual(opened);
  });

  it('a step-up racing the commit voids the case instead of entombing a living owner', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    // Liveness read says "no step-up"; the step-up lands immediately after,
    // so identity's atomic interlock refuses the terminal transition.
    h.identity.livenessAnswer = { status: 'deceased_pending', lastStepUpAt: null };
    h.identity.raceStepUpAt = new Date(NOW.getTime() + 5 * DAY);
    await expect(h.service.confirmVerification(OPERATOR, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'owner_alive' },
    });
    const row = h.cases.rows.get(caseId);
    expect(row?.status).toBe('rejected_fraud');
    expect(row?.resolution).toBe('owner_voided');
    // The half-applied verification is unwound, and the account is restored.
    expect(row?.verified_at).toBeNull();
    expect(h.identity.setStateCalls.map((c) => c.state)).toEqual(['deceased_pending', 'active']);
    expect(auditActions(h.producer)).not.toContain('settlement.case.verified');
    expect(auditActions(h.producer)).toContain('settlement.case.voided');
  });

  it('a step-up OLDER than the case does not void (pre-existing sign-ins are not liveness)', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    h.identity.livenessAnswer = {
      status: 'deceased_pending',
      lastStepUpAt: new Date(NOW.getTime() - DAY),
    };
    const dto = await h.service.confirmVerification(OPERATOR, SESSION, caseId);
    expect(dto.status).toBe('verified');
  });

  it('an unreachable liveness answer refuses verification (fail closed)', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    h.identity.failLiveness = true;
    await expect(h.service.confirmVerification(OPERATOR, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'identity_unavailable' },
    });
    expect(h.cases.rows.get(caseId)?.status).toBe('waiting_period');
  });

  it('the reporter can never confirm verification of their own report', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.operators.active.add(REPORTER);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    await expect(h.service.confirmVerification(REPORTER, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'reviewer_is_reporter' },
    });
  });
});

describe('the estate-wide legal hold (M9 PR2: settlement → documents)', () => {
  it('approval sets the hold in the same transition as the account lock', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    expect(h.documentsHold.setHoldCalls).toEqual([{ ownerUserId: DECEDENT, hold: true, caseId }]);
  });

  it('an unconfirmable hold rolls the approval back exactly like the lock (fail closed)', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await h.service.startReview(OPERATOR, SESSION, caseId);
    h.documentsHold.failSetHold = true;
    await expect(
      h.service.decideReview(OPERATOR, SESSION, caseId, { decision: 'approve' }),
    ).rejects.toMatchObject({ response: { error: 'documents_unavailable' } });
    // In the real DB the transaction rolls back; the audit trail shows no
    // approval. The identity lock that DID land is idempotent and heals on
    // the operator's retry — the same accepted cost as a commit failure
    // after a successful lock (M7).
    expect(auditActions(h.producer)).not.toContain('settlement.case.approved');
  });

  it('reject from waiting_period lifts the hold with the account restore', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    await h.service.decideReview(OPERATOR, SESSION, caseId, {
      decision: 'reject',
      reason: 'insufficient_evidence',
    });
    expect(h.documentsHold.setHoldCalls).toEqual([
      { ownerUserId: DECEDENT, hold: true, caseId },
      { ownerUserId: DECEDENT, hold: false, caseId },
    ]);
  });

  it('reject from verifying never touches documents (nothing was locked or held)', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await h.service.startReview(OPERATOR, SESSION, caseId);
    await h.service.decideReview(OPERATOR, SESSION, caseId, {
      decision: 'reject',
      reason: 'fraud_suspected',
    });
    expect(h.documentsHold.setHoldCalls).toEqual([]);
  });

  it('the owner void lifts the hold with the restore', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    await h.service.void(DECEDENT, SESSION, caseId);
    expect(h.documentsHold.setHoldCalls).toEqual([
      { ownerUserId: DECEDENT, hold: true, caseId },
      { ownerUserId: DECEDENT, hold: false, caseId },
    ]);
  });

  it('verification re-asserts the hold: documents uploaded during the wait are covered', async () => {
    // The owner's login stays alive in deceased_pending (the rescue path), so
    // the estate can GROW between approval and verification. The invariant is
    // "every live document of a verified estate is held", enforced by
    // re-driving the idempotent sweep with the terminal lock.
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    await h.service.confirmVerification(OPERATOR, SESSION, caseId);
    expect(h.documentsHold.setHoldCalls).toEqual([
      { ownerUserId: DECEDENT, hold: true, caseId },
      { ownerUserId: DECEDENT, hold: true, caseId },
    ]);
  });

  it('a liveness void at confirmation lifts the hold with the restore', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.identity.livenessAnswer = {
      status: 'deceased_pending',
      lastStepUpAt: new Date(NOW.getTime() + HOUR),
    };
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    await expect(h.service.confirmVerification(OPERATOR, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'owner_alive' },
    });
    expect(h.documentsHold.setHoldCalls).toEqual([
      { ownerUserId: DECEDENT, hold: true, caseId },
      { ownerUserId: DECEDENT, hold: false, caseId },
    ]);
  });

  it('a documents outage at VERIFICATION never leaves the account terminally locked', async () => {
    // The M9 security review's load-bearing finding. `settlement` is the one
    // irreversible identity state (no transition back to `active`), so if the
    // lock ran before the fallible hold, a documents blip would roll the case
    // back to waiting_period while the owner stayed locked out forever — and
    // every restore path would then 503. Order is the fix: nothing
    // irreversible may run before something that can still fail.
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    h.documentsHold.failSetHold = true;
    await expect(h.service.confirmVerification(OPERATOR, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'documents_unavailable' },
    });
    // THE ASSERTION THAT PINS THE ORDERING: the terminal, irreversible
    // `settlement` transition was never even attempted, so the owner remains
    // restorable and every void/reject path still works. Only the
    // approve-time deceased_pending call is on record.
    expect(h.identity.setStateCalls.map((c) => c.state)).toEqual(['deceased_pending']);
    // In the real DB the transaction rolls back (the in-memory repos here have
    // no rollback, the sibling fail-closed tests above take the same tack), so
    // the durable evidence is the audit trail: no verification happened.
    expect(auditActions(h.producer)).not.toContain('settlement.case.verified');
  });

  it('a documents outage during the owner void refuses the void (fail closed)', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    h.documentsHold.failSetHold = true;
    await expect(h.service.void(DECEDENT, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'documents_unavailable' },
    });
    // In the real DB the transaction rolls back; the audit trail shows no
    // void. A hold outliving its case blocks only deletion — deny-safe —
    // and the owner's retry heals it.
    expect(auditActions(h.producer)).not.toContain('settlement.case.voided');
  });
});

describe('reads and the operator queue', () => {
  it('subject, reporter, and operators can read; strangers get the SAME not-found an unknown id gets', async () => {
    // The refusal is NOT_FOUND, and that is the control rather than a detail:
    // a 403 for a real case beside a 404 for an unknown one tells any
    // authenticated caller holding an id whether a death case exists for it.
    // Both answers are compared here, in one test, because the property is
    // that they are INDISTINGUISHABLE — asserting either alone would pass
    // while the pair still leaked.
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await expect(h.service.getCase(DECEDENT, SESSION, caseId)).resolves.toMatchObject({ caseId });
    await expect(h.service.getCase(REPORTER, SESSION, caseId)).resolves.toMatchObject({ caseId });
    await expect(h.service.getCase(OPERATOR, SESSION, caseId)).resolves.toMatchObject({ caseId });

    const real = await h.service.getCase(STRANGER, SESSION, caseId).catch((e: unknown) => e);
    const unknown = await h.service
      .getCase(STRANGER, SESSION, '00000000-0000-4000-8000-0000000000ff')
      .catch((e: unknown) => e);
    expect(real).toBeInstanceOf(NotFoundException);
    expect((real as NotFoundException).getStatus()).toBe(
      (unknown as NotFoundException).getStatus(),
    );
    expect((real as NotFoundException).getResponse()).toEqual(
      (unknown as NotFoundException).getResponse(),
    );
  });

  it('the queue is operator-only and lists pre-verification cases', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    await expect(h.service.queue(STRANGER, SESSION)).rejects.toThrow(ForbiddenException);
    const queue = await h.service.queue(OPERATOR, SESSION);
    expect(queue).toEqual([expect.objectContaining({ caseId })]);
  });

  it('eligibleForVerification flips when the deadline lapses, without any state change', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);
    let dto = await h.service.getCase(OPERATOR, SESSION, caseId);
    expect(dto.eligibleForVerification).toBe(false);
    h.clock.value = new Date(NOW.getTime() + 5 * DAY + HOUR);
    dto = await h.service.getCase(OPERATOR, SESSION, caseId);
    expect(dto.eligibleForVerification).toBe(true);
    expect(dto.status).toBe('waiting_period'); // the clock moved nothing
  });
});

describe('settings (waiting period, configurable UP only)', () => {
  it('defaults to 5 days and updates with audit', async () => {
    const h = buildHarness();
    await expect(h.service.getSettings(DECEDENT)).resolves.toEqual({ waitingPeriodDays: 5 });
    await h.service.updateSettings(DECEDENT, SESSION, { waitingPeriodDays: 21 });
    await expect(h.service.getSettings(DECEDENT)).resolves.toEqual({ waitingPeriodDays: 21 });
    expect(auditActions(h.producer)).toContain('settlement.settings.updated');
  });

  it('refuses changes while a case is open (a pending case freezes its parameters)', async () => {
    const h = linkedHarness();
    await reportCase(h);
    await expect(
      h.service.updateSettings(DECEDENT, SESSION, { waitingPeriodDays: 10 }),
    ).rejects.toMatchObject({ response: { error: 'case_open' } });
  });
});

describe('evidence-read authority (the documents cross-check)', () => {
  it('answers only for operators, only for registered evidence, with the attacher id', async () => {
    const h = linkedHarness();
    const documentId = randomUUID();
    const dto = await h.service.report(REPORTER, SESSION, {
      decedentUserId: DECEDENT,
      source: 'death_certificate_upload',
      evidence: [{ type: 'document', documentId, version: 2 }],
    });
    await expect(h.service.evidenceReadAuthority(STRANGER, documentId, 2)).resolves.toEqual({
      allowed: false,
      caseId: null,
      ownerUserId: null,
    });
    await expect(h.service.evidenceReadAuthority(OPERATOR, randomUUID(), 2)).resolves.toEqual({
      allowed: false,
      caseId: null,
      ownerUserId: null,
    });
    await expect(h.service.evidenceReadAuthority(OPERATOR, documentId, 1)).resolves.toEqual({
      allowed: false,
      caseId: null,
      ownerUserId: null,
    });
    await expect(h.service.evidenceReadAuthority(OPERATOR, documentId, 2)).resolves.toEqual({
      allowed: true,
      caseId: dto.caseId,
      ownerUserId: REPORTER,
    });
  });
});

describe('the contact sweep (the driver holds no transition power)', () => {
  it('records escalating attempts on the 12h schedule, idempotently, capped at the deadline', async () => {
    const h = linkedHarness();
    const caseId = await approvedCase(h);

    // Immediately after approval: seq 1 (seq 0 was the report-time notice).
    let result = await h.service.runContactSweep(h.clock.value);
    expect(result.attempts).toBe(1);
    // Re-running the sweep at the same instant adds nothing.
    result = await h.service.runContactSweep(h.clock.value);
    expect(result.attempts).toBe(0);

    // 25h in: seqs 2 and 3 are due; channels cycle push→email→sms→voice.
    h.clock.value = new Date(NOW.getTime() + 25 * HOUR);
    result = await h.service.runContactSweep(h.clock.value);
    expect(result.attempts).toBe(2);
    expect(h.attempts.rows.map((r) => [r.seq, r.channel])).toEqual([
      [0, 'push'],
      [1, 'push'],
      [2, 'email'],
      [3, 'sms'],
    ]);

    // Far past the deadline: the schedule is capped at waiting_period_ends
    // (5 days / 12h = 10 slots + the approval slot = seq 11).
    h.clock.value = new Date(NOW.getTime() + 30 * DAY);
    await h.service.runContactSweep(h.clock.value);
    const seqs = h.attempts.rows.map((r) => r.seq);
    expect(Math.max(...seqs)).toBe(11);

    // Every attempt was notified and audited; the case never moved.
    expect(h.notifier.sent.filter((n) => n.kind === 'owner_contact')).toHaveLength(11);
    expect(
      auditActions(h.producer).filter((a) => a === 'settlement.contact.attempted'),
    ).toHaveLength(11);
    expect(h.cases.rows.get(caseId)?.status).toBe('waiting_period');
  });

  it('system attempts are audited with actorType system and a null actor', async () => {
    const h = linkedHarness();
    await approvedCase(h);
    await h.service.runContactSweep(h.clock.value);
    const attempt = auditEvents(h.producer).find(
      (e) => e['action'] === 'settlement.contact.attempted',
    );
    expect(attempt).toMatchObject({ actorType: 'system', actorId: null, onBehalfOf: DECEDENT });
  });
});

describe('intake counts toward operator breadth (docs/03 §6ii, the closed residual)', () => {
  /**
   * The first slice left this route uncounted because `insertCase` owns the
   * transaction and the caller does not. It is counted now, and the property
   * that matters is not "does it record" — it is WHICH ARM records. The two
   * intake paths pass the same `reportedBy` and differ only in the AUTHORITY
   * that admitted them, so the test that decides this must exercise the case
   * where those two facts DISAGREE: an operator who is also a linked contact.
   */
  function spy(answer: number): {
    monitor: OperatorBreadthMonitor;
    calls: Array<{ operator: string; caseId: string; action: string }>;
  } {
    const calls: Array<{ operator: string; caseId: string; action: string }> = [];
    const monitor = {
      record: (
        _tx: unknown,
        operator: string,
        caseId: string,
        action: string,
        _now: Date,
      ): Promise<number> => {
        calls.push({ operator, caseId, action });
        return Promise.resolve(answer);
      },
      exceeded: (n: number): boolean => breadthExceeded(n),
    } as unknown as OperatorBreadthMonitor;
    return { monitor, calls };
  }

  const warnings = (h: Harness): string[] =>
    h.producer.messages
      .map((m) => String(m.value))
      .filter((v) => v.includes('settlement.operator.breadth_exceeded'));

  it('declares case.reported as a permissive kind', () => {
    expect([...PERMISSIVE_OPERATOR_ACTIONS]).toContain('case.reported');
  });

  it('counts a provider signal against the operator who filed it', async () => {
    const { monitor, calls } = spy(1);
    const h = buildHarness({ monitor });
    h.operators.active.add(OPERATOR);
    const dto = await h.service.reportProviderSignal(OPERATOR, SESSION, {
      decedentUserId: DECEDENT,
      providerMatchIds: ['m1'],
    });
    // The case id is the one just created — the ledger row and the case were
    // written in the same transaction, so there is no other id it could be.
    expect(calls).toEqual([{ operator: OPERATOR, caseId: dto.caseId, action: 'case.reported' }]);
  });

  it('counts NOTHING when an OPERATOR reports through the contact path', async () => {
    // THE DISAGREEING ARM. `reportedBy` is an allowlisted operator here and the
    // authority used is the linked-contact check, so the two facts point
    // opposite ways. Deriving `countBreadthFor` from `reportedBy` — the obvious
    // simplification — type-checks perfectly and is wrong exactly here.
    const { monitor, calls } = spy(1);
    const h = buildHarness({ monitor });
    h.coreReads.link(DECEDENT, OPERATOR);
    h.operators.active.add(OPERATOR);
    await h.service.report(OPERATOR, SESSION, {
      decedentUserId: DECEDENT,
      source: 'trusted_contact',
      evidence: [],
    });
    expect(calls).toEqual([]);
  });

  it('records nothing when the case already exists', async () => {
    // One open case per decedent. A refused intake must leave no ledger row,
    // or an operator is charged for work the platform declined to do.
    const { monitor, calls } = spy(1);
    const h = buildHarness({ monitor });
    h.operators.active.add(OPERATOR);
    await h.service.reportProviderSignal(OPERATOR, SESSION, {
      decedentUserId: DECEDENT,
      providerMatchIds: ['m1'],
    });
    calls.length = 0;
    await expect(
      h.service.reportProviderSignal(OPERATOR, SESSION, {
        decedentUserId: DECEDENT,
        providerMatchIds: ['m2'],
      }),
    ).rejects.toThrow();
    expect(calls).toEqual([]);
  });

  it('WARNS above the ceiling and still opens the case', async () => {
    const { monitor } = spy(OPERATOR_BREADTH_MAX_CASES + 1);
    const h = buildHarness({ monitor });
    h.operators.active.add(OPERATOR);
    const dto = await h.service.reportProviderSignal(OPERATOR, SESSION, {
      decedentUserId: DECEDENT,
      providerMatchIds: ['m1'],
    });
    expect(dto.caseId).toBeDefined();
    expect(warnings(h)).toHaveLength(1);
  });

  it('stays silent at the ceiling', async () => {
    const { monitor } = spy(OPERATOR_BREADTH_MAX_CASES);
    const h = buildHarness({ monitor });
    h.operators.active.add(OPERATOR);
    await h.service.reportProviderSignal(OPERATOR, SESSION, {
      decedentUserId: DECEDENT,
      providerMatchIds: ['m1'],
    });
    expect(warnings(h)).toEqual([]);
  });
});
