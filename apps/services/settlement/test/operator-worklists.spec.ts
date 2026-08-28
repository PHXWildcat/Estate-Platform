import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ForbiddenException } from '@nestjs/common';
import { ADMINISTRABLE_STATUSES, QUEUE_STATUSES } from '../src/cases.repo';
import {
  auditActions,
  auditEvents,
  buildAdminHarness,
  buildHarness,
  markCaseVerified,
  NOW,
  type AdminHarness,
  type Harness,
} from './support';

/**
 * The two operator worklists, the claim marker, and the read events — the
 * three things M21 PR3b adds to the settlement service itself.
 *
 * Each exists because of a measured absence rather than a feature request:
 * `/queue` could not reach a closeable case, `markReviewStarted` recorded the
 * claiming operator nowhere, and all 23 settlement audit actions were writes,
 * so an operator reading somebody's death case left no trace at all.
 */

const DECEDENT = randomUUID();
const REPORTER = randomUUID();
const OPERATOR = randomUUID();
const EXECUTOR = randomUUID();
const STRANGER = randomUUID();
const SESSION = randomUUID();

function linkedHarness(): Harness {
  const h = buildHarness();
  h.coreReads.link(DECEDENT, REPORTER);
  h.operators.active.add(OPERATOR);
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

async function verifiedAdminCase(h: AdminHarness): Promise<string> {
  const row = await h.cases.insert(undefined as never, {
    decedentUserId: DECEDENT,
    reportedBy: REPORTER,
    source: 'trusted_contact',
    evidence: [],
  });
  markCaseVerified(h.cases, row.id, NOW);
  // The reporter is LINKED, because intake cannot produce one who is not:
  // `report` refuses with a uniform 404 unless `isLinkedContact` holds
  // (settlement.service.ts). Leaving this out put every fixture reporter in a
  // state the product cannot reach, which is why the tests named for the
  // reporter's access were evidence about nothing.
  h.coreReads.link(DECEDENT, REPORTER);
  h.coreReads.link(DECEDENT, EXECUTOR);
  h.coreReads.executors.add(`${DECEDENT}:${EXECUTOR}`);
  h.operators.active.add(OPERATOR);
  return row.id;
}

describe('the two worklists are disjoint, and the DDL is what says so', () => {
  /**
   * Pinned against the MIGRATION rather than against a list retyped here.
   * `CaseStatus` is a type and vanishes at runtime, so a spec that declared
   * its own eight members would be checking one hand-written list against
   * another — which is how a ninth status ends up in both worklists, or in
   * neither, with everything green (the M10 scope-vocabulary precedent).
   */
  const ddlStatuses = (): string[] => {
    const sql = readFileSync(
      join(__dirname, '..', 'migrations', '001_settlement_schema.sql'),
      'utf8',
    );
    const m = /CHECK \(status IN \(([^)]*)\)\)/.exec(sql);
    const body = m?.[1];
    // A regex that stops matching goes GREEN, which is the failure this whole
    // block exists to prevent — so it throws rather than returning nothing.
    if (!body) throw new Error('could not find the status CHECK in 001 — the fence is blind');
    return [...body.matchAll(/'([a-z_]+)'/g)].map((x) => x[1] as string);
  };

  it('every status the DDL admits is on at most one worklist', () => {
    const all = ddlStatuses();
    expect(all.length).toBeGreaterThanOrEqual(8); // anti-vacuity: the regex found statuses
    for (const status of all) {
      const on = [QUEUE_STATUSES, ADMINISTRABLE_STATUSES].filter((set) =>
        (set as readonly string[]).includes(status),
      );
      expect(on.length).toBeLessThanOrEqual(1);
    }
  });

  it('neither worklist names a status the DDL does not admit', () => {
    const all = new Set(ddlStatuses());
    for (const status of [...QUEUE_STATUSES, ...ADMINISTRABLE_STATUSES]) {
      expect(all.has(status)).toBe(true);
    }
  });

  it('the statuses on NEITHER worklist are exactly the terminal ones', () => {
    // Stated as an equality rather than a subset, because the failure that
    // matters is a status quietly reachable from no screen at all — which is
    // what close/stage-decision/distribution-approval were before this PR.
    const listed = new Set<string>([...QUEUE_STATUSES, ...ADMINISTRABLE_STATUSES]);
    const unlisted = ddlStatuses().filter((s) => !listed.has(s));
    expect(unlisted.sort()).toEqual(['closed', 'rejected_fraud']);
  });
});

describe('the post-verification worklist', () => {
  it('is operator-only', async () => {
    const h = linkedHarness();
    await expect(h.service.administrable(STRANGER, SESSION)).rejects.toThrow(ForbiddenException);
  });

  it('lists administrable cases and the queue does not, and vice versa', async () => {
    // ONE test over BOTH lists, because the property is that a case appears on
    // exactly one of them — asserting either alone would pass while a case sat
    // on both or on neither.
    const h = linkedHarness();
    const caseId = await reportCase(h);

    expect((await h.service.queue(OPERATOR, SESSION)).map((c) => c.caseId)).toEqual([caseId]);
    expect(await h.service.administrable(OPERATOR, SESSION)).toEqual([]);

    markCaseVerified(h.cases, caseId, NOW);

    expect(await h.service.queue(OPERATOR, SESSION)).toEqual([]);
    expect((await h.service.administrable(OPERATOR, SESSION)).map((c) => c.caseId)).toEqual([
      caseId,
    ]);
  });
});

describe('the claim marker', () => {
  it('records WHO claimed the review, and when', async () => {
    const h = linkedHarness();
    const caseId = await reportCase(h);
    const dto = await h.service.startReview(OPERATOR, SESSION, caseId);

    expect(dto.status).toBe('verifying');
    expect(dto.claimedBy).toBe(OPERATOR);
    expect(dto.claimedAt).toBe(NOW.toISOString());
    // Distinct from the review pair, which is written at the DECISION — the
    // whole reason this is a second pair rather than an early write of that one.
    expect(dto.humanReviewBy).toBeNull();
    expect(dto.humanReviewAt).toBeNull();
  });

  it('refuses a reporter-operator AT THE CLAIM, leaving the case unclaimed', async () => {
    // Before this, a reporter-operator could claim (moving the case to
    // `verifying` and putting their name on it) and only discover at the
    // decision that they could never discharge it.
    const h = linkedHarness();
    h.operators.active.add(REPORTER);
    const caseId = await reportCase(h);

    await expect(h.service.startReview(REPORTER, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'reviewer_is_reporter' },
    });

    const after = await h.service.getCase(OPERATOR, SESSION, caseId);
    expect(after.status).toBe('reported');
    expect(after.claimedBy).toBeNull();
  });
});

describe('operator reads leave a trace (docs/03 §4 TB7)', () => {
  it('a queue read is recorded with its size and NO case id', async () => {
    const h = linkedHarness();
    await reportCase(h);
    h.producer.messages.length = 0;

    await h.service.queue(OPERATOR, SESSION);

    const [event] = auditEvents(h.producer);
    expect(event).toMatchObject({
      action: 'settlement.queue.viewed',
      actorType: 'operator',
      actorId: OPERATOR,
      detail: { worklist: 'queue', count: '1' },
    });
    // No single case is the subject of a cross-case listing.
    expect(event?.resourceId).toBeNull();
    expect(event?.onBehalfOf).toBeNull();
  });

  it('the administrable worklist is recorded under its own name', async () => {
    const h = linkedHarness();
    h.producer.messages.length = 0;
    await h.service.administrable(OPERATOR, SESSION);
    expect(auditEvents(h.producer)[0]).toMatchObject({
      action: 'settlement.queue.viewed',
      // The CLASS as well as the name (M48 PR2 review): `worklistViewed` stopped
      // asserting `'operator'` and derives it now, so the two operator worklists
      // need saying too — otherwise the only fenced arm is the `false` one and a
      // flag that was ignored entirely would look identical.
      actorType: 'operator',
      detail: { worklist: 'administrable', count: '0' },
    });
  });

  it('every getCase read is recorded, and the DIFFERENCE is the actor class', async () => {
    /*
     * THE PROPERTY MOVED, AND THE OLD PREMISE IS SPENT (M48 PR2).
     *
     * This test used to assert that the subject and the reporter produce NO
     * row, on the argument that "recording every read would drown the signal
     * TB7 asks for — platform staff looking at somebody else's death case — in
     * people reading their own". That argument holds for the DECEDENT. It does
     * not hold for a third party administering somebody else's estate, and the
     * assets service has always audited exactly that read as
     * `asset.estate.viewed` with `actorType: 'user'`.
     *
     * The other half of the old argument — that a false actor class on an
     * append-only trail is worse than no row — is spent the moment the class is
     * DERIVED from the gate rather than asserted by the emitter.
     *
     * So the discriminator is no longer presence-vs-absence, which a reader
     * cannot tell apart from an emitter that stopped firing. It is the
     * actorType, asserted for all three readers in one place.
     */
    const h = linkedHarness();
    const caseId = await reportCase(h);
    h.producer.messages.length = 0;

    await h.service.getCase(DECEDENT, SESSION, caseId);
    await h.service.getCase(REPORTER, SESSION, caseId);
    await h.service.getCase(OPERATOR, SESSION, caseId);

    // ANTI-VACUITY: three reads, three rows. An emitter that stopped firing
    // would leave this empty, and an empty list trivially satisfies a
    // per-element claim.
    expect(auditActions(h.producer)).toEqual([
      'settlement.case.viewed',
      'settlement.case.viewed',
      'settlement.case.viewed',
    ]);
    expect(
      auditEvents(h.producer).map((e) => ({ actorId: e.actorId, actorType: e.actorType })),
    ).toEqual([
      { actorId: DECEDENT, actorType: 'user' },
      { actorId: REPORTER, actorType: 'user' },
      { actorId: OPERATOR, actorType: 'operator' },
    ]);
    // The case-scoped fields are the same whoever read it: this is one case's
    // trail, and `onBehalfOf` names the estate, never the reader.
    for (const e of auditEvents(h.producer)) {
      expect(e).toMatchObject({
        resourceId: caseId,
        onBehalfOf: DECEDENT,
        detail: { surface: 'case' },
      });
    }
  });

  it('each administration read names WHICH surface it was', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedAdminCase(h);
    h.producer.messages.length = 0;

    await h.admin.timeline(OPERATOR, SESSION, caseId);
    await h.admin.listStages(OPERATOR, SESSION, caseId);
    await h.admin.listTasks(OPERATOR, SESSION, caseId);
    await h.admin.listDistributions(OPERATOR, SESSION, caseId);

    expect(auditEvents(h.producer).map((e) => (e.detail as { surface: string }).surface)).toEqual([
      'timeline',
      'stages',
      'tasks',
      'distributions',
    ]);
    expect(auditActions(h.producer).every((a) => a === 'settlement.case.viewed')).toBe(true);
    // THE CLASS, PER ROW, mirroring the executor test below (M48 PR2 review).
    // Until this line the derivation was fenced on `amount` alone: passing
    // `false` instead of `isOperator` in `recordCaseRead` recorded all four of
    // these as the estate's own reader and only the money-route test noticed.
    expect(
      auditEvents(h.producer).map((e) => ({ actorId: e.actorId, actorType: e.actorType })),
    ).toEqual(Array(4).fill({ actorId: OPERATOR, actorType: 'operator' }));
  });

  it('the EXECUTOR reading the same four surfaces is recorded AS A USER', async () => {
    /*
     * THE READ THIS MILESTONE EXISTS FOR (M48 PR2). An executor is not reading
     * their own case — they are administering a dead person's estate, and until
     * now settlement was the only service that let that happen silently.
     * `admin.service.ts`'s `executorCases` cites `asset.estate.viewed` as the
     * reason it needs no event of its own; this is settlement agreeing with the
     * sibling it already cites.
     */
    const h = buildAdminHarness();
    const caseId = await verifiedAdminCase(h);
    h.producer.messages.length = 0;

    await h.admin.timeline(EXECUTOR, SESSION, caseId);
    await h.admin.listStages(EXECUTOR, SESSION, caseId);
    await h.admin.listTasks(EXECUTOR, SESSION, caseId);
    await h.admin.listDistributions(EXECUTOR, SESSION, caseId);

    expect(auditEvents(h.producer).map((e) => (e.detail as { surface: string }).surface)).toEqual([
      'timeline',
      'stages',
      'tasks',
      'distributions',
    ]);
    // EVERY one a user read, by the same actor. Asserting the class per ROW
    // rather than once means a single mis-derived surface cannot hide behind
    // three right ones.
    expect(
      auditEvents(h.producer).map((e) => ({ actorId: e.actorId, actorType: e.actorType })),
    ).toEqual([
      { actorId: EXECUTOR, actorType: 'user' },
      { actorId: EXECUTOR, actorType: 'user' },
      { actorId: EXECUTOR, actorType: 'user' },
      { actorId: EXECUTOR, actorType: 'user' },
    ]);
  });

  it('an operator who is ALSO the reporter is still recorded as an operator read', async () => {
    // The gate is consulted unconditionally rather than as the second arm of
    // the visibility chain, so this cannot depend on which clause admitted the
    // caller — an audit claim whose truth turned on the order of an `if`.
    //
    // ASSERTS THE CLASS, NOT THE PRESENCE (M48 PR2 review). While
    // `recordCaseRead` opened `if (!isOperator) return;` the presence of a row
    // WAS the classification, so counting rows tested this property. Removing
    // that early return made every reader emit exactly one row and silently
    // disarmed the count — the test kept passing and stopped testing its name.
    const h = buildAdminHarness();
    const caseId = await verifiedAdminCase(h);
    h.operators.active.add(REPORTER);
    h.producer.messages.length = 0;

    await h.admin.timeline(REPORTER, SESSION, caseId);

    expect(auditActions(h.producer)).toEqual(['settlement.case.viewed']);
    expect(
      auditEvents(h.producer).map((e) => ({ actorId: e.actorId, actorType: e.actorType })),
    ).toEqual([{ actorId: REPORTER, actorType: 'operator' }]);
  });

  it("the EXECUTOR's worklist lands on the trail, as a USER read", async () => {
    /*
     * THE OMISSION M23 PR2 ARGUED AND M48 PR2 RE-DECIDED. That argument turned
     * entirely on `worklistViewed` hardcoding `actorType: 'operator'`: reusing
     * `settlement.queue.viewed` for an executor would have put a false actor
     * type on the trail, and a new vocabulary member costs a consumer
     * deployment ahead of its producer. Deriving the class spends the first
     * half and removes the need for the second, so the reason no longer holds
     * and the read — one person listing the estates they administer for OTHER
     * people — is the same disclosure `asset.estate.viewed` has recorded on the
     * assets side since M7 PR2.
     *
     * A COUNT, NOT ROWS, and no `resourceId`: `queue`'s argument verbatim.
     */
    const h = buildAdminHarness();
    const caseId = await verifiedAdminCase(h);
    h.producer.messages.length = 0;

    const administered = await h.admin.executorCases(EXECUTOR, SESSION);

    expect(auditEvents(h.producer)).toEqual([
      expect.objectContaining({
        action: 'settlement.queue.viewed',
        actorId: EXECUTOR,
        actorType: 'user',
        sessionId: SESSION,
        resourceId: null,
        onBehalfOf: null,
        detail: { worklist: 'executor', count: String(administered.length) },
      }),
    ]);
    // ANTI-VACUITY: a count of '0' would satisfy the shape above while proving
    // the executor saw nothing. They administer this case; it must be listed.
    expect(administered.map((c) => c.caseId)).toEqual([caseId]);
  });

  it('the money route lands on BOTH trails, with one derived class', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedAdminCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '4500.00',
    });
    h.producer.messages.length = 0;

    await h.admin.distributionAmount(EXECUTOR, SESSION, dto.distributionId);
    await h.admin.distributionAmount(OPERATOR, SESSION, dto.distributionId);

    // TWO events per read, answering different questions: what happened to this
    // distribution, and who has been reading this estate. Until M48 PR2 the
    // second did not exist for this route — it joined the gate in M23 PR4b and
    // joined no surface union.
    expect(auditActions(h.producer)).toEqual([
      'settlement.case.viewed',
      'settlement.distribution.amount_viewed',
      'settlement.case.viewed',
      'settlement.distribution.amount_viewed',
    ]);
    expect(
      auditEvents(h.producer).map((e) => ({ actorId: e.actorId, actorType: e.actorType })),
    ).toEqual([
      { actorId: EXECUTOR, actorType: 'user' },
      { actorId: EXECUTOR, actorType: 'user' },
      { actorId: OPERATOR, actorType: 'operator' },
      { actorId: OPERATOR, actorType: 'operator' },
    ]);
    expect(
      auditEvents(h.producer)
        .filter((e) => e.action === 'settlement.case.viewed')
        .map((e) => (e.detail as { surface: string }).surface),
    ).toEqual(['amount', 'amount']);
  });

  it('the DECRYPT itself names the right actor class', async () => {
    /*
     * The half of the fix no assertion could see. `decryptField` has always
     * ACCEPTED an `actorType` and `FakeFieldCrypto` threw it away, so
     * `crypto.field.decrypted` naming every operator read as the estate's own
     * reader was unprovable: revert the fix and nothing went red. The double
     * records it now, which is why this test can exist at all.
     */
    const h = buildAdminHarness();
    const caseId = await verifiedAdminCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '4500.00',
    });
    h.crypto.opened.length = 0;

    await h.admin.distributionAmount(EXECUTOR, SESSION, dto.distributionId);
    await h.admin.distributionAmount(OPERATOR, SESSION, dto.distributionId);

    expect(h.crypto.opened.map((o) => ({ actorId: o.actorId, actorType: o.actorType }))).toEqual([
      { actorId: EXECUTOR, actorType: 'user' },
      { actorId: OPERATOR, actorType: 'operator' },
    ]);
  });
});
