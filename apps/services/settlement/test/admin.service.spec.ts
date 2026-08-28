import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ForbiddenException, type HttpException, NotFoundException } from '@nestjs/common';
import {
  auditActions,
  auditEvents,
  buildAdminHarness,
  markCaseVerified,
  NOW,
  type AdminHarness,
} from './support';
import {
  breadthExceeded,
  OPERATOR_BREADTH_MAX_CASES,
  PERMISSIVE_OPERATOR_ACTIONS,
  PROTECTIVE_OPERATOR_ACTIONS,
} from '../src/operator-breadth';
import type { OperatorBreadthMonitor } from '../src/operator-breadth.monitor';

const DECEDENT = randomUUID();
const EXECUTOR = randomUUID();
const OPERATOR = randomUUID();
const SECOND_OPERATOR = randomUUID();
const STRANGER = randomUUID();
const REPORTER = randomUUID();
const SESSION = randomUUID();
const CONTACT = randomUUID();

/** A verified case with an executor designated, ready for administration. */
async function verifiedCase(h: AdminHarness): Promise<string> {
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
  h.operators.active.add(SECOND_OPERATOR);
  return row.id;
}

/**
 * The refusal a caller actually receives, as a comparable VALUE.
 *
 * `rejects.toThrow(SomeException)` cannot express the property a uniform
 * refusal has — two refusals being THE SAME — and all three tests below used
 * to pin the exception TYPE. Every one of them stayed green while the route
 * answered 404, 409 and 403 to three different callers, which is the gap M23
 * PR1 closed. Throws if the call RESOLVES, so two non-refusals can never be
 * compared to each other.
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

/** A case that exists and has NOT been verified — the middle rung of the ladder. */
async function pendingCase(h: AdminHarness): Promise<string> {
  const row = await h.cases.insert(undefined as never, {
    decedentUserId: randomUUID(),
    reportedBy: REPORTER,
    source: 'trusted_contact',
    evidence: [],
  });
  return row.id;
}

/** A verified case with one approved stage — the state distributions need. */
async function readyCase(h: AdminHarness): Promise<string> {
  const caseId = await verifiedCase(h);
  const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
  await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
  return caseId;
}

/**
 * THE EXECUTOR'S FRONT DOOR (M23 PR2).
 *
 * Until this route existed, every verb in `admin.service.ts` was reachable
 * only by a caller who already held a case id — the gap M21 PR3b closed for
 * operators, keyed on the other audience. The properties that matter are what
 * it LEAVES OUT: a case an operator has not verified, an estate that links the
 * caller without designating them executor, and anybody else's estate at all.
 */
describe('the estates an executor is settling', () => {
  it('names a verified estate, with the CONTACT id the browser will use', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);

    const mine = await h.admin.executorCases(EXECUTOR, SESSION);
    // EQUALITY on everything but the timestamp the fixture does not fix, so a
    // field added to the DTO — a `decedentUserId` sibling, say — fails here
    // rather than sliding through a `toMatchObject`.
    expect(mine.map(({ createdAt, ...rest }) => rest)).toEqual([
      {
        caseId,
        contactId: h.coreReads.contactIdFor(DECEDENT, EXECUTOR),
        decedentUserId: DECEDENT,
        status: 'verified',
        verifiedAt: NOW.toISOString(),
      },
    ]);
    expect(typeof mine[0]?.createdAt).toBe('string');
    // The contact id is the estate's handle end to end, so it must be the
    // one the reportable list gives for the same pair — two lookups that
    // could disagree is what returning it on the case row avoids.
    const [estate] = await h.coreReads.reportableEstates(EXECUTOR);
    expect(mine[0]?.contactId).toBe(estate?.contactId);
  });

  it('is EMPTY before an operator verifies the death', async () => {
    const h = buildAdminHarness();
    const row = await h.cases.insert(undefined as never, {
      decedentUserId: DECEDENT,
      reportedBy: REPORTER,
      source: 'trusted_contact',
      evidence: [],
    });
    h.coreReads.link(DECEDENT, EXECUTOR);
    h.coreReads.executors.add(`${DECEDENT}:${EXECUTOR}`);

    // A designated executor of a LIVING person has nothing to administer, and
    // listing the case would tell them a death report exists about somebody
    // who may well be alive — the reporter's own disclosure to make, not ours.
    expect(await h.admin.executorCases(EXECUTOR, SESSION)).toEqual([]);

    // Positive control: the same case, once verified, DOES appear — so the
    // assertion above is about the status filter and not about the join
    // failing to match anything at all.
    markCaseVerified(h.cases, row.id, NOW);
    expect((await h.admin.executorCases(EXECUTOR, SESSION)).map((c) => c.caseId)).toEqual([row.id]);
  });

  it('a LINKED contact who was never designated executor sees nothing', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    // The reporter is linked to this estate — they had to be, to file — and
    // holds no executor designation. Being trusted enough to report a death is
    // not being trusted to settle the estate.
    h.coreReads.link(DECEDENT, REPORTER);
    expect(await h.admin.executorCases(REPORTER, SESSION)).toEqual([]);
    expect(await h.admin.executorCases(STRANGER, SESSION)).toEqual([]);
    // Positive control on the same fixture.
    expect((await h.admin.executorCases(EXECUTOR, SESSION)).map((c) => c.caseId)).toEqual([caseId]);
  });

  it('does not leak one estate into another executor’s list', async () => {
    const h = buildAdminHarness();
    const mine = await verifiedCase(h);
    const otherDecedent = randomUUID();
    const otherExecutor = randomUUID();
    const other = await h.cases.insert(undefined as never, {
      decedentUserId: otherDecedent,
      reportedBy: REPORTER,
      source: 'trusted_contact',
      evidence: [],
    });
    markCaseVerified(h.cases, other.id, NOW);
    h.coreReads.link(otherDecedent, otherExecutor);
    h.coreReads.executors.add(`${otherDecedent}:${otherExecutor}`);

    // SETS, not counts: a join that matched the wrong contact row would
    // return one case to each caller and preserve every count in sight.
    expect((await h.admin.executorCases(EXECUTOR, SESSION)).map((c) => c.caseId)).toEqual([mine]);
    expect((await h.admin.executorCases(otherExecutor, SESSION)).map((c) => c.caseId)).toEqual([
      other.id,
    ]);
  });

  it('is audited as a WORKLIST — a count, never the case ids', async () => {
    // M23 PR2 argued this route needed no event; M48 PR2 re-decided it, because
    // the argument rested entirely on `worklistViewed` hardcoding
    // `actorType: 'operator'` and that hardcode is gone. What the read
    // discloses has not changed: these are OTHER PEOPLE's estates, held by a
    // third party administering them.
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    h.producer.messages.length = 0;

    await h.admin.executorCases(EXECUTOR, SESSION);

    const [event] = auditEvents(h.producer);
    expect(event).toMatchObject({
      action: 'settlement.queue.viewed',
      actorId: EXECUTOR,
      actorType: 'user',
      detail: { worklist: 'executor', count: '1' },
    });
    // NO case id reaches the trail, in the resource slot or the payload: naming
    // one member of a list puts an arbitrary estate on a cross-case read.
    expect(event?.resourceId).toBeNull();
    expect(event?.onBehalfOf).toBeNull();
    for (const message of h.producer.messages) {
      expect(message.value).not.toContain(caseId);
    }
  });
});

describe('staged executor access (docs/03 §5.1 control 5)', () => {
  it('the ladder cannot be skipped: documents needs inventory approved first', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);

    await expect(
      h.admin.requestStage(EXECUTOR, SESSION, caseId, 'documents'),
    ).rejects.toMatchObject({ response: { error: 'stage_out_of_order' } });
    await expect(h.admin.requestStage(EXECUTOR, SESSION, caseId, 'vault')).rejects.toMatchObject({
      response: { error: 'stage_out_of_order' },
    });

    // Inventory first — the least dangerous grant.
    const inventory = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    expect(inventory.status).toBe('requested');
    // Still not enough: a REQUESTED stage grants nothing.
    await expect(
      h.admin.requestStage(EXECUTOR, SESSION, caseId, 'documents'),
    ).rejects.toMatchObject({ response: { error: 'stage_out_of_order' } });

    await h.admin.decideStage(OPERATOR, SESSION, inventory.stageId, 'approve');
    const documents = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'documents');
    expect(documents.stage).toBe('documents');
    // And vault is STILL out of reach until documents is approved.
    await expect(h.admin.requestStage(EXECUTOR, SESSION, caseId, 'vault')).rejects.toMatchObject({
      response: { error: 'stage_out_of_order' },
    });
  });

  /**
   * THE REFUSAL LADDER (M23 PR1), and the reason it needed measuring rather
   * than reading: this route answered THREE distinguishable ways, and the test
   * that was here pinned only the exception type, so the suite was green
   * either way.
   *
   * 404 for an unknown id, 409 `case_not_verified` for a real case that had
   * not been verified, 403 for a real administrable case the caller had no
   * authority over. Holding one case UUID told you which. The concrete holder
   * is a former or replaced executor, or the reporter — case ids are v4, so
   * this was never blind enumeration — and what they could track is an
   * estate's settlement progress after losing any right to it.
   */
  it('answers ONE refusal to everyone without authority, whatever the case is', async () => {
    const h = buildAdminHarness();
    const administrable = await verifiedCase(h);
    const pending = await pendingCase(h);
    const absent = randomUUID();

    const onAdministrable = await refusalOf(() =>
      h.admin.requestStage(STRANGER, SESSION, administrable, 'inventory'),
    );
    const onPending = await refusalOf(() =>
      h.admin.requestStage(STRANGER, SESSION, pending, 'inventory'),
    );
    const onAbsent = await refusalOf(() =>
      h.admin.requestStage(STRANGER, SESSION, absent, 'inventory'),
    );

    expect(onAdministrable).toEqual(onAbsent);
    expect(onPending).toEqual(onAbsent);
    expect(onAbsent).toEqual({ status: 404, body: { error: 'not_found' } });
  });

  it('and the reporter, who opened the case, is told the same nothing', async () => {
    // Opening a case is not administering the estate it names.
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    expect(
      await refusalOf(() => h.admin.requestStage(REPORTER, SESSION, caseId, 'inventory')),
    ).toEqual({ status: 404, body: { error: 'not_found' } });
  });

  it('but the EXECUTOR still learns a case is not verified yet — fail closed de-escalates', async () => {
    /*
     * The positive control, and the property that stops this fix becoming
     * "refuse everything". `case_not_verified` has a different remedy from a
     * 404 — wait, rather than conclude the case does not exist — and it is
     * reachable only by the person entitled to it.
     */
    const h = buildAdminHarness();
    const row = await h.cases.insert(undefined as never, {
      decedentUserId: DECEDENT,
      reportedBy: REPORTER,
      source: 'trusted_contact',
      evidence: [],
    });
    h.coreReads.link(DECEDENT, EXECUTOR);
    h.coreReads.executors.add(`${DECEDENT}:${EXECUTOR}`);
    expect(
      await refusalOf(() => h.admin.requestStage(EXECUTOR, SESSION, row.id, 'inventory')),
    ).toEqual({ status: 409, body: { error: 'case_not_verified' } });
  });

  it('the approver can never be the requester (two people per stage)', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    // The executor is ALSO an operator — the dangerous overlap.
    h.operators.active.add(EXECUTOR);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await expect(
      h.admin.decideStage(EXECUTOR, SESSION, stage.stageId, 'approve'),
    ).rejects.toMatchObject({ response: { error: 'approver_is_requester' } });
  });

  it('a non-operator cannot approve, and approval is audited', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await expect(h.admin.decideStage(STRANGER, SESSION, stage.stageId, 'approve')).rejects.toThrow(
      ForbiddenException,
    );

    const approved = await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    expect(approved.status).toBe('approved');
    expect(approved.decidedBy).toBe(OPERATOR);
    expect(auditActions(h.producer)).toContain('settlement.stage.approved');
    // The first approved stage moves the case into active administration.
    expect(h.cases.rows.get(caseId)?.status).toBe('active');
  });

  it('a denied stage is not approved, and can be re-requested', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'deny');
    expect(auditActions(h.producer)).toContain('settlement.stage.denied');
    // Denied frees the slot; the ladder is still closed above it.
    const again = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    expect(again.status).toBe('requested');
  });

  it('an approved stage can be revoked — access is a grant, not a fact', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    await expect(
      h.admin.stageAccessAuthority(EXECUTOR, DECEDENT, 'inventory'),
    ).resolves.toMatchObject({ allowed: true });

    await h.admin.revokeStage(SECOND_OPERATOR, SESSION, stage.stageId);
    await expect(h.admin.stageAccessAuthority(EXECUTOR, DECEDENT, 'inventory')).resolves.toEqual({
      allowed: false,
      caseId: null,
    });
    expect(auditActions(h.producer)).toContain('settlement.stage.revoked');
  });

  it('the operator who requested a stage cannot revoke it — a second operator must', async () => {
    // Dual control applies to revocation because revocation writes decided_by,
    // and the DDL CHECK is decided_by <> requested_by. Before the M7 security
    // review this refusal reached Postgres unhandled: a 23514 surfaced as a
    // 500, so a caller could not tell "fetch another operator" from "the
    // service is down" — while the access the revoke was meant to remove
    // stayed granted. It refuses cleanly now, and a second operator succeeds.
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    // An operator who is also the executor on this case: nothing forbids that,
    // and it is the reason requester and decider identities can collide.
    h.coreReads.link(DECEDENT, OPERATOR);
    h.coreReads.executors.add(`${DECEDENT}:${OPERATOR}`);
    const stage = await h.admin.requestStage(OPERATOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(SECOND_OPERATOR, SESSION, stage.stageId, 'approve');

    await expect(h.admin.revokeStage(OPERATOR, SESSION, stage.stageId)).rejects.toMatchObject({
      response: { error: 'approver_is_requester' },
    });
    // Still granted — the refusal did not silently half-apply.
    await expect(
      h.admin.stageAccessAuthority(OPERATOR, DECEDENT, 'inventory'),
    ).resolves.toMatchObject({ allowed: true });

    await h.admin.revokeStage(SECOND_OPERATOR, SESSION, stage.stageId);
    await expect(h.admin.stageAccessAuthority(OPERATOR, DECEDENT, 'inventory')).resolves.toEqual({
      allowed: false,
      caseId: null,
    });
  });

  it('no stage exists before verification — a fresh report grants nothing', async () => {
    const h = buildAdminHarness();
    const row = await h.cases.insert(undefined as never, {
      decedentUserId: DECEDENT,
      reportedBy: REPORTER,
      source: 'trusted_contact',
      evidence: [],
    });
    // LINKED as well as designated. `isExecutorOf` is a JOIN: a designation
    // with no live contact link is not an executor, so without this the caller
    // is refused at the door with the uniform 404 and never reaches the
    // verification check this test is named for.
    h.coreReads.link(DECEDENT, EXECUTOR);
    h.coreReads.executors.add(`${DECEDENT}:${EXECUTOR}`);
    await expect(
      h.admin.requestStage(EXECUTOR, SESSION, row.id, 'inventory'),
    ).rejects.toMatchObject({ response: { error: 'case_not_verified' } });
  });
});

describe('stage authority (what assets asks)', () => {
  it('requires a verified case, the executor, and an approved stage — all three', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    // No stage yet.
    await expect(h.admin.stageAccessAuthority(EXECUTOR, DECEDENT, 'inventory')).resolves.toEqual({
      allowed: false,
      caseId: null,
    });

    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    // Requested but not approved.
    await expect(h.admin.stageAccessAuthority(EXECUTOR, DECEDENT, 'inventory')).resolves.toEqual({
      allowed: false,
      caseId: null,
    });

    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    await expect(h.admin.stageAccessAuthority(EXECUTOR, DECEDENT, 'inventory')).resolves.toEqual({
      allowed: true,
      caseId,
    });
    // A different stage is still closed.
    await expect(h.admin.stageAccessAuthority(EXECUTOR, DECEDENT, 'vault')).resolves.toEqual({
      allowed: false,
      caseId: null,
    });
    // A non-executor gets nothing even with the stage approved.
    await expect(h.admin.stageAccessAuthority(STRANGER, DECEDENT, 'inventory')).resolves.toEqual({
      allowed: false,
      caseId: null,
    });
  });
});

describe('the vault gate (docs/03 §6a)', () => {
  it('permits release when the owner has no settlement case at all', async () => {
    const h = buildAdminHarness();
    await expect(h.admin.vaultReleaseAuthority(randomUUID())).resolves.toEqual({
      permitted: true,
      caseId: null,
    });
  });

  it('BLOCKS while a case is merely reported — the owner may still be alive', async () => {
    const h = buildAdminHarness();
    const row = await h.cases.insert(undefined as never, {
      decedentUserId: DECEDENT,
      reportedBy: REPORTER,
      source: 'trusted_contact',
      evidence: [],
    });
    await expect(h.admin.vaultReleaseAuthority(DECEDENT)).resolves.toEqual({
      permitted: false,
      caseId: row.id,
    });
  });

  it('BLOCKS a verified case until the vault stage is separately approved — Zone A is last', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    await expect(h.admin.vaultReleaseAuthority(DECEDENT)).resolves.toEqual({
      permitted: false,
      caseId,
    });

    // Climb the whole ladder.
    const inventory = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, inventory.stageId, 'approve');
    const documents = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'documents');
    await h.admin.decideStage(OPERATOR, SESSION, documents.stageId, 'approve');
    // Still blocked: documents approved is not vault approved.
    await expect(h.admin.vaultReleaseAuthority(DECEDENT)).resolves.toMatchObject({
      permitted: false,
    });

    const vault = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'vault');
    await h.admin.decideStage(OPERATOR, SESSION, vault.stageId, 'approve');
    await expect(h.admin.vaultReleaseAuthority(DECEDENT)).resolves.toEqual({
      permitted: true,
      caseId,
    });
  });

  it('re-blocks when the vault stage is revoked', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    for (const stage of ['inventory', 'documents', 'vault'] as const) {
      const s = await h.admin.requestStage(EXECUTOR, SESSION, caseId, stage);
      await h.admin.decideStage(OPERATOR, SESSION, s.stageId, 'approve');
    }
    await expect(h.admin.vaultReleaseAuthority(DECEDENT)).resolves.toMatchObject({
      permitted: true,
    });
    const vaultStage = h.stages.rows.find((r) => r.stage === 'vault')!;
    await h.admin.revokeStage(OPERATOR, SESSION, vaultStage.id);
    await expect(h.admin.vaultReleaseAuthority(DECEDENT)).resolves.toMatchObject({
      permitted: false,
    });
  });
});

describe('distributions under dual control (docs/02 §7)', () => {
  it('encrypts the amount under the DECEDENT’s key and never audits the value', async () => {
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '12345.67',
    });
    expect(dto.hasAmount).toBe(true);
    expect(h.crypto.sealed).toEqual([
      { userId: DECEDENT, field: 'distributions.amount', plaintext: '12345.67' },
    ]);
    // The amount appears in NO audit payload.
    for (const message of h.producer.messages) {
      expect(message.value).not.toContain('12345.67');
    }
    // Recording moves the case into distributing.
    expect(h.cases.rows.get(caseId)?.status).toBe('distributing');
  });

  it('the approver can never be the recorder', async () => {
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    // The executor is also an operator — the overlap dual control exists for.
    h.operators.active.add(EXECUTOR);
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '100.00',
    });
    await expect(
      h.admin.approveDistribution(EXECUTOR, SESSION, dto.distributionId),
    ).rejects.toMatchObject({ response: { error: 'approver_is_recorder' } });
    // A different operator can.
    const approved = await h.admin.approveDistribution(OPERATOR, SESSION, dto.distributionId);
    expect(approved.status).toBe('approved');
    expect(approved.approvedBy).toBe(OPERATOR);
    expect(auditActions(h.producer)).toContain('settlement.distribution.approved');
  });

  it('nothing moves past planned without an approval', async () => {
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '50.00',
    });
    await expect(
      h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'in_progress'),
    ).rejects.toMatchObject({ response: { error: 'invalid_transition' } });
    await expect(
      h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'completed'),
    ).rejects.toMatchObject({ response: { error: 'invalid_transition' } });
  });

  it('a non-executor cannot record a distribution, and learns nothing from trying', async () => {
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    const onReal = await refusalOf(() =>
      h.admin.recordDistribution(STRANGER, SESSION, caseId, {
        beneficiaryContactId: CONTACT,
        amount: '1.00',
      }),
    );
    const onAbsent = await refusalOf(() =>
      h.admin.recordDistribution(STRANGER, SESSION, randomUUID(), {
        beneficiaryContactId: CONTACT,
        amount: '1.00',
      }),
    );
    expect(onReal).toEqual(onAbsent);
    expect(onReal).toEqual({ status: 404, body: { error: 'not_found' } });
  });

  /**
   * AND THE REFUSAL COSTS THE ESTATE NOTHING (M23 PR1).
   *
   * This method seals the amount OUTSIDE the transaction, so the KMS round
   * trip does not sit inside an open one — correct, and it used to happen
   * before anyone asked whether the caller was the executor. A stranger
   * holding a case id could therefore spend a KMS operation on the DECEDENT's
   * own DEK, with a plaintext of their choosing. Measured with this same
   * double before the fix: it recorded
   * `{userId: <decedent>, field: 'distributions.amount', plaintext: '1000.00'}`
   * for an account that was refused a moment later.
   */
  it('does not touch the estate’s DEK on behalf of a caller it is about to refuse', async () => {
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    const sealedBefore = h.crypto.sealed.length;

    await refusalOf(() =>
      h.admin.recordDistribution(STRANGER, SESSION, caseId, {
        beneficiaryContactId: CONTACT,
        amount: '1000.00',
      }),
    );
    expect(h.crypto.sealed).toHaveLength(sealedBefore);

    // Positive control: the executor's own record DOES seal, so the assertion
    // above is about authority and not about sealing having been switched off.
    await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '1000.00',
    });
    expect(h.crypto.sealed).toHaveLength(sealedBefore + 1);
    expect(h.crypto.sealed.at(-1)).toMatchObject({ userId: DECEDENT, plaintext: '1000.00' });
  });

  /**
   * THE PRE-TRANSACTION CHECK DOES NOT REPLACE THE ONE UNDER THE LOCK.
   *
   * Written because a mutation SURVIVED: reverting the in-transaction gate to
   * `requireAdministrableCase` — which tests administrability and not
   * authority — left all 43 tests green, because every other test authorises
   * once and nothing changes underneath it. A pre-transaction read and the
   * transaction it guards are separated by every commit that lands between
   * them, and the only thing that can observe the difference is a revocation
   * landing in that gap.
   *
   * The window is real and small: `requireAdministeredDecedentFor` reads
   * authority, the KMS seal runs, and only then does the transaction open. An
   * executor removed in that gap must not get one last write.
   */
  it('re-tests authority UNDER THE LOCK, not only before the seal', async () => {
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    const truthful = h.coreReads.isExecutorOf.bind(h.coreReads);
    let asked = 0;
    h.coreReads.isExecutorOf = async (decedent: string, user: string): Promise<boolean> => {
      const answer = await truthful(decedent, user);
      // The revocation lands after the pre-transaction read has been answered
      // and before the transaction opens — the gap the two checks exist for.
      if (++asked === 1) {
        h.coreReads.executors.delete(`${DECEDENT}:${EXECUTOR}`);
      }
      return answer;
    };

    const refusal = await refusalOf(() =>
      h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
        beneficiaryContactId: CONTACT,
        amount: '1000.00',
      }),
    );
    expect(asked).toBeGreaterThan(1);
    expect(refusal).toEqual({ status: 404, body: { error: 'not_found' } });
    expect(h.distributions.rows).toEqual([]);

    // Positive control: with authority intact throughout, the same call writes.
    h.coreReads.isExecutorOf = truthful;
    h.coreReads.executors.add(`${DECEDENT}:${EXECUTOR}`);
    await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '1000.00',
    });
    expect(h.distributions.rows).toHaveLength(1);
  });

  it('an amount is optional; a distribution can be recorded without one', async () => {
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: null,
    });
    expect(dto.hasAmount).toBe(false);
    expect(h.crypto.sealed).toEqual([]);
  });

  /**
   * READING ONE BACK (M23 PR4b).
   *
   * Until this route the amount was WRITE-ONLY — sealed under the decedent's
   * DEK at `recordDistribution` and readable by nobody, which made the
   * dual-control, step-up-gated approval above an approval of a number the
   * approver could not see.
   */
  describe('revealing a recorded amount', () => {
    /** A ready case carrying one distribution of `amount`. */
    async function recorded(
      h: AdminHarness,
      amount: string | null,
    ): Promise<{ caseId: string; id: string }> {
      const caseId = await readyCase(h);
      const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
        beneficiaryContactId: CONTACT,
        amount,
      });
      return { caseId, id: dto.distributionId };
    }

    it('returns the sealed decimal EXACTLY, as a string', async () => {
      const h = buildAdminHarness();
      /*
       * THE LARGEST AMOUNT THE ROUTE ACCEPTS, and it does not survive a float:
       * `String(Number('999999999999999.99'))` is '1000000000000000', so a
       * parse anywhere on this path changes the answer by a cent and rounds an
       * estate's largest distribution up to a round number.
       *
       * Fifteen digits and two places because that is `AmountSchema`'s own
       * bound — a fixture wider than the schema would prove a round trip the
       * controller refuses to start.
       */
      expect(String(Number('999999999999999.99'))).not.toBe('999999999999999.99');
      const { id } = await recorded(h, '999999999999999.99');
      await expect(h.admin.distributionAmount(EXECUTOR, SESSION, id)).resolves.toEqual({
        amount: '999999999999999.99',
      });
    });

    /**
     * THE SAME PARTIES AS THE LIST, DERIVED rather than hand-listed.
     *
     * The claim is not "these four can read" — it is that this route's
     * authority IS `listDistributions`'s, because it reveals a field of a row
     * that route already returns. Comparing the two admitted SETS says that;
     * four `resolves` assertions would say something weaker and would not
     * notice a fifth party gaining one route and not the other.
     */
    it('admits exactly the callers `listDistributions` admits', async () => {
      const h = buildAdminHarness();
      h.operators.active.add(OPERATOR);
      const { caseId, id } = await recorded(h, '42.00');
      const parties = { DECEDENT, REPORTER, EXECUTOR, OPERATOR, STRANGER };

      const admits = async (call: (who: string) => Promise<unknown>): Promise<string[]> => {
        const out: string[] = [];
        for (const [name, who] of Object.entries(parties)) {
          const ok = await call(who).then(
            () => true,
            () => false,
          );
          if (ok) out.push(name);
        }
        return out;
      };

      const onList = await admits((who) => h.admin.listDistributions(who, SESSION, caseId));
      const onAmount = await admits((who) => h.admin.distributionAmount(who, SESSION, id));
      expect(onAmount).toEqual(onList);
      // ANTI-VACUITY: two empty sets are also equal. These are the parties the
      // route exists for, and a stranger is not among them.
      expect(onAmount).toEqual(expect.arrayContaining(['EXECUTOR', 'OPERATOR']));
      expect(onAmount).not.toContain('STRANGER');
    });

    it('answers a stranger the same way for a real id and an unknown one', async () => {
      const h = buildAdminHarness();
      const { id } = await recorded(h, '42.00');
      const onReal = await refusalOf(() => h.admin.distributionAmount(STRANGER, SESSION, id));
      const onAbsent = await refusalOf(() =>
        h.admin.distributionAmount(STRANGER, SESSION, randomUUID()),
      );
      expect(onReal).toEqual(onAbsent);
      expect(onReal).toEqual({ status: 404, body: { error: 'not_found' } });
    });

    it('does not open the estate’s DEK for a caller it is about to refuse', async () => {
      const h = buildAdminHarness();
      const { id } = await recorded(h, '42.00');
      await refusalOf(() => h.admin.distributionAmount(STRANGER, SESSION, id));
      expect(h.crypto.opened).toEqual([]);
      // Positive control: the same id under the executor DOES open it, so the
      // assertion above is about authority and not about a double that never
      // decrypts.
      await h.admin.distributionAmount(EXECUTOR, SESSION, id);
      expect(h.crypto.opened).toHaveLength(1);
    });

    /**
     * THE RECORD GOES FIRST. Both orderings return the same amount, so only an
     * ORDER assertion can see this: an event written after the decrypt is one a
     * crash can lose while the plaintext already exists, leaving an
     * actor-attributed `crypto.field.decrypted` on a dead person's trail with
     * nothing saying what authorised it.
     */
    it('records the disclosure BEFORE it reads the plaintext', async () => {
      const h = buildAdminHarness();
      const { id } = await recorded(h, '42.00');
      const truthful = h.crypto.decryptField.bind(h.crypto);
      let actionsAtDecrypt: string[] = [];
      h.crypto.decryptField = (input): Promise<Buffer> => {
        // Snapshot the trail AS THE DECRYPT HAPPENS — asserting on the final
        // order of two lists would measure the fixture's own events too.
        actionsAtDecrypt = auditActions(h.producer);
        return truthful(input);
      };

      await h.admin.distributionAmount(EXECUTOR, SESSION, id);
      expect(actionsAtDecrypt).toContain('settlement.distribution.amount_viewed');
    });

    it('never writes the amount into the audit trail', async () => {
      const h = buildAdminHarness();
      const { id } = await recorded(h, '98765.43');
      await h.admin.distributionAmount(EXECUTOR, SESSION, id);

      const viewed = auditEvents(h.producer).filter(
        (e) => e.action === 'settlement.distribution.amount_viewed',
      );
      expect(viewed).toHaveLength(1);
      expect(viewed[0]).toMatchObject({
        resourceType: 'distribution',
        resourceId: id,
        onBehalfOf: DECEDENT,
        actorId: EXECUTOR,
      });
      // Entity ids and enums only — the value this event records the reading
      // of appears in NO payload on the trail.
      for (const message of h.producer.messages) {
        expect(message.value).not.toContain('98765.43');
      }
    });

    /**
     * THREE FACTS, THREE ANSWERS. "Nothing was recorded", "you may not look"
     * and "it was erased" have different remedies, and the first is not a
     * failure at all — `amount_ct` is nullable by design, because a
     * distribution may name an asset rather than a sum.
     */
    it('answers null for a row with no amount, spending nothing to do it', async () => {
      const h = buildAdminHarness();
      const { id } = await recorded(h, null);
      h.producer.messages.length = 0;
      await expect(h.admin.distributionAmount(EXECUTOR, SESSION, id)).resolves.toEqual({
        amount: null,
      });
      // No decrypt and no DISCLOSURE event: there was no disclosure.
      expect(h.crypto.opened).toEqual([]);
      expect(auditActions(h.producer)).not.toContain('settlement.distribution.amount_viewed');
      // But the CASE-TRAIL row stands, and it is not conditional on the payload
      // (M48 PR2 review). This is a successful read behind `assertCaseVisible`
      // that confirms the row exists and that this estate is visible to the
      // caller; "who has been reading this estate" does not depend on whether
      // the row happened to carry a sum, and the four list surfaces record
      // themselves even when they return `[]`.
      expect(auditActions(h.producer)).toEqual(['settlement.case.viewed']);
      expect(auditEvents(h.producer)[0]).toMatchObject({
        actorId: EXECUTOR,
        actorType: 'user',
        detail: { surface: 'amount' },
      });
    });

    it('answers a crypto-shredded estate `content_erased`, not null and not 500', async () => {
      const h = buildAdminHarness();
      const { id } = await recorded(h, '42.00');
      // Legal erasure destroyed the decedent's DEK. The ledger row survives —
      // no hard deletes anywhere — but the sum it carried does not.
      for (const dekId of h.crypto.dekIds()) h.crypto.shredded.add(dekId);

      const refusal = await refusalOf(() => h.admin.distributionAmount(EXECUTOR, SESSION, id));
      expect(refusal).toEqual({ status: 410, body: { error: 'content_erased' } });
      // The spelling `DocumentsService` already uses for exactly this — one
      // behaviour, one spelling — and distinct from the `null` above.
    });
  });
});

describe('case close', () => {
  it('refuses while distributions are open, then closes', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '10.00',
    });

    await expect(h.admin.closeCase(OPERATOR, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'distributions_open' },
    });

    await h.admin.approveDistribution(OPERATOR, SESSION, dto.distributionId);
    await h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'in_progress');
    await h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'completed');

    await expect(h.admin.closeCase(OPERATOR, SESSION, caseId)).resolves.toEqual({
      status: 'closed',
    });
    expect(auditActions(h.producer)).toContain('settlement.case.closed');
  });

  it('is operator-only', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    await expect(h.admin.closeCase(EXECUTOR, SESSION, caseId)).rejects.toThrow(ForbiddenException);
  });
});

describe('case visibility for administration reads', () => {
  it('subject, reporter, executor, and operators can read', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    await expect(h.admin.listStages(DECEDENT, SESSION, caseId)).resolves.toEqual([]);
    await expect(h.admin.listStages(REPORTER, SESSION, caseId)).resolves.toEqual([]);
    await expect(h.admin.listStages(EXECUTOR, SESSION, caseId)).resolves.toEqual([]);
    await expect(h.admin.listStages(OPERATOR, SESSION, caseId)).resolves.toEqual([]);
  });

  it("a stranger's refusal is INDISTINGUISHABLE from an unknown case", async () => {
    // These used to be two tests: one asserting a stranger got Forbidden and
    // one, named "404s an unknown case rather than leaking its absence
    // differently", asserting an unknown id got NotFound. Together they
    // asserted the leak and called it the opposite — a case-existence oracle
    // on every read that funnels through `assertCaseVisible` (stages, tasks,
    // distributions, timeline). One test now, because the property is that the
    // two answers are the same and neither alone can see it.
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);

    const real = await h.admin.listStages(STRANGER, SESSION, caseId).catch((e: unknown) => e);
    const unknown = await h.admin
      .listStages(STRANGER, SESSION, randomUUID())
      .catch((e: unknown) => e);

    expect(real).toBeInstanceOf(NotFoundException);
    expect(unknown).toBeInstanceOf(NotFoundException);
    expect((real as NotFoundException).getStatus()).toBe(
      (unknown as NotFoundException).getStatus(),
    );
    expect((real as NotFoundException).getResponse()).toEqual(
      (unknown as NotFoundException).getResponse(),
    );
  });

  it('setDistributionStatus answers a stranger the SAME way three times over', async () => {
    // THE ORACLE THIS CLOSES. Until M21 PR4d this verb refused in three
    // distinguishable ways — 404 unknown id, 409 `case_not_verified`, 403 for a
    // real administrable case — so holding a distribution UUID let a caller
    // with no authority follow an estate's settlement progress. A replaced
    // executor is the concrete holder.
    //
    // One test, because the property is that the three answers are IDENTICAL
    // and no one of them alone can see it.
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '50.00',
    });
    await h.admin.approveDistribution(OPERATOR, SESSION, dto.distributionId);
    await h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'in_progress');
    await h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'completed');

    const probe = (id: string): Promise<unknown> =>
      h.admin.setDistributionStatus(STRANGER, SESSION, id, 'disputed').catch((e: unknown) => e);

    const onLiveCase = await probe(dto.distributionId);
    const unknownId = await probe(randomUUID());
    await h.admin.closeCase(OPERATOR, SESSION, caseId);
    const onClosedCase = await probe(dto.distributionId);

    for (const answer of [onLiveCase, unknownId, onClosedCase]) {
      expect(answer).toBeInstanceOf(NotFoundException);
    }
    // Byte-identical, not merely all-4xx: status AND body.
    const shape = (e: unknown): unknown => [
      (e as NotFoundException).getStatus(),
      (e as NotFoundException).getResponse(),
    ];
    expect(shape(onLiveCase)).toEqual(shape(unknownId));
    expect(shape(onClosedCase)).toEqual(shape(unknownId));
  });

  it('but an EXECUTOR is still told the case is closed, not that it is missing', async () => {
    // DE-ESCALATE, DO NOT REFUSE EVERYTHING. A fix that answered 404 to
    // everybody would pass the test above and be wrong: the person entitled to
    // act needs the specific answer, because their remedy differs from
    // "this id does not exist". This is the positive control for it.
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '50.00',
    });
    await h.admin.approveDistribution(OPERATOR, SESSION, dto.distributionId);
    await h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'in_progress');
    await h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'completed');
    await h.admin.closeCase(OPERATOR, SESSION, caseId);

    await expect(
      h.admin.setDistributionStatus(EXECUTOR, SESSION, dto.distributionId, 'disputed'),
    ).rejects.toMatchObject({ response: { error: 'case_not_verified' } });
  });

  it('an OPERATOR still learns an unknown case is unknown', async () => {
    // The uniform answer is about what a caller with no relationship learns.
    // Someone entitled to read the case must still be told the id is wrong,
    // or the fix would make the surface unusable for the people it is for.
    const h = buildAdminHarness();
    await expect(h.admin.listStages(OPERATOR, SESSION, randomUUID())).rejects.toThrow(
      NotFoundException,
    );
  });

  it('the timeline orders case milestones and stage decisions', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    const timeline = await h.admin.timeline(EXECUTOR, SESSION, caseId);
    const kinds = timeline.map((t) => t.kind);
    expect(kinds).toContain('case.reported');
    expect(kinds).toContain('case.verified');
    expect(kinds).toContain('stage.requested');
    expect(kinds).toContain('stage.approved');
    // Sorted oldest first.
    expect([...timeline].sort((a, b) => a.at.localeCompare(b.at))).toEqual(timeline);
  });
});

describe('tasks', () => {
  it('only the estate’s executor may complete a checklist item, and it is audited', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    await h.tasks.insertMany(undefined, caseId, [{ title: 'Locate the original will' }]);
    const taskId = h.tasks.rows[0]!.id;

    // A task on somebody else's estate answers exactly what an unknown task id
    // answers — the ladder `requestStage` had, keyed on a task UUID instead.
    const onReal = await refusalOf(() =>
      h.admin.completeTask(STRANGER, SESSION, taskId, { completed: true }),
    );
    const onAbsent = await refusalOf(() =>
      h.admin.completeTask(STRANGER, SESSION, randomUUID(), { completed: true }),
    );
    expect(onReal).toEqual(onAbsent);
    expect(onReal).toEqual({ status: 404, body: { error: 'not_found' } });

    const done = await h.admin.completeTask(EXECUTOR, SESSION, taskId, { completed: true });
    expect(done.completedBy).toBe(EXECUTOR);
    expect(auditActions(h.producer)).toContain('settlement.task.completed');

    // Reopening is allowed and clears the completion.
    const reopened = await h.admin.completeTask(EXECUTOR, SESSION, taskId, { completed: false });
    expect(reopened.completedAt).toBeNull();
  });

  it('404s an unknown task', async () => {
    const h = buildAdminHarness();
    await verifiedCase(h);
    await expect(
      h.admin.completeTask(EXECUTOR, SESSION, randomUUID(), { completed: true }),
    ).rejects.toThrow(NotFoundException);
  });
});

describe('the PII firewall holds across every PR2 audit payload', () => {
  it('emits only ids, enums, and counts', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '999.99',
    });
    await h.admin.approveDistribution(OPERATOR, SESSION, dto.distributionId);

    for (const event of auditEvents(h.producer)) {
      const detail = event['detail'] as Record<string, unknown>;
      for (const value of Object.values(detail)) {
        if (typeof value === 'string') {
          // The audit-safe token grammar: no whitespace, no '@'.
          expect(value).toMatch(/^[A-Za-z0-9_.:-]{1,128}$/);
        }
      }
    }
  });
});

describe('operator actions name the estate they act on', () => {
  /*
   * THE RULE, and it is the audit schema's own: `onBehalfOf` is "Set for
   * delegated access (trustee acting for an owner, OPERATOR SUPPORT)". So every
   * event whose ACTOR is an operator names the decedent. Before this fix the
   * four operator decisions that GRANT ACCESS TO AN ESTATE — the three stage
   * decisions, including the one that opens Zone A, and the distribution
   * approval — were the only operator events that did not, so from the audit
   * cluster alone you could not answer "who was granted access to THIS
   * person's estate" without leaving it and joining `settlement_cases` in core.
   *
   * Asserted as a PROPERTY over every event the run emits rather than as four
   * assertions, so an emitter added later is covered without anyone
   * remembering. Executor-actor events on the same resources stay null
   * deliberately: an executor administering an estate is not operator support,
   * which is why this is four of the eight sub-resource emitters and not all
   * eight.
   *
   * No test asserted an audit ENVELOPE at all before this one — the suite
   * checked action NAMES, which is why it was green either way.
   */
  it('EVERY operator-actor event carries the decedent, across the whole administration flow', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);

    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    const denied = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'documents');
    await h.admin.decideStage(OPERATOR, SESSION, denied.stageId, 'deny');
    await h.admin.revokeStage(OPERATOR, SESSION, stage.stageId);

    const dist = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '100.00',
    });
    await h.admin.approveDistribution(OPERATOR, SESSION, dist.distributionId);

    const operatorEvents = auditEvents(h.producer).filter((e) => e['actorType'] === 'operator');
    // Anti-vacuity: a filter that stops matching agrees with any expectation.
    expect(operatorEvents.length).toBeGreaterThanOrEqual(4);
    for (const event of operatorEvents) {
      expect({ action: event['action'], onBehalfOf: event['onBehalfOf'] }).toEqual({
        action: event['action'],
        onBehalfOf: DECEDENT,
      });
    }
  });

  it('AN OPERATOR COMPLETING A DISTRIBUTION IS RECORDED AS AN OPERATOR', async () => {
    /*
     * `distributions` has `created_by` and `approved_by` and no `completed_by`,
     * so this event is the only record of who completed one and in what
     * capacity. The flag was computed two statements above to authorize the
     * call and then discarded.
     *
     * Every pre-existing test of this method passed EXECUTOR — the one arm
     * where `'user'` is correct — so the operator disjunct, which is the only
     * reason the gate is consulted here, had no coverage at all.
     */
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const dist = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '100.00',
    });
    await h.admin.approveDistribution(OPERATOR, SESSION, dist.distributionId);
    await h.admin.setDistributionStatus(OPERATOR, SESSION, dist.distributionId, 'in_progress');
    await h.admin.setDistributionStatus(OPERATOR, SESSION, dist.distributionId, 'completed');

    const completed = auditEvents(h.producer).filter(
      (e) => e['action'] === 'settlement.distribution.completed',
    );
    expect(completed).toHaveLength(1);
    expect(completed[0]?.['actorType']).toBe('operator');
    expect(completed[0]?.['onBehalfOf']).toBe(DECEDENT);
  });

  it('AN EXECUTOR completing one is still a user, and still names no estate', async () => {
    /*
     * The other arm, pinned so the fix above cannot be "simplified" into
     * marking every completion as operator support.
     */
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const dist = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: randomUUID(),
      amount: '100.00',
    });
    await h.admin.approveDistribution(OPERATOR, SESSION, dist.distributionId);
    await h.admin.setDistributionStatus(EXECUTOR, SESSION, dist.distributionId, 'in_progress');
    await h.admin.setDistributionStatus(EXECUTOR, SESSION, dist.distributionId, 'completed');

    const completed = auditEvents(h.producer).filter(
      (e) => e['action'] === 'settlement.distribution.completed',
    );
    expect(completed).toHaveLength(1);
    expect(completed[0]?.['actorType']).toBe('user');
    expect(completed[0]?.['onBehalfOf']).toBeNull();
  });
});

describe('the operator breadth bound', () => {
  /**
   * Four properties, and three are invisible to a test of the fourth: where the
   * ceiling is, that PERMISSIVE actions are counted with the right estate and
   * kind, that PROTECTIVE ones never are, and that crossing it WARNS rather
   * than refuses. A refusal would satisfy every test here but the last two.
   *
   * `verifiedCase`, not `readyCase` — the latter approves a stage of its own,
   * and a fixture that records before the test acts hides an arm that records
   * nothing.
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

  const warnings = (h: AdminHarness): string[] =>
    h.producer.messages
      .map((m) => String(m.value))
      .filter((v) => v.includes('settlement.operator.breadth_exceeded'));

  it('crosses ABOVE the ceiling and not AT it', () => {
    // Both arms of the boundary the property decides. `>=` for `>` is the
    // likeliest mutation and it costs exactly one legitimate operator.
    expect(breadthExceeded(OPERATOR_BREADTH_MAX_CASES - 1)).toBe(false);
    expect(breadthExceeded(OPERATOR_BREADTH_MAX_CASES)).toBe(false);
    expect(breadthExceeded(OPERATOR_BREADTH_MAX_CASES + 1)).toBe(true);
  });

  it('keeps the permissive and protective sets DISJOINT', () => {
    // A protective action landing in the counted set inverts the control:
    // the operator who withdraws access runs out before the one who grants it.
    const permissive = new Set<string>(PERMISSIVE_OPERATOR_ACTIONS);
    expect(PROTECTIVE_OPERATOR_ACTIONS.filter((a) => permissive.has(a))).toEqual([]);
    expect(PROTECTIVE_OPERATOR_ACTIONS.length).toBeGreaterThan(0);
    expect(PERMISSIVE_OPERATOR_ACTIONS.length).toBeGreaterThan(0);
  });

  it('counts an APPROVED stage, naming the estate and the kind', async () => {
    const { monitor, calls } = spy(1);
    const h = buildAdminHarness(monitor);
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    expect(calls).toEqual([{ operator: OPERATOR, caseId, action: 'stage.approved' }]);
  });

  it('does NOT count a DENIED stage', async () => {
    // The protective arm of the very same verb, which is the arm a fixture
    // built on the approve path would never reach.
    const { monitor, calls } = spy(1);
    const h = buildAdminHarness(monitor);
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'deny');
    expect(calls).toEqual([]);
  });

  it('does NOT count a REVOKED stage', async () => {
    const { monitor, calls } = spy(1);
    const h = buildAdminHarness(monitor);
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    expect(calls).toHaveLength(1);
    calls.length = 0;
    await h.admin.revokeStage(OPERATOR, SESSION, stage.stageId);
    expect(calls).toEqual([]);
  });

  it('WARNS above the ceiling, and lets the action through', async () => {
    // Which product this is. A refusal passes every other case in this block.
    const { monitor } = spy(OPERATOR_BREADTH_MAX_CASES + 1);
    const h = buildAdminHarness(monitor);
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    const decided = await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    expect(decided.status).toEqual('approved');
    expect(warnings(h)).toHaveLength(1);
  });

  it('stays silent at the ceiling', async () => {
    // Anti-vacuity for the case above: a warning that always fired would pass
    // it and mean nothing.
    const { monitor } = spy(OPERATOR_BREADTH_MAX_CASES);
    const h = buildAdminHarness(monitor);
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    expect(warnings(h)).toEqual([]);
  });

  it('names no estate in the warning', async () => {
    // The event is about the operator's pattern ACROSS estates. Naming one
    // would put a family into a record that is not about them, picked
    // arbitrarily out of a set.
    const { monitor } = spy(OPERATOR_BREADTH_MAX_CASES + 1);
    const h = buildAdminHarness(monitor);
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    const [warning] = warnings(h);
    expect(warning).toBeDefined();
    expect(warning).not.toContain(caseId);
    expect(warning).not.toContain(DECEDENT);
  });
});

describe("the reporter's link, re-derived at read time (M48, docs/03 §6g)", () => {
  /**
   * DERIVED FROM THE SERVICE SOURCE, never hand-listed. `assertCaseVisible` is
   * the gate; the routes behind it are whatever calls it today. A sixth one
   * added tomorrow joins this fence without anybody remembering it exists,
   * which is the failure mode that let this defect reach five routes while the
   * residual describing it named two.
   */
  /**
   * ONE SCANNER, read by every fence below (M48 PR2 review). There were two
   * near-identical copies of this loop, and the equality between their outputs
   * read as a cross-check while comparing a parser to a verbatim copy of
   * itself. A second copy is a copy that drifts.
   *
   * Comments are stripped as BLOCKS, not by leading `*`: a call commented out
   * with `/* … *\/` does not start with `*` and used to count as a live one.
   * Bodies are JOINED before matching, so a call whose arguments wrap over five
   * lines is still a call — which every multi-argument call in these files is.
   */
  const MEMBER_DECL =
    /^ {2}(?:(?:public|private|protected|static|readonly|abstract)\s+)+?(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(|^ {2}(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(/;

  function membersOf(file: string): Map<string, string> {
    const src = readFileSync(join(__dirname, '..', 'src', file), 'utf8');
    const bodies = new Map<string, string[]>();
    let current: string | null = null;
    let inBlock = false;
    for (const line of src.split('\n')) {
      const trimmed = line.trim();
      if (inBlock) {
        if (trimmed.includes('*/')) inBlock = false;
        continue;
      }
      if (trimmed.startsWith('/*')) {
        if (!trimmed.includes('*/')) inBlock = true;
        continue;
      }
      if (trimmed.startsWith('//')) continue;
      const decl = MEMBER_DECL.exec(line);
      if (decl) {
        current = (decl[1] ?? decl[2]) as string;
        if (!bodies.has(current)) bodies.set(current, []);
      }
      if (current !== null) (bodies.get(current) as string[]).push(line);
    }
    return new Map([...bodies].map(([name, lines]) => [name, lines.join('\n')]));
  }

  /** The last string literal in a call's argument list — the `surface` slot. */
  function surfaceArg(body: string, callee: string): string | null {
    const call = new RegExp(`${callee}\\(([\\s\\S]*?)\\)`).exec(body);
    if (call === null) return null;
    const literals = [...(call[1] as string).matchAll(/'([^']*)'/g)].map((m) => m[1] as string);
    return literals.length === 0 ? null : (literals[literals.length - 1] as string);
  }

  /** `assertCaseVisible` callers in admin.service.ts -> the surface each records. */
  function gatedSurfaces(): Map<string, string | null> {
    const gated = new Map<string, string | null>();
    for (const [name, body] of membersOf('admin.service.ts')) {
      if (!body.includes('this.assertCaseVisible(')) continue;
      gated.set(name, surfaceArg(body, 'this\\.recordCaseRead'));
    }
    return gated;
  }

  /** The OTHER gate: `getCase` takes a Cedar decision and emits directly. */
  function cedarSurfaces(): Map<string, string | null> {
    const found = new Map<string, string | null>();
    for (const [name, body] of membersOf('settlement.service.ts')) {
      if (!body.includes('this.events.caseViewed(')) continue;
      found.set(name, surfaceArg(body, 'this\\.events\\.caseViewed'));
    }
    return found;
  }

  /** How many times each helper is actually called, across live code. */
  function callSites(file: string, needle: string): number {
    return [...membersOf(file).values()].join('\n').split(needle).length - 1;
  }

  function routesBehindTheGate(): string[] {
    return [...gatedSurfaces().keys()].sort();
  }

  /** How to reach each gated route. Compared as a SET against the derivation. */
  const EXERCISE: Record<
    string,
    (
      h: AdminHarness,
      who: string,
      ids: { caseId: string; distributionId: string },
    ) => Promise<unknown>
  > = {
    distributionAmount: (h, who, ids) =>
      h.admin.distributionAmount(who, SESSION, ids.distributionId),
    listDistributions: (h, who, ids) => h.admin.listDistributions(who, SESSION, ids.caseId),
    listStages: (h, who, ids) => h.admin.listStages(who, SESSION, ids.caseId),
    listTasks: (h, who, ids) => h.admin.listTasks(who, SESSION, ids.caseId),
    timeline: (h, who, ids) => h.admin.timeline(who, SESSION, ids.caseId),
  };

  async function estateWithMoney(
    h: AdminHarness,
  ): Promise<{ caseId: string; distributionId: string }> {
    const caseId = await readyCase(h);
    h.coreReads.link(DECEDENT, REPORTER);
    const dto = await h.admin.recordDistribution(EXECUTOR, SESSION, caseId, {
      beneficiaryContactId: CONTACT,
      amount: '4500.00',
    });
    return { caseId, distributionId: dto.distributionId };
  }

  it('the gated route set is DERIVED, and every member of it is exercised here', () => {
    const derived = routesBehindTheGate();
    // ANTI-VACUITY: a scan that returns nothing and a scan that found nothing
    // look identical, and two empty sets compare equal.
    expect(derived.length).toBeGreaterThanOrEqual(5);
    expect(derived).toContain('distributionAmount');
    expect(derived).toEqual(Object.keys(EXERCISE).sort());
  });

  it('an UNLINKED reporter is refused by every route behind the gate', async () => {
    const h = buildAdminHarness();
    const ids = await estateWithMoney(h);
    h.coreReads.unlink(DECEDENT, REPORTER);
    const refused: string[] = [];
    for (const [name, call] of Object.entries(EXERCISE)) {
      const ok = await call(h, REPORTER, ids).then(
        () => true,
        () => false,
      );
      if (!ok) refused.push(name);
    }
    expect(refused.sort()).toEqual(Object.keys(EXERCISE).sort());
  });

  it('a STILL-LINKED reporter is admitted by every one of them', async () => {
    // THE POSITIVE CONTROL. Without it, "the reporter is refused everywhere" is
    // equally consistent with a harness that refuses everyone.
    const h = buildAdminHarness();
    const ids = await estateWithMoney(h);
    const admitted: string[] = [];
    for (const [name, call] of Object.entries(EXERCISE)) {
      const ok = await call(h, REPORTER, ids).then(
        () => true,
        () => false,
      );
      if (ok) admitted.push(name);
    }
    expect(admitted.sort()).toEqual(Object.keys(EXERCISE).sort());
  });

  it('the money route refuses an unlinked reporter with the UNIFORM refusal', async () => {
    const h = buildAdminHarness();
    const ids = await estateWithMoney(h);
    h.coreReads.unlink(DECEDENT, REPORTER);
    // Indistinguishable from a stranger's refusal and from an unknown id: an
    // unlinked reporter must not learn that the distribution exists.
    const onUnlinked = await refusalOf(() =>
      h.admin.distributionAmount(REPORTER, SESSION, ids.distributionId),
    );
    const onStranger = await refusalOf(() =>
      h.admin.distributionAmount(STRANGER, SESSION, ids.distributionId),
    );
    const onUnknown = await refusalOf(() =>
      h.admin.distributionAmount(STRANGER, SESSION, randomUUID()),
    );
    expect(onUnlinked).toEqual(onStranger);
    expect(onUnlinked).toEqual(onUnknown);
  });

  it('and still returns the exact decimal to a reporter who is still linked', async () => {
    const h = buildAdminHarness();
    const ids = await estateWithMoney(h);
    await expect(
      h.admin.distributionAmount(REPORTER, SESSION, ids.distributionId),
    ).resolves.toEqual({ amount: '4500.00' });
  });

  it('the executor arm was ALREADY live — the double now says so too', async () => {
    // The contrast M48 exists to remove. `isExecutorOf` is a JOIN on a live
    // contact, so unlinking has always revoked the executor. Until the harness
    // was repaired this passed on a fake that ignored links entirely, which
    // made the contrast unmeasurable.
    const h = buildAdminHarness();
    const ids = await estateWithMoney(h);
    await expect(h.admin.timeline(EXECUTOR, SESSION, ids.caseId)).resolves.toBeDefined();
    h.coreReads.unlink(DECEDENT, EXECUTOR);
    await expect(h.admin.timeline(EXECUTOR, SESSION, ids.caseId)).rejects.toThrow();
  });

  /**
   * THE SURFACE UNION IS DERIVED FROM THE GATES, NOT MAINTAINED BESIDE THEM.
   *
   * `CaseReadSurface` used to exist twice — once in `events.service.ts` and
   * again, narrower, as the wrapper's `surface` parameter — with nothing tying
   * either to the set of reads that actually go through a gate. They agreed by
   * hand until M23 PR4b added `distributionAmount` to `assertCaseVisible` and
   * to neither union, so from 2026-08-21 to 2026-08-28 the fifth gated read
   * produced no case-trail row and nothing went red.
   *
   * THE CORPUS IS TWO SOURCE FILES, one per gate: `admin.service.ts` for the
   * five behind `assertCaseVisible`, and `settlement.service.ts` for `getCase`,
   * which takes a Cedar decision and emits directly. A read that records no
   * surface fails the first assertion by name; a surface declared in the union
   * that no read produces fails the second. Neither can be satisfied by editing
   * one file.
   *
   * A case read on NEITHER gate is outside this corpus and needs its own fence.
   * `listMyCases` is exactly that read — raw SQL, no gate object — and it is
   * deliberately unaudited; `settlement.service.ts`'s docstring carries the
   * reason, and `every getCase read is recorded` is what pins the Cedar one.
   */
  function declaredSurfaces(): string[] {
    const src = readFileSync(join(__dirname, '..', 'src', 'events.service.ts'), 'utf8');
    const block = /export type CaseReadSurface =([\s\S]*?);/.exec(src);
    if (block === null) throw new Error('CaseReadSurface union not found in events.service.ts');
    // `[^']*`, not `[a-z]+`: a union member the character class cannot spell is
    // a member this scan drops SILENTLY, and a declared-but-unproduced surface
    // is precisely what the second assertion exists to catch.
    return [...(block[1] as string).matchAll(/'([^']*)'/g)].map((m) => m[1] as string).sort();
  }

  it('every read behind the gate records a SURFACE — none is silent', () => {
    const gated = gatedSurfaces();
    // ANTI-VACUITY AT EVERY LEVEL. A scan that found nothing and a scan that
    // found no silent route look identical, so: a floor on the routes, and —
    // because a route whose DECLARATION the scanner misses is attributed to no
    // one and vanishes without changing this map — the raw call-site counts
    // must match the routes and the surfaces they produce.
    expect(gated.size).toBeGreaterThanOrEqual(5);
    expect(callSites('admin.service.ts', 'this.assertCaseVisible(')).toBe(gated.size);
    const recorded = [...gated.values()].filter((s) => s !== null);
    expect(callSites('admin.service.ts', 'this.recordCaseRead(')).toBe(recorded.length);
    const silent = [...gated.entries()].filter(([, s]) => s === null).map(([n]) => n);
    expect(silent).toEqual([]);
  });

  it('the declared surface union is exactly what the reads produce', () => {
    const cedar = cedarSurfaces();
    // The OTHER gate is scanned, not hand-injected: `'case'` used to be added
    // here by name, so deleting `getCase`'s emit left both assertions green.
    expect([...cedar.keys()]).toEqual(['getCase']);
    const silent = [...cedar.entries()].filter(([, s]) => s === null).map(([n]) => n);
    expect(silent).toEqual([]);
    const produced = [...gatedSurfaces().values(), ...cedar.values()].filter(
      (s): s is string => s !== null,
    );
    const expected = [...new Set(produced)].sort();
    expect(declaredSurfaces()).toEqual(expected);
    // FLOORS, so two empty sets cannot satisfy the equality above.
    expect(expected).toEqual(expect.arrayContaining(['amount', 'case', 'timeline']));
    expect(expected.length).toBeGreaterThanOrEqual(6);
  });

  /**
   * M23 PR4b'S SET EQUALITY, RE-ARMED FOR THE LINK DIMENSION.
   *
   * `admits exactly the callers listDistributions admits` says this route's
   * authority IS `listDistributions`'s, because it reveals a field of a row
   * that route already returns. It cannot see the LINK dimension: its fixture
   * reporter is linked by `verifiedCase`, so an alternative that refused the
   * money route alone leaves both admitted sets unchanged and that comparison
   * stays green.
   *
   * Before M48 PR1 the fixture reporter was UNLINKED — a state intake cannot
   * produce — and the money-only alternative DID redden it. That is the
   * measurement M48 PR1 cited to justify taking all five reads. Repairing the
   * fixture in the same commit silently removed the arm the argument rested
   * on, so the prose outlived its evidence.
   *
   * This is that arm, stated where an unlink can be expressed. The property is
   * not "the reporter is refused" — the test above says that. It is that these
   * two routes admit the SAME SET whatever the link state, so shrinking one
   * without the other reddens HERE.
   */
  it('admit the same SET after an unlink — the arm the fixture repair removed', async () => {
    const h = buildAdminHarness();
    const ids = await estateWithMoney(h);
    h.coreReads.unlink(DECEDENT, REPORTER);
    const parties = { DECEDENT, REPORTER, EXECUTOR, OPERATOR, STRANGER };

    const admits = async (call: (who: string) => Promise<unknown>): Promise<string[]> => {
      const out: string[] = [];
      for (const [name, who] of Object.entries(parties)) {
        const ok = await call(who).then(
          () => true,
          () => false,
        );
        if (ok) out.push(name);
      }
      return out;
    };

    const onList = await admits((who) => h.admin.listDistributions(who, SESSION, ids.caseId));
    const onAmount = await admits((who) =>
      h.admin.distributionAmount(who, SESSION, ids.distributionId),
    );
    expect(onAmount).toEqual(onList);
    // ANTI-VACUITY, on both halves. Two empty sets are equal, and so are two
    // sets that lost the same party for an unrelated reason: the floor names
    // the parties these routes exist for, and the REPORTER's absence is what
    // distinguishes a working gate from no gate at all.
    expect(onAmount).toEqual(expect.arrayContaining(['EXECUTOR', 'OPERATOR']));
    expect(onAmount).not.toContain('STRANGER');
    expect(onAmount).not.toContain('REPORTER');
  });
});
