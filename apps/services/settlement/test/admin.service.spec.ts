import { randomUUID } from 'node:crypto';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
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
  h.coreReads.link(DECEDENT, EXECUTOR);
  h.coreReads.executors.add(`${DECEDENT}:${EXECUTOR}`);
  h.operators.active.add(OPERATOR);
  h.operators.active.add(SECOND_OPERATOR);
  return row.id;
}

/** A verified case with one approved stage — the state distributions need. */
async function readyCase(h: AdminHarness): Promise<string> {
  const caseId = await verifiedCase(h);
  const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
  await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
  return caseId;
}

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

  it('only the estate’s executor may request a stage', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    await expect(h.admin.requestStage(STRANGER, SESSION, caseId, 'inventory')).rejects.toThrow(
      ForbiddenException,
    );
    // Even the reporter, who opened the case, is not the executor.
    await expect(h.admin.requestStage(REPORTER, SESSION, caseId, 'inventory')).rejects.toThrow(
      ForbiddenException,
    );
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

  it('a non-executor cannot record a distribution', async () => {
    const h = buildAdminHarness();
    const caseId = await readyCase(h);
    await expect(
      h.admin.recordDistribution(STRANGER, SESSION, caseId, {
        beneficiaryContactId: CONTACT,
        amount: '1.00',
      }),
    ).rejects.toThrow(ForbiddenException);
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

    await expect(
      h.admin.completeTask(STRANGER, SESSION, taskId, { completed: true }),
    ).rejects.toThrow(ForbiddenException);

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
