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
  async function readyCase(h: AdminHarness): Promise<string> {
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    return caseId;
  }

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
  it('subject, reporter, executor, and operators can read; strangers cannot', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    await expect(h.admin.listStages(DECEDENT, caseId)).resolves.toEqual([]);
    await expect(h.admin.listStages(REPORTER, caseId)).resolves.toEqual([]);
    await expect(h.admin.listStages(EXECUTOR, caseId)).resolves.toEqual([]);
    await expect(h.admin.listStages(OPERATOR, caseId)).resolves.toEqual([]);
    await expect(h.admin.listStages(STRANGER, caseId)).rejects.toThrow(ForbiddenException);
  });

  it('404s an unknown case rather than leaking its absence differently', async () => {
    const h = buildAdminHarness();
    await expect(h.admin.listStages(OPERATOR, randomUUID())).rejects.toThrow(NotFoundException);
  });

  it('the timeline orders case milestones and stage decisions', async () => {
    const h = buildAdminHarness();
    const caseId = await verifiedCase(h);
    const stage = await h.admin.requestStage(EXECUTOR, SESSION, caseId, 'inventory');
    await h.admin.decideStage(OPERATOR, SESSION, stage.stageId, 'approve');
    const timeline = await h.admin.timeline(EXECUTOR, caseId);
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
