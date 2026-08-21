/**
 * End-to-end integration test against a real Postgres, gated exactly like
 * packages/db: set PG_TEST_URL to run (CI service container; locally e.g.
 * postgres://estate:estate_dev@localhost:5434/core). Runs the service's real
 * migrations into a scratch schema, boots the Nest app over it with an
 * in-memory audit producer, and drives the profile/contacts flow with
 * supertest — including the docs/03 §5.5 ABAC read boundary end to end.
 */
import 'reflect-metadata';
import type { Server } from 'node:http';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import {
  blindIndexCaptureCorpus,
  blindIndexCaptureGaps,
  checkConventions,
  Migrator,
} from '@estate/db';
import { TOPICS, type MfaLevel } from '@estate/contracts';
import { DekConflictError } from '@estate/crypto';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { Client } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { canonicalCode } from '../src/contact-links.service';
import { InMemoryAuditProducer } from '@estate/kafka';
import { PgDekRepository } from '../src/dek.repository';
import { AUDIT_PRODUCER, PG_POOL_CONFIG } from '../src/di-tokens';
import {
  SETTLEMENT_AUTHORITY,
  type AccessStage,
  type SettlementStageAuthority,
  type StageAccessAuthority,
} from '@estate/settlement-client';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

/**
 * Stands in for real identity introspection: a bearer token `<level>:<userId>`
 * verifies to that session (what CallerGuard would get from HttpSessionVerifier
 * → identity's /v1/auth/session); a malformed token verifies to null (⇒ 401).
 * The real cross-service path is proven in the session-verification e2e.
 *
 * `stepup` is now meaningful here: M13 PR1 put StepUpGuard on the
 * role-assignment mutations (docs/01 §5), which M2 shipped without.
 */
const fakeVerifier: SessionVerifier = {
  verify: (token) => {
    const m = /^(mfa|stepup):([0-9a-f-]{36})$/.exec(token);
    if (!m) {
      return Promise.resolve(null);
    }
    const [, level, userId] = m;
    const ctx: SessionContext = {
      userId: userId!,
      sessionId: '00000000-0000-4000-8000-000000000000',
      mfaLevel: level as MfaLevel,
      stepupExpiresAt: level === 'stepup' ? new Date(Date.now() + 5 * 60 * 1000) : null,
      audience: 'account',
    };
    return Promise.resolve(ctx);
  },
};

/**
 * SETTLEMENT'S ANSWER, stubbed for the int suite — see the override below.
 * Defaults to REFUSING, exactly as the real client does on any failure, so an
 * "executor is refused" assertion cannot pass because nobody wired anything.
 */
class StubStageAuthority implements SettlementStageAuthority {
  allowed = false;
  calls: AccessStage[] = [];
  checkStageAccess(input: {
    bearerToken: string;
    ownerUserId: string;
    stage: AccessStage;
  }): Promise<StageAccessAuthority> {
    this.calls.push(input.stage);
    return Promise.resolve(
      this.allowed
        ? { allowed: true, caseId: '00000000-0000-4000-8000-0000000000ca' }
        : { allowed: false, caseId: null },
    );
  }
}

const OWNER = randomUUID();
const GRANTEE = randomUUID();
const STRANGER = randomUUID();
const LEGAL_NAME = 'Jane Quincy Public';
const NAMED_CONTACT = 'Named Beneficiary Contact';
const OTHER_CONTACT = 'Unrelated Private Contact';

describeIfPg('profile & contacts service end to end', () => {
  jest.setTimeout(120_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `profsvc_test_${Date.now()}`;
  let admin: Client;
  let app: INestApplication;
  let server: Server;
  let producer: InMemoryAuditProducer;
  let stageAuthority: StubStageAuthority;

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Put the scratch schema on the admin connection's search_path too: the
    // convention versions triggers run `INSERT INTO <table>_versions`
    // UNQUALIFIED, so a raw admin UPDATE that fires a trigger (e.g. setting
    // linked_user_id below) must resolve those names against the scratch schema.
    // (In production each cluster is its own DB with tables in `public`, so the
    // app pool's search_path already covers this — only this raw client needs it.)
    await admin.query(`SET search_path TO ${schema}, public`);

    const migrClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrClient.connect();
    try {
      const migrator = new Migrator(migrClient, `${__dirname}/../migrations`);
      const { applied } = await migrator.migrate();
      expect(applied).toContain('001_core_schema.sql');
      expect(applied).toContain('002_dek_unique_active.sql');
      expect(applied).toContain('003_contact_link_invitations.sql');
    } finally {
      await migrClient.end();
    }

    process.env['DATABASE_URL'] = pgUrl;
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['EMAIL_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];

    producer = new InMemoryAuditProducer();
    stageAuthority = new StubStageAuthority();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AUDIT_PRODUCER)
      .useValue(producer)
      .overrideProvider(PG_POOL_CONFIG)
      .useValue({ connectionString: pgUrl, options: `-c search_path=${schema}` })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      /*
       * SETTLEMENT IS STUBBED, and only settlement (M23 PR4a). The real client
       * would reach for a service this suite does not run, and the point of
       * this file is the DATABASE half — that the executor's contacts really
       * come back from real Postgres once the answer is yes, and that the
       * grant query really refuses them when it is no. Whether settlement gives
       * the right answer is settlement's own suite, and whether this service
       * asks it correctly is `contacts.service.spec.ts`.
       *
       * It DEFAULTS TO REFUSING, like the real client on any failure, so a test
       * that wants the estate open has to say so.
       */
      .overrideProvider(SETTLEMENT_AUTHORITY)
      .useValue(stageAuthority)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    server = app.getHttpServer() as Server;
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  // The gateway-injected `x-estate-user-id` header is replaced by the caller's
  // bearer token; asUser now yields the Authorization header value.
  const asUser = (id: string): string => `Bearer mfa:${id}`;
  /** A session with a fresh step-up — required by the role-assignment mutations. */
  const asElevated = (id: string): string => `Bearer stepup:${id}`;

  it('rejects a request without the gateway-injected user header (401)', async () => {
    const res = await request(server).get('/v1/profile');
    expect(res.status).toBe(401);
  });

  it('upserts an encrypted profile and reads it back decrypted', async () => {
    const put = await request(server).put('/v1/profile').set('authorization', asUser(OWNER)).send({
      legalName: LEGAL_NAME,
      ssn: '123456789',
      maritalStatus: 'married',
      stateOfResidence: 'CA',
    });
    expect(put.status).toBe(200);

    // Ciphertext at rest — the plaintext legal name never appears in the column.
    const { rows } = await admin.query(
      `SELECT legal_name_ct, ssn_last4_ct, state_of_residence FROM ${schema}.profiles WHERE user_id = $1`,
      [OWNER],
    );
    const row = rows[0] as {
      legal_name_ct: Buffer;
      ssn_last4_ct: Buffer;
      state_of_residence: string;
    };
    expect(row.legal_name_ct.toString('utf8')).not.toContain('Jane');
    expect(row.state_of_residence).toBe('CA'); // plaintext by design (template driver)

    const get = await request(server).get('/v1/profile').set('authorization', asUser(OWNER));
    expect(get.status).toBe(200);
    const view = get.body as { legalName: string; ssnLast4: string; stateOfResidence: string };
    expect(view.legalName).toBe(LEGAL_NAME);
    expect(view.ssnLast4).toBe('6789');
    expect(view.stateOfResidence).toBe('CA');
  });

  let namedId: string;
  let otherId: string;
  let linkedContactId: string;
  let roleAssignmentId: string;

  it('owner creates contacts (encrypted) and captures a version row on update', async () => {
    const named = await request(server)
      .post('/v1/contacts')
      .set('authorization', asUser(OWNER))
      .send({ name: NAMED_CONTACT, email: 'named@example.com' });
    expect(named.status).toBe(201);
    namedId = (named.body as { id: string }).id;

    const other = await request(server)
      .post('/v1/contacts')
      .set('authorization', asUser(OWNER))
      .send({ name: OTHER_CONTACT });
    expect(other.status).toBe(201);
    otherId = (other.body as { id: string }).id;

    // The contact through which GRANTEE is a platform user (invite accepted).
    const linked = await request(server)
      .post('/v1/contacts')
      .set('authorization', asUser(OWNER))
      .send({ name: 'Grantee Person' });
    linkedContactId = (linked.body as { id: string }).id;
    await admin.query(`UPDATE ${schema}.contacts SET linked_user_id = $1 WHERE id = $2`, [
      GRANTEE,
      linkedContactId,
    ]);

    // Update a contact → the versions shadow table captures the prior row.
    const upd = await request(server)
      .put(`/v1/contacts/${namedId}`)
      .set('authorization', asUser(OWNER))
      .send({ name: NAMED_CONTACT, email: 'named@example.com', relationship: 'friend' });
    expect(upd.status).toBe(200);
    const { rows } = await admin.query(
      `SELECT count(*)::int AS n FROM ${schema}.contacts_versions WHERE row_id = $1`,
      [namedId],
    );
    expect((rows[0] as { n: number }).n).toBe(1);
  });

  it('the edit above did NOT clear the contact link (raw SQL, M13 PR1)', async () => {
    // The link is the authorization edge behind docs/03 §6b and M7's executor
    // resolution. Asserted here rather than only in the service unit test
    // because the defect lived in the repo's UPDATE statement, which a fake
    // repo cannot see: a `linked_user_id = ...` reappearing in that SQL has to
    // turn THIS red.
    const upd = await request(server)
      .put(`/v1/contacts/${linkedContactId}`)
      .set('authorization', asUser(OWNER))
      .send({ name: 'Grantee Person', phone: '555-0142' });
    expect(upd.status).toBe(200);

    const { rows } = await admin.query(
      `SELECT linked_user_id FROM ${schema}.contacts WHERE id = $1`,
      [linkedContactId],
    );
    expect((rows[0] as { linked_user_id: string | null }).linked_user_id).toBe(GRANTEE);
  });

  it('serves grantee candidates as their own projection, over real SQL (M15 PR3)', async () => {
    // A Shamir share is sealed to a specific ACCOUNT's published recovery key,
    // so a grantee picker cannot work from a contact id alone. Asserted here
    // because the account id comes from a column no other response returns —
    // a fake repo would happily invent it.
    const candidates = await request(server)
      .get('/v1/contacts/grantee-candidates')
      .set('authorization', asUser(OWNER));
    expect(candidates.status).toBe(200);
    const rows = candidates.body as Array<{ contactId: string; userId: string; name: string }>;
    expect(rows).toEqual([{ contactId: linkedContactId, userId: GRANTEE, name: 'Grantee Person' }]);

    // The route is DECLARED BEFORE `contacts/:id`, so the literal path must not
    // be captured as a uuid parameter — which would 400 rather than answer.
    expect(JSON.stringify(rows)).not.toContain('uuid');

    // And the general summary is UNCHANGED: M15 PR3 deliberately did not widen
    // it, so no existing client's disclosure surface moved.
    const list = await request(server).get('/v1/contacts').set('authorization', asUser(OWNER));
    expect(list.status).toBe(200);
    for (const row of list.body as Array<Record<string, unknown>>) {
      expect(Object.keys(row)).not.toContain('linkedUserId');
    }
  });

  it('role-assignment mutations require a fresh step-up (docs/01 §5)', async () => {
    const denied = await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asUser(OWNER)) // authenticated, but no step-up
      .send({ contactId: linkedContactId, role: 'trustee', scopeType: 'estate' });
    expect(denied.status).toBe(403);
    expect(denied.body).toEqual({ error: 'stepup_required' });
  });

  it('owner grants GRANTEE a scope naming ONLY the named contact', async () => {
    const ra = await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asElevated(OWNER))
      .send({
        contactId: linkedContactId,
        role: 'beneficiary',
        scopeType: 'asset',
        scopeId: namedId,
      });
    expect(ra.status).toBe(201);
    roleAssignmentId = (ra.body as { id: string }).id;

    const perm = await request(server)
      .post(`/v1/role-assignments/${roleAssignmentId}/permissions`)
      .set('authorization', asElevated(OWNER))
      .send({ resource: 'contact', action: 'read' });
    expect(perm.status).toBe(201);
  });

  it('refuses a SECOND identical live designation (M13 review)', async () => {
    // Two clicks, or a click and a retry, used to mint two identical live
    // executor designations: harmless to every resolver (they all use EXISTS),
    // which is why it would have gone unnoticed — but revoking "the" designation
    // would leave the duplicate conferring everything, and on the docs/03 §5.1
    // executor chain "revoked" has to mean revoked.
    const again = await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asElevated(OWNER))
      .send({
        contactId: linkedContactId,
        role: 'beneficiary',
        scopeType: 'asset',
        scopeId: namedId,
      });
    expect(again.status).toBe(409);
    expect(again.body).toEqual({ error: 'role_already_granted' });

    // A DIFFERENT condition on the same contact and role is a different
    // designation, and still allowed.
    const different = await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asElevated(OWNER))
      .send({
        contactId: linkedContactId,
        role: 'beneficiary',
        scopeType: 'asset',
        scopeId: namedId,
        effectiveCondition: 'on_death_verified',
      });
    expect(different.status).toBe(201);
    await request(server)
      .delete(`/v1/role-assignments/${(different.body as { id: string }).id}`)
      .set('authorization', asElevated(OWNER))
      .expect(204);

    // ...and once revoked, the original shape can be granted again — the index is
    // partial on deleted_at, so a soft delete really does free the slot.
    const revocableId = (
      await request(server)
        .post('/v1/role-assignments')
        .set('authorization', asElevated(OWNER))
        .send({ contactId: otherId, role: 'viewer', scopeType: 'estate' })
        .expect(201)
    ).body as { id: string };
    await request(server)
      .delete(`/v1/role-assignments/${revocableId.id}`)
      .set('authorization', asElevated(OWNER))
      .expect(204);
    await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asElevated(OWNER))
      .send({ contactId: otherId, role: 'viewer', scopeType: 'estate' })
      .expect(201);
  });

  it('§5.5: the grant-holder reads ONLY the named contact; the other is denied', async () => {
    const allowed = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts/${namedId}`)
      .set('authorization', asUser(GRANTEE));
    expect(allowed.status).toBe(200);
    expect((allowed.body as { name: string }).name).toBe(NAMED_CONTACT);

    const denied = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts/${otherId}`)
      .set('authorization', asUser(GRANTEE));
    expect(denied.status).toBe(403);
    expect(denied.body).toEqual({ error: 'forbidden' });

    // The list is filtered to the named contact only — no enumeration.
    const list = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts`)
      .set('authorization', asUser(GRANTEE));
    expect(list.status).toBe(200);
    const names = (list.body as Array<{ name: string }>).map((c) => c.name);
    expect(names).toEqual([NAMED_CONTACT]);
  });

  it('a stranger with no grant is denied both the list and a single read', async () => {
    const list = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts`)
      .set('authorization', asUser(STRANGER));
    expect(list.status).toBe(403);

    const one = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts/${namedId}`)
      .set('authorization', asUser(STRANGER));
    expect(one.status).toBe(403);
  });

  it('owner sees all their contacts (owner path)', async () => {
    const list = await request(server)
      .get(`/v1/profiles/${OWNER}/contacts`)
      .set('authorization', asUser(OWNER));
    expect(list.status).toBe(200);
    expect((list.body as unknown[]).length).toBe(3);
  });

  /**
   * THE THAW, AGAINST REAL POSTGRES (M23 PR4a).
   *
   * The doubles in `contacts.service.spec.ts` prove the decision; this proves
   * the DATABASE half, which is where the defect actually lived. Before this
   * PR an executor's `on_death_verified` designation resolved to nothing on
   * `effectiveContactReadGrants` — the query filters
   * `effective_condition = 'immediate'` and carried a freeze predicate over
   * exactly the case states an executor administers. That is real SQL against
   * real rows, and no in-memory roles double could have shown it.
   */
  describe('the estate’s contacts, for a verified executor', () => {
    it('refuses on the GRANT path even with the rung open — two arms, no overlap', async () => {
      /*
       * THE ANTI-VACUITY CONTROL for everything below, and the property the
       * two-arm design exists for: opening the ladder must not thaw the grant
       * query. `STRANGER` holds no grant, and the cross-owner ABAC route
       * refuses them whatever settlement would say — because that route never
       * asks settlement at all.
       */
      stageAuthority.allowed = true;
      const viaGrantPath = await request(server)
        .get(`/v1/profiles/${OWNER}/contacts`)
        .set('authorization', asUser(STRANGER));
      expect(viaGrantPath.status).toBe(403);
      expect(stageAuthority.calls).toEqual([]);
    });

    it('refuses the estate route while the rung is shut', async () => {
      stageAuthority.allowed = false;
      const refused = await request(server)
        .get(`/v1/estates/${OWNER}/contacts`)
        .set('authorization', asUser(STRANGER));
      expect(refused.status).toBe(403);
      expect(refused.body).toEqual({ error: 'forbidden' });
    });

    it('returns the estate’s real contacts once the DOCUMENTS rung is approved', async () => {
      stageAuthority.allowed = true;
      stageAuthority.calls = [];
      const opened = await request(server)
        .get(`/v1/estates/${OWNER}/contacts`)
        .set('authorization', asUser(STRANGER));
      expect(opened.status).toBe(200);
      /*
       * THE ROWS ARE REAL, and the count is the anti-vacuity floor: this suite
       * seeded three contacts for OWNER, so a route that silently returned an
       * empty list — the shape a still-frozen query would produce — cannot pass.
       */
      const rows = opened.body as Array<{ name: string; ownerUserId: string }>;
      expect(rows).toHaveLength(3);
      expect(rows.every((r) => r.ownerUserId === OWNER)).toBe(true);
      // THE RUNG IS ASSERTED. "Gated on a stage" and "gated on the DOCUMENTS
      // stage" are different claims, and only the second is docs/03 §5.1's.
      expect(stageAuthority.calls).toEqual(['documents']);
    });

    it('audits the disclosure, naming the case and no contact', async () => {
      stageAuthority.allowed = true;
      await request(server)
        .get(`/v1/estates/${OWNER}/contacts`)
        .set('authorization', asUser(STRANGER));
      const viewed = producer.messages
        .filter((m) => m.topic === TOPICS.auditEvents)
        .map((m) => JSON.parse(m.value) as { action: string; detail?: unknown })
        .filter((e) => e.action === 'contact.estate.viewed');
      expect(viewed.length).toBeGreaterThan(0);
      expect(viewed.at(-1)?.detail).toMatchObject({
        caseId: '00000000-0000-4000-8000-0000000000ca',
        count: '3',
      });
      // Entity ids, enums and counts only — never the names it disclosed.
      expect(JSON.stringify(viewed)).not.toContain('Named Contact');
    });
  });

  it('refuses a permission grant nothing honours, storing nothing', async () => {
    // Until this landed the route took any lowercase token as a resource, wrote
    // the row, listed it back as an allowance and audited `permission.granted`,
    // while `effectiveContactReadGrants` — the only reader — filters
    // `contact`/`read` and ignored the rest. TWO CASES IN THIS SUITE USED THOSE
    // INERT PAIRS AS FIXTURES (`document`/`read` and `asset`/`read`) and passed,
    // which is how a promise with no enforcement behind it survives a test run.
    const before = await admin.query(`SELECT count(*)::int AS n FROM ${schema}.permission_grants`);

    for (const body of [
      { resource: 'asset', action: 'read' },
      { resource: 'document', action: 'read' },
      // The PAIR is the unit: both tokens appear in the one enforced pair.
      { resource: 'contact', action: 'download' },
      { resource: 'anything_at_all', action: 'read' },
    ]) {
      const refused = await request(server)
        .post(`/v1/role-assignments/${roleAssignmentId}/permissions`)
        .set('authorization', asElevated(OWNER))
        .send(body);
      // Its own status and token — a client that drifts ahead of the platform
      // must be able to tell "not implemented" from "malformed" (M9).
      expect(refused.status).toBe(422);
      expect(refused.body).toEqual({ error: 'grant_not_enforced' });
    }

    // Nothing reached the table. A refusal that still writes an inert row would
    // be the finding with an error message on top.
    const after = await admin.query(`SELECT count(*)::int AS n FROM ${schema}.permission_grants`);
    expect((after.rows[0] as { n: number }).n).toBe((before.rows[0] as { n: number }).n);
  });

  it('an owner can read and withdraw a permission grant (M13 PR1)', async () => {
    // On a SECOND assignment, so withdrawing leaves the §5.5 fixture above
    // intact. It used to be a second grant on the same assignment — which is no
    // longer expressible, there being exactly one enforced pair and migration
    // 005's unique index being per (assignment, resource, action).
    const second = await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asElevated(OWNER))
      .send({ contactId: linkedContactId, role: 'viewer', scopeType: 'estate' });
    expect(second.status).toBe(201);
    const secondRaId = (second.body as { id: string }).id;

    const extra = await request(server)
      .post(`/v1/role-assignments/${secondRaId}/permissions`)
      .set('authorization', asElevated(OWNER))
      .send({ resource: 'contact', action: 'read' });
    expect(extra.status).toBe(201);
    const extraId = (extra.body as { id: string }).id;

    const list = await request(server)
      .get(`/v1/role-assignments/${secondRaId}/permissions`)
      .set('authorization', asUser(OWNER));
    expect(list.status).toBe(200);
    expect((list.body as Array<{ resource: string }>).map((g) => g.resource)).toEqual(['contact']);

    // Withdrawal needs NO step-up: the protective act must never be harder than
    // the permissive one (the M6 rule).
    const del = await request(server)
      .delete(`/v1/role-assignments/${secondRaId}/permissions/${extraId}`)
      .set('authorization', asUser(OWNER));
    expect(del.status).toBe(204);

    const again = await request(server)
      .delete(`/v1/role-assignments/${secondRaId}/permissions/${extraId}`)
      .set('authorization', asUser(OWNER));
    expect(again.status).toBe(404);

    const after = await request(server)
      .get(`/v1/role-assignments/${secondRaId}/permissions`)
      .set('authorization', asUser(OWNER));
    expect((after.body as unknown[]).length).toBe(0);
    // ...and the §5.5 fixture on the first assignment is untouched.
    const original = await request(server)
      .get(`/v1/role-assignments/${roleAssignmentId}/permissions`)
      .set('authorization', asUser(OWNER));
    expect((original.body as Array<{ resource: string }>).map((g) => g.resource)).toEqual([
      'contact',
    ]);
    // revoked_at is the history — the row survives (no soft delete on this table).
    const { rows } = await admin.query(
      `SELECT revoked_at FROM ${schema}.permission_grants WHERE id = $1`,
      [extraId],
    );
    expect((rows[0] as { revoked_at: Date | null }).revoked_at).not.toBeNull();
  });

  it('a grant cannot be revoked through a DIFFERENT assignment (real SQL scoping)', async () => {
    // `role_assignment_id` is in the revoke predicate because it is the only
    // thing tying a grant row to an owner. A second assignment of the SAME owner
    // is the sharpest case: the owner check passes, so only the SQL stands
    // between a grant id and the wrong parent.
    const second = await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asElevated(OWNER))
      .send({ contactId: namedId, role: 'viewer', scopeType: 'estate' });
    const secondRaId = (second.body as { id: string }).id;
    const grant = await request(server)
      .post(`/v1/role-assignments/${secondRaId}/permissions`)
      .set('authorization', asElevated(OWNER))
      // `contact`/`read` because it is now the only pair the platform accepts;
      // this case is about the revoke predicate's scoping, not the vocabulary.
      .send({ resource: 'contact', action: 'read' });
    const grantId = (grant.body as { id: string }).id;

    const wrongParent = await request(server)
      .delete(`/v1/role-assignments/${roleAssignmentId}/permissions/${grantId}`)
      .set('authorization', asUser(OWNER));
    expect(wrongParent.status).toBe(404);

    // Still live under its real parent.
    const list = await request(server)
      .get(`/v1/role-assignments/${secondRaId}/permissions`)
      .set('authorization', asUser(OWNER));
    expect((list.body as Array<{ id: string }>).map((g) => g.id)).toEqual([grantId]);
  });

  it('refuses to delete a contact a live role assignment names (M13 PR1)', async () => {
    // linkedContactId carries the beneficiary assignment granted above. Deleting
    // it would silently un-resolve every query that joins `deleted_at IS NULL`.
    const refused = await request(server)
      .delete(`/v1/contacts/${linkedContactId}`)
      .set('authorization', asUser(OWNER));
    expect(refused.status).toBe(409);
    expect(refused.body).toEqual({ error: 'contact_in_use' });

    // SERIALIZED, not merely re-checked: both paths take `FOR UPDATE` on the
    // contact row. The review found the previous version still racy — a
    // `WHERE NOT EXISTS` over role_assignments locks the CONTACTS row, not the
    // assignments it reads, and grantRole was itself check-then-act.
    const raced = await request(server)
      .post('/v1/contacts')
      .set('authorization', asUser(OWNER))
      .send({ name: 'Raced Contact' });
    const racedId = (raced.body as { id: string }).id;
    const racedRole = await request(server)
      .post('/v1/role-assignments')
      .set('authorization', asElevated(OWNER))
      .send({ contactId: racedId, role: 'trustee', scopeType: 'estate' });
    expect(racedRole.status).toBe(201);
    const blocked = await request(server)
      .delete(`/v1/contacts/${racedId}`)
      .set('authorization', asUser(OWNER));
    expect(blocked.status).toBe(409);
    // ...and the contact is untouched, so no query silently loses its designation.
    const { rows: stillThere } = await admin.query(
      `SELECT deleted_at FROM ${schema}.contacts WHERE id = $1`,
      [racedId],
    );
    expect((stillThere[0] as { deleted_at: Date | null }).deleted_at).toBeNull();

    // THE RACE ITSELF, fired concurrently. Whichever wins, the invariant holds:
    // never a live designation on a deleted contact. Before the lock, this
    // interleaving produced exactly that — the docs/03 §6f fail-open.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const victim = await request(server)
        .post('/v1/contacts')
        .set('authorization', asUser(OWNER))
        .send({ name: `Race Victim ${attempt}` });
      const victimId = (victim.body as { id: string }).id;
      await Promise.all([
        request(server)
          .post('/v1/role-assignments')
          .set('authorization', asElevated(OWNER))
          .send({ contactId: victimId, role: 'guardian', scopeType: 'estate' }),
        request(server).delete(`/v1/contacts/${victimId}`).set('authorization', asUser(OWNER)),
      ]);
      const { rows } = await admin.query(
        `SELECT c.deleted_at IS NOT NULL AS contact_gone,
                EXISTS (SELECT 1 FROM ${schema}.role_assignments ra
                         WHERE ra.contact_id = c.id AND ra.deleted_at IS NULL) AS has_live_role
           FROM ${schema}.contacts c WHERE c.id = $1`,
        [victimId],
      );
      const state = rows[0] as { contact_gone: boolean; has_live_role: boolean };
      // The forbidden combination: a designation nothing can resolve, still
      // listed, never revoked.
      expect(state.contact_gone && state.has_live_role).toBe(false);
    }

    // An unencumbered contact still deletes normally.
    const spare = await request(server)
      .post('/v1/contacts')
      .set('authorization', asUser(OWNER))
      .send({ name: 'Spare Contact' });
    const spareId = (spare.body as { id: string }).id;
    const ok = await request(server)
      .delete(`/v1/contacts/${spareId}`)
      .set('authorization', asUser(OWNER));
    expect(ok.status).toBe(204);
  });

  it('a profile edit does not destroy the SSN it never received (M13 PR1)', async () => {
    const { rows: before } = await admin.query(
      `SELECT ssn_ct, ssn_last4_ct FROM ${schema}.profiles WHERE user_id = $1`,
      [OWNER],
    );
    const ssnCtBefore = (before[0] as { ssn_ct: Buffer }).ssn_ct;
    expect(ssnCtBefore).not.toBeNull();

    // What an edit form sends: the one field being changed, plus the required name.
    // `GET /v1/profile` never returns `ssn`, so no client can echo it back.
    const put = await request(server)
      .put('/v1/profile')
      .set('authorization', asUser(OWNER))
      .send({ legalName: LEGAL_NAME, stateOfResidence: 'AZ' });
    expect(put.status).toBe(200);

    const { rows: after } = await admin.query(
      `SELECT ssn_ct, ssn_last4_ct, state_of_residence, marital_status
         FROM ${schema}.profiles WHERE user_id = $1`,
      [OWNER],
    );
    const row = after[0] as {
      ssn_ct: Buffer;
      ssn_last4_ct: Buffer;
      state_of_residence: string;
      marital_status: string;
    };
    expect(row.state_of_residence).toBe('AZ');
    expect(row.ssn_ct).toEqual(ssnCtBefore); // carried as bytes, never re-encrypted
    expect(row.ssn_last4_ct).not.toBeNull();
    expect(row.marital_status).toBe('married'); // set by the first test, untouched
    expect(
      (await request(server).get('/v1/profile').set('authorization', asUser(OWNER))).body,
    ).toMatchObject({ ssnLast4: '6789', stateOfResidence: 'AZ' });
  });

  describe('the contact link ceremony (M13 PR3)', () => {
    let inviteeId: string;
    let code: string;

    it('mints a code under step-up, and refuses without one', async () => {
      const contact = await request(server)
        .post('/v1/contacts')
        .set('authorization', asUser(OWNER))
        .send({ name: 'Invitee Person' });
      inviteeId = (contact.body as { id: string }).id;

      // Minting hands out a capability whose endpoint is an authorization edge
      // on the docs/03 §5.1 chain, so it is gated like naming a fiduciary.
      const refused = await request(server)
        .post(`/v1/contacts/${inviteeId}/link-invitation`)
        .set('authorization', asUser(OWNER));
      expect(refused.status).toBe(403);
      expect(refused.body).toEqual({ error: 'stepup_required' });

      const minted = await request(server)
        .post(`/v1/contacts/${inviteeId}/link-invitation`)
        .set('authorization', asElevated(OWNER));
      expect(minted.status).toBe(201);
      code = (minted.body as { code: string }).code;
      expect(code).toMatch(/^ESL1-/);

      // ONLY THE HASH IS STORED. A database read — the docs/03 §5.3 insider, a
      // leaked backup — must not yield a usable capability.
      const { rows } = await admin.query(
        `SELECT code_sha256, expires_at > now() AS live FROM ${schema}.contact_link_invitations
          WHERE contact_id = $1`,
        [inviteeId],
      );
      const row = rows[0] as { code_sha256: Buffer; live: boolean };
      expect(row.live).toBe(true);
      expect(row.code_sha256.toString('utf8')).not.toContain(code);
      // The CANONICAL form is hashed, so a code retyped in lowercase or without
      // its grouping dashes still redeems (the alphabet exists to be read aloud).
      // Using the real function rather than re-deriving it: a second copy of a
      // hashing rule is a copy that drifts.
      expect(row.code_sha256).toEqual(
        createHash('sha256').update(canonicalCode(code), 'utf8').digest(),
      );
    });

    it('refuses every bad code with the SAME answer, and counts the attempt', async () => {
      const wrong = await request(server)
        .post('/v1/contact-links/redeem')
        .set('authorization', asUser(GRANTEE))
        .send({ code: 'ESL1-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000' });
      expect(wrong.status).toBe(400);
      expect(wrong.body).toEqual({ error: 'invalid_code' });

      // The OWNER cannot redeem their own invitation: they would become their
      // own linked contact and so eligible to report their own death.
      const selfDirected = await request(server)
        .post('/v1/contact-links/redeem')
        .set('authorization', asUser(OWNER))
        .send({ code });
      expect(selfDirected.status).toBe(400);
      // Byte-identical to the unknown-code answer, so a refusal never reveals
      // that the code was real.
      expect(selfDirected.body).toEqual(wrong.body);

      // ...but the attempt against a REAL invitation is counted.
      const { rows } = await admin.query(
        `SELECT attempts FROM ${schema}.contact_link_invitations WHERE contact_id = $1`,
        [inviteeId],
      );
      expect((rows[0] as { attempts: number }).attempts).toBe(1);
    });

    it('links the redeemer, spends the code, and says nothing about the estate', async () => {
      const redeemed = await request(server)
        .post('/v1/contact-links/redeem')
        .set('authorization', asUser(STRANGER))
        // Retyped the way a person would: lowercase, dashes dropped. The
        // alphabet is chosen for being read aloud, so redemption folds to the
        // canonical form rather than refusing.
        .send({ code: code.toLowerCase().replace(/-/g, '') });
      expect(redeemed.status).toBe(200);
      // NOTHING about the estate comes back — not the owner, not the contact.
      expect(redeemed.body).toEqual({ status: 'ok' });

      const { rows } = await admin.query(
        `SELECT c.linked_user_id, i.redeemed_by, i.redeemed_at IS NOT NULL AS spent
           FROM ${schema}.contacts c
           JOIN ${schema}.contact_link_invitations i ON i.contact_id = c.id
          WHERE c.id = $1`,
        [inviteeId],
      );
      expect(rows[0]).toMatchObject({
        linked_user_id: STRANGER,
        redeemed_by: STRANGER,
        spent: true,
      });

      // The list now says the contact has an account, which is what decides
      // whether any designation on them can be exercised.
      const list = await request(server).get('/v1/contacts').set('authorization', asUser(OWNER));
      expect(
        (list.body as Array<{ id: string; linked: boolean }>).find((c) => c.id === inviteeId),
      ).toMatchObject({ linked: true });
    });

    /**
     * THE REVERSE-LINK READ AGAINST A REAL DATABASE (M22 PR4a).
     *
     * The service spec drives this through doubles, which cannot test the part
     * most likely to be wrong: the SQL. Two LEFT JOINs, a GROUP BY across four
     * columns and an `array_remove(array_agg(...))` all have to be right for
     * this to answer at all, and a query that silently returns nothing looks
     * exactly like an account with no links.
     */
    it('tells the redeemer whose estate now names them, by name', async () => {
      const estates = await request(server)
        .get('/v1/contact-links/estates')
        .set('authorization', asUser(STRANGER));
      expect(estates.status).toBe(200);
      expect(estates.body).toEqual([
        {
          ownerUserId: OWNER,
          contactId: inviteeId,
          // Decrypted from the OWNER's profile under the OWNER's key, for a
          // CALLER who is not its owner — the disclosure this PR exists to
          // make, proven end to end rather than asserted against a stub.
          ownerName: LEGAL_NAME,
          roles: [],
        },
      ]);
    });

    it('aggregates every role the caller holds in that estate', async () => {
      // GRANTEE was linked earlier in this spec and carries two roles, so this
      // is what proves the array_agg/array_remove half of the query — the row
      // above has none, and a GROUP BY that collapsed or duplicated rows would
      // look identical there.
      const held = await request(server)
        .get('/v1/contact-links/estates')
        .set('authorization', asUser(GRANTEE));
      expect(held.status).toBe(200);
      const [estate] = held.body as Array<{ ownerUserId: string; roles: string[] }>;
      expect(estate?.ownerUserId).toBe(OWNER);
      expect([...(estate?.roles ?? [])].sort()).toEqual(['beneficiary', 'viewer']);
      // ONE row, not one per role — the GROUP BY is doing its job.
      expect(held.body).toHaveLength(1);
    });

    it('says nothing to somebody no estate names', async () => {
      // Anti-vacuity for the two tests above: the route must be capable of an
      // empty answer, or "it returned rows" proves nothing about the WHERE
      // clause. A freshly-minted id is linked to nobody by construction.
      const none = await request(server)
        .get('/v1/contact-links/estates')
        .set('authorization', asUser(randomUUID()));
      expect(none.status).toBe(200);
      expect(none.body).toEqual([]);
    });

    it('is ONE-SHOT: the same code cannot be used twice', async () => {
      const replay = await request(server)
        .post('/v1/contact-links/redeem')
        .set('authorization', asUser(GRANTEE))
        .send({ code });
      expect(replay.status).toBe(400);
      expect(replay.body).toEqual({ error: 'invalid_code' });
    });

    it('refuses to invite a contact that is already linked', async () => {
      const again = await request(server)
        .post(`/v1/contacts/${inviteeId}/link-invitation`)
        .set('authorization', asElevated(OWNER));
      expect(again.status).toBe(409);
      expect(again.body).toEqual({ error: 'already_linked' });
    });

    it('unlinks WITHOUT a step-up — the protective direction stays easy', async () => {
      const removed = await request(server)
        .delete(`/v1/contacts/${inviteeId}/link`)
        .set('authorization', asUser(OWNER));
      expect(removed.status).toBe(204);
      const { rows } = await admin.query(
        `SELECT linked_user_id FROM ${schema}.contacts WHERE id = $1`,
        [inviteeId],
      );
      expect((rows[0] as { linked_user_id: string | null }).linked_user_id).toBeNull();
      // Idempotent-free: nothing to remove is a not-found, not a silent success.
      expect(
        (
          await request(server)
            .delete(`/v1/contacts/${inviteeId}/link`)
            .set('authorization', asUser(OWNER))
        ).status,
      ).toBe(404);

      /*
       * AND THE DISCLOSURE ENDS WITH IT (M22 PR4a). This is the assertion the
       * whole proportionality argument for reading another user's legal name
       * rests on: the owner can stop it, from their side, with one ungated
       * click. If unlinking left the estate readable, the decision recorded in
       * docs/06 would be wrong and this is what would say so.
       */
      const afterUnlink = await request(server)
        .get('/v1/contact-links/estates')
        .set('authorization', asUser(STRANGER));
      expect(afterUnlink.status).toBe(200);
      expect(afterUnlink.body).toEqual([]);
    });

    it('re-issuing retires the previous code rather than refusing', async () => {
      const first = await request(server)
        .post(`/v1/contacts/${inviteeId}/link-invitation`)
        .set('authorization', asElevated(OWNER));
      const firstCode = (first.body as { code: string }).code;
      const second = await request(server)
        .post(`/v1/contacts/${inviteeId}/link-invitation`)
        .set('authorization', asElevated(OWNER));
      expect(second.status).toBe(201);

      // The owner was told the first code once and may have lost it; the
      // partial unique index would otherwise make re-issuing an error.
      const stale = await request(server)
        .post('/v1/contact-links/redeem')
        .set('authorization', asUser(GRANTEE))
        .send({ code: firstCode });
      expect(stale.status).toBe(400);

      // And withdrawing the live one needs no step-up either.
      expect(
        (
          await request(server)
            .delete(`/v1/contacts/${inviteeId}/link-invitation`)
            .set('authorization', asUser(OWNER))
        ).status,
      ).toBe(204);
    });

    it('a stranger cannot invite on someone else’s contact', async () => {
      const foreign = await request(server)
        .post(`/v1/contacts/${inviteeId}/link-invitation`)
        .set('authorization', asElevated(STRANGER));
      // The owner cross-check turns a foreign id into a uniform not-found.
      expect(foreign.status).toBe(404);
    });
  });

  it('concurrent first-writes cannot mint two active DEKs (unique index + adoption)', async () => {
    const newUser = randomUUID();
    const results = await Promise.all(
      [1, 2, 3, 4].map((i) =>
        request(server)
          .post('/v1/contacts')
          .set('authorization', asUser(newUser))
          .send({ name: `Race Contact ${i}` }),
      ),
    );
    for (const res of results) {
      expect(res.status).toBe(201);
    }
    const { rows } = await admin.query(
      `SELECT count(*)::int AS n FROM ${schema}.deks WHERE user_id = $1 AND destroyed_at IS NULL`,
      [newUser],
    );
    expect((rows[0] as { n: number }).n).toBe(1);
  });

  it('translates a duplicate active-DEK insert to DekConflictError (23505)', async () => {
    const repo = app.get(PgDekRepository);
    const userId = randomUUID();
    const record = {
      userId,
      kekAlias: 'local',
      wrappedKey: randomBytes(32),
      createdAt: new Date(),
      destroyedAt: null,
    };
    await repo.insert({ ...record, dekId: randomUUID() });
    await expect(repo.insert({ ...record, dekId: randomUUID() })).rejects.toBeInstanceOf(
      DekConflictError,
    );
  });

  it('emitted the required audit actions and never leaked PII on the wire', () => {
    const auditActions = producer.messages
      .filter((m) => m.topic === TOPICS.auditEvents)
      .map((m) => (JSON.parse(m.value) as { action: string }).action);
    expect(auditActions).toEqual(
      expect.arrayContaining([
        'profile.updated',
        'contact.created',
        'contact.updated',
        'role.granted',
        'permission.granted',
        'permission.revoked',
        'contact.link.invited',
        'contact.link.claimed',
        'contact.link.invitation_revoked',
        'contact.link.removed',
        'crypto.field.decrypted', // every read decrypts through FieldCrypto
      ]),
    );
    // PII firewall: no plaintext name/legal-name on any emitted message.
    for (const message of producer.messages) {
      expect(message.value).not.toContain(LEGAL_NAME);
      expect(message.value).not.toContain(NAMED_CONTACT);
      expect(message.value).not.toContain(OTHER_CONTACT);
    }
  });

  it('no version capture in this schema keeps a blind index (M25 PR1)', async () => {
    // Asks the DATABASE what function it is running, not what the migration
    // says — a redaction written and never applied, or superseded by a later
    // CREATE OR REPLACE that lost it, is invisible to a text scan. The static
    // half is `packages/contracts/test/version-capture-redaction.spec.ts`.
    //
    // THE CORPUS IS ASSERTED FIRST, because an empty corpus and a clean one
    // produce the same empty gap list. `contacts` carries the blind index this
    // milestone is about.
    const corpus = await blindIndexCaptureCorpus(admin, schema);
    expect([...corpus.keys()]).toContain('contacts');
    expect(await blindIndexCaptureGaps(admin, schema)).toEqual([]);
  });

  it('the migrated core schema satisfies the docs/02 conventions (checkConventions)', async () => {
    const violations = await checkConventions(
      { query: (text: string, values?: unknown[]) => admin.query(text, values) },
      {
        schema,
        businessTables: ['family_members', 'contacts', 'role_assignments'],
        appendOnlyTables: [
          'profiles_versions',
          'family_members_versions',
          'contacts_versions',
          'role_assignments_versions',
        ],
      },
    );
    expect(violations).toEqual([]);
  });
});
