import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import type {
  AccessStage,
  SettlementStageAuthority,
  StageAccessAuthority,
} from '@estate/settlement-client';
import { FieldCrypto, LocalKmsProvider, type DekRecord, type DekRepository } from '@estate/crypto';
import { ProfileAuthz } from '../src/authz.service';
import type { ProfileConfig } from '../src/config';
import { ContactsService } from '../src/contacts.service';
import type { ContactFields, ContactInsert, ContactRow } from '../src/contacts.repo';
import { FieldCipher } from '../src/field-cipher';
import type { EffectiveGrant } from '../src/roles.repo';

const OWNER = 'a1111111-1111-4111-8111-111111111111';
const GRANTEE = 'b2222222-2222-4222-8222-222222222222';
const STRANGER = 'c3333333-3333-4333-8333-333333333333';

/** In-memory DekRepository for the real FieldCrypto (no Postgres needed). */
class MemoryDeks implements DekRepository {
  private readonly rows = new Map<string, DekRecord>();
  findActiveByUser(userId: string): Promise<DekRecord | null> {
    for (const r of this.rows.values()) {
      if (r.userId === userId && r.destroyedAt === null) return Promise.resolve(r);
    }
    return Promise.resolve(null);
  }
  findById(dekId: string): Promise<DekRecord | null> {
    return Promise.resolve(this.rows.get(dekId) ?? null);
  }
  insert(record: DekRecord): Promise<void> {
    this.rows.set(record.dekId, record);
    return Promise.resolve();
  }
  markDestroyed(dekId: string, at: Date): Promise<void> {
    const r = this.rows.get(dekId);
    if (r) this.rows.set(dekId, { ...r, destroyedAt: at });
    return Promise.resolve();
  }
}

/**
 * In-memory contacts repo, faithful to the real one in the one respect this
 * suite turns on: `update` applies only the `ContactFields` it is handed, so a
 * service that stopped sending `linked_user_id` (or started sending it as null)
 * shows up here exactly as it would in Postgres.
 */
class FakeContactsRepo {
  readonly rows: ContactRow[] = [];
  private seq = 0;
  insert(row: ContactInsert): Promise<string> {
    const id = `f0000000-0000-4000-8000-00000000000${++this.seq}`;
    this.rows.push({ ...row, id, linked_user_id: null });
    return Promise.resolve(id);
  }
  findById(id: string): Promise<ContactRow | null> {
    return Promise.resolve(this.rows.find((r) => r.id === id) ?? null);
  }
  listByOwner(ownerUserId: string): Promise<ContactRow[]> {
    return Promise.resolve(this.rows.filter((r) => r.owner_user_id === ownerUserId));
  }
  update(id: string, ownerUserId: string, fields: ContactFields): Promise<boolean> {
    const i = this.rows.findIndex((r) => r.id === id && r.owner_user_id === ownerUserId);
    if (i < 0) return Promise.resolve(false);
    this.rows[i] = { ...(this.rows[i] as ContactRow), ...fields };
    return Promise.resolve(true);
  }
  /**
   * Faithful to the real one since the M13 review: the in-use predicate lives in
   * the UPDATE's own WHERE, so this fake evaluates it here rather than letting
   * the service check separately — a fake that split them would let the
   * check-then-act defect back in unnoticed.
   */
  /** The link a real redemption writes; no ordinary write path sets it. */
  link(id: string, userId: string): void {
    const i = this.rows.findIndex((r) => r.id === id);
    this.rows[i] = { ...(this.rows[i] as ContactRow), linked_user_id: userId };
  }
  assignedContactIds = new Set<string>();
  softDelete(id: string, ownerUserId: string): Promise<'deleted' | 'in_use' | 'not_found'> {
    // ownerUserId is honoured because in the real repo it is the ONLY access
    // control on this path — the service's PEP call cannot see whose contact an
    // id names. A fake that ignored it left that check unmodelled and untested.
    const i = this.rows.findIndex((r) => r.id === id && r.owner_user_id === ownerUserId);
    if (i < 0) return Promise.resolve('not_found');
    if (this.assignedContactIds.has(id)) return Promise.resolve('in_use');
    this.rows.splice(i, 1);
    return Promise.resolve('deleted');
  }
}

/** Fake roles repo returning pre-configured effective grants for GRANTEE only. */
class FakeRolesRepo {
  grants: EffectiveGrant[] = [];
  effectiveContactReadGrants(
    _owner: string,
    caller: string,
    _now: Date,
  ): Promise<EffectiveGrant[]> {
    return Promise.resolve(caller === GRANTEE ? this.grants : []);
  }
}

class FakeEvents {
  readonly created: string[] = [];
  /** Every emission in order — the estate read asserts WHEN, not just whether. */
  readonly order: string[] = [];
  readonly estateViews: Array<{
    actor: string;
    owner: string;
    caseId: string | null;
    count: number;
  }> = [];
  contactCreated(_actor: string, id: string): Promise<void> {
    this.created.push(id);
    this.order.push('contact.created');
    return Promise.resolve();
  }
  contactEstateViewed(
    actor: string,
    owner: string,
    detail: { caseId: string | null; count: number },
  ): Promise<void> {
    this.order.push('contact.estate.viewed');
    this.estateViews.push({ actor, owner, ...detail });
    return Promise.resolve();
  }
  contactUpdated(): Promise<void> {
    return Promise.resolve();
  }
  contactDeleted(): Promise<void> {
    return Promise.resolve();
  }
}

function build() {
  const deks = new MemoryDeks();
  const crypto = new FieldCrypto(LocalKmsProvider.generate(), deks, () => undefined, {
    kekAlias: 'core/kek',
  });
  // Every decrypt is one audited `crypto.field.decrypted`; recording the AAD
  // field lets a test assert how many a route spends (docs/03 §6f).
  const decrypted: string[] = [];
  const cipher = new FieldCipher(crypto);
  const realDecrypt = cipher.decrypt.bind(cipher);
  cipher.decrypt = (input): Promise<string | null> => {
    decrypted.push(input.field);
    return realDecrypt(input);
  };
  const repo = new FakeContactsRepo();
  const roles = new FakeRolesRepo();
  const events = new FakeEvents();
  const authz = new ProfileAuthz(new PolicyDecisionPoint(loadBundledPolicies()));
  const config = { emailIndexKey: Buffer.alloc(32, 7) } as unknown as ProfileConfig;
  const settlement = new FakeStageAuthority();
  const service = new ContactsService(
    repo as never,
    roles as never,
    cipher,
    authz,
    events as never,
    settlement,
    config,
    () => new Date(),
  );
  return { service, repo, roles, events, decrypted, authz, settlement };
}

/**
 * SETTLEMENT'S STAGED-ACCESS ANSWER, doubled.
 *
 * FAITHFUL ABOUT WHAT IT REFUSES, not only about what it grants: the real
 * `HttpSettlementAuthority` answers `{allowed:false, caseId:null}` for a
 * network failure, a non-2xx and an unparseable body alike, so the double
 * defaults to REFUSING and a test must open it deliberately. A double that
 * defaulted to `allowed` would make every "the executor is refused" assertion
 * in this file pass for the wrong reason.
 *
 * It also RECORDS THE STAGE it was asked about, because "gated on a stage" and
 * "gated on the DOCUMENTS stage" are different claims and only one of them is
 * the decision docs/03 §5.1 records.
 */
class FakeStageAuthority implements SettlementStageAuthority {
  allowed = false;
  caseId = 'case-1';
  calls: Array<{ bearerToken: string; ownerUserId: string; stage: string }> = [];

  checkStageAccess(input: {
    bearerToken: string;
    ownerUserId: string;
    stage: AccessStage;
  }): Promise<StageAccessAuthority> {
    this.calls.push({ ...input });
    return Promise.resolve(
      this.allowed ? { allowed: true, caseId: this.caseId } : { allowed: false, caseId: null },
    );
  }
}

describe('ContactsService ABAC boundary (docs/03 §5.5)', () => {
  it('owner creates, lists, and reads their own contacts (encrypted at rest, decrypted on read)', async () => {
    const { service, repo, events } = build();
    const a = await service.create(OWNER, { name: 'Alice Attorney', email: 'alice@law.example' });
    await service.create(OWNER, { name: 'Bob Banker' });

    // Ciphertext at rest never contains the plaintext name.
    const stored = repo.rows.find((r) => r.id === a.id) as ContactRow;
    expect(stored.name_ct.toString('utf8')).not.toContain('Alice');
    expect(events.created).toContain(a.id);

    const list = await service.listForOwner(OWNER, OWNER);
    expect(list.map((c) => c.name).sort()).toEqual(['Alice Attorney', 'Bob Banker']);

    const one = await service.getOne(OWNER, OWNER, a.id);
    expect(one.name).toBe('Alice Attorney');
    expect(one.email).toBe('alice@law.example');
  });

  it('a grant-holder reads ONLY the named contact; a non-named one is denied', async () => {
    const { service, roles } = build();
    const a = await service.create(OWNER, { name: 'Named Contact' });
    const b = await service.create(OWNER, { name: 'Other Contact' });

    // GRANTEE is granted a scope naming contact A only.
    roles.grants = [{ scope_type: 'asset', scope_id: a.id }];

    const named = await service.getOne(GRANTEE, OWNER, a.id);
    expect(named.name).toBe('Named Contact');

    await expect(service.getOne(GRANTEE, OWNER, b.id)).rejects.toBeInstanceOf(ForbiddenException);

    // The list is filtered to only the named contact — no enumeration of others.
    const list = await service.listForOwner(GRANTEE, OWNER);
    expect(list.map((c) => c.id)).toEqual([a.id]);
  });

  it('the LIST decrypts one field per row, the detail read decrypts all of them', async () => {
    // docs/03 §6f / M12's audited-decrypt-volume rule. A twenty-contact page
    // must not spend a hundred decrypt events on the owner's own trail.
    const { service, decrypted } = build();
    await service.create(OWNER, {
      name: 'Alice Attorney',
      email: 'alice@law.example',
      phone: '555-0100',
      address: '1 Main St',
      notes: 'lead counsel',
    });

    decrypted.length = 0;
    const list = await service.listForOwner(OWNER, OWNER);
    expect(decrypted).toEqual(['contact.name']);
    expect(list[0]).toMatchObject({
      name: 'Alice Attorney',
      hasEmail: true,
      hasPhone: true,
      hasAddress: true,
      hasNotes: true,
      linked: false,
    });
    // M15 PR3 deliberately did NOT add the linked ACCOUNT id here: it lives on
    // the dedicated grantee-candidates projection instead, so the disclosure
    // surface of every existing profile client is unchanged.
    expect(Object.keys(list[0] as object)).not.toContain('linkedUserId');
    // The summary has no field for the values themselves.
    expect(Object.keys(list[0] as object)).not.toContain('email');

    decrypted.length = 0;
    const one = await service.getOne(OWNER, OWNER, (list[0] as { id: string }).id);
    expect(decrypted.sort()).toEqual([
      'contact.address',
      'contact.email',
      'contact.name',
      'contact.notes',
      'contact.phone',
    ]);
    expect(one.email).toBe('alice@law.example');
  });

  it('an estate-wide grant exposes all contacts; a stranger gets nothing', async () => {
    const { service, roles } = build();
    await service.create(OWNER, { name: 'One' });
    await service.create(OWNER, { name: 'Two' });

    roles.grants = [{ scope_type: 'estate', scope_id: null }];
    const all = await service.listForOwner(GRANTEE, OWNER);
    expect(all).toHaveLength(2);

    // Stranger: no grant at all → collection read is a generic 403.
    await expect(service.listForOwner(STRANGER, OWNER)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('a stranger cannot read a single contact (deny by default)', async () => {
    const { service } = build();
    const a = await service.create(OWNER, { name: 'Private' });
    await expect(service.getOne(STRANGER, OWNER, a.id)).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe('the contact link survives ordinary edits (M13 PR1)', () => {
  /**
   * The link is an authorization edge, not a profile field: it is what makes
   * someone able to open a death case (docs/03 §6b) and what makes an executor
   * resolvable (M7). `encryptRow` used to hardcode `linked_user_id: null` and
   * feed it to BOTH insert and update, and the UPDATE wrote the column — so
   * changing a phone number revoked a §5.1 control with no audit event.
   *
   * The type system now makes that unrepresentable (`ContactFields` has no such
   * key), which is why this test asserts the OUTCOME rather than the shape: a
   * future edit that reintroduces the column has to make this red.
   */
  it('an update leaves linked_user_id exactly as it was', async () => {
    const { service, repo } = build();
    const a = await service.create(OWNER, { name: 'Grantee Person', phone: '555-0100' });

    // Stand in for the link ceremony (PR3), which is the only writer of this
    // column — the four existing test files that set it in raw SQL say the same.
    const row = repo.rows.find((r) => r.id === a.id) as ContactRow;
    row.linked_user_id = GRANTEE;

    await service.update(OWNER, a.id, { name: 'Grantee Person', phone: '555-0199' });

    const after = repo.rows.find((r) => r.id === a.id) as ContactRow;
    expect(after.linked_user_id).toBe(GRANTEE);
    // ...and the edit itself still landed.
    const view = await service.getOne(OWNER, OWNER, a.id);
    expect(view.phone).toBe('555-0199');
  });

  it('refuses to delete another owner’s contact, as a uniform not-found', async () => {
    const { service, repo } = build();
    const a = await service.create(OWNER, { name: 'Owner’s Contact' });
    /*
     * NOT-FOUND, not forbidden, and the distinction is the control. `remove` is
     * caller-relative — the PEP models the resource owner AS the caller, so it
     * always permits and the repo's `owner_user_id` predicate is the entire access
     * check on this path. That is deliberate: a 403 would confirm the id names a
     * real contact belonging to somebody, turning delete into the enumeration
     * oracle the read paths are careful not to be. A fake repo that dropped
     * `ownerUserId` left this untested, which is how a repo edit could have
     * removed the predicate with every spec still green.
     */
    await expect(service.remove(STRANGER, a.id)).rejects.toBeInstanceOf(NotFoundException);
    expect(repo.rows.some((r) => r.id === a.id)).toBe(true);
  });

  it('refuses to delete a contact a live role assignment still names', async () => {
    const { service, repo } = build();
    const a = await service.create(OWNER, { name: 'Trustee Person' });
    repo.assignedContactIds.add(a.id);

    await expect(service.remove(OWNER, a.id)).rejects.toBeInstanceOf(ConflictException);
    // Nothing was deleted: retiring a fiduciary is its own step-up-gated act.
    expect(repo.rows.some((r) => r.id === a.id)).toBe(true);

    // Once the assignment is revoked, the contact deletes normally.
    repo.assignedContactIds.delete(a.id);
    await service.remove(OWNER, a.id);
    expect(repo.rows.some((r) => r.id === a.id)).toBe(false);
  });

  /**
   * THE ESTATE'S CONTACTS, FOR A VERIFIED EXECUTOR (M23 PR4a) — docs/03 §5.1
   * control 5, and the §5.4 control that says an executor dashboard shows
   * verified contact cards for the estate's attorney and CPA.
   *
   * The property this block exists for is that the decision is SETTLEMENT'S and
   * this service adds nothing to it. Before PR4a an executor could not read
   * these contacts at any point, ever: `effectiveContactReadGrants` resolves
   * only `effective_condition = 'immediate'`, which an `on_death_verified`
   * designation never satisfies, and carried a freeze predicate excluding
   * exactly the case states an executor administers. Control 4 was answering a
   * question that belongs to control 5, and answering it "no" forever.
   */
  describe('the estate’s contacts, for a verified executor', () => {
    const EXECUTOR = 'c3333333-3333-4333-8333-333333333333';

    async function estateWithTwoContacts(): Promise<ReturnType<typeof build>> {
      const h = build();
      await h.service.create(OWNER, { name: 'Ada Lovelace’s attorney' });
      await h.service.create(OWNER, { name: 'Ada Lovelace’s accountant' });
      // The fixture's own writes are not the thing under test — clearing both
      // ledgers means every count below is this call's, not the setup's.
      h.decrypted.length = 0;
      h.events.order.length = 0;
      return h;
    }

    it('asks settlement about the DOCUMENTS rung, on the caller’s own bearer', async () => {
      const { service, settlement } = await estateWithTwoContacts();
      settlement.allowed = true;
      await service.listEstateContacts(EXECUTOR, 'bearer-abc', OWNER);
      /*
       * THE STAGE IS ASSERTED, not just that a stage was asked about. "Gated on
       * a rung" and "gated on the DOCUMENTS rung" are different claims, and
       * only the second is the decision docs/03 §5.1 records — INVENTORY would
       * open a decedent's address book on the lightest approval on the ladder.
       */
      expect(settlement.calls).toEqual([
        { bearerToken: 'bearer-abc', ownerUserId: OWNER, stage: 'documents' },
      ]);
    });

    it('returns the estate’s contacts once the rung is approved', async () => {
      const { service, settlement } = await estateWithTwoContacts();
      settlement.allowed = true;
      const rows = await service.listEstateContacts(EXECUTOR, 'bearer-abc', OWNER);
      expect(rows.map((r) => r.name).sort()).toEqual([
        'Ada Lovelace’s accountant',
        'Ada Lovelace’s attorney',
      ]);
      // Every row names the DECEDENT as its owner — this is their address book,
      // not a merged view of the executor's own.
      expect(rows.every((r) => r.ownerUserId === OWNER)).toBe(true);
    });

    it('refuses when the rung is NOT approved, and reads nothing first', async () => {
      const { service, settlement, decrypted, events } = await estateWithTwoContacts();
      settlement.allowed = false;
      await expect(
        service.listEstateContacts(EXECUTOR, 'bearer-abc', OWNER),
      ).rejects.toBeInstanceOf(ForbiddenException);
      // No decrypt spent and no disclosure event: the refusal happens before
      // anything about this estate is read, so a refused call costs the
      // decedent's DEK nothing and leaves no trace claiming a disclosure.
      expect(decrypted).toEqual([]);
      expect(events.estateViews).toEqual([]);
    });

    it('refuses when settlement cannot be reached — fail closed', async () => {
      const { service, settlement } = await estateWithTwoContacts();
      /*
       * The real client answers `{allowed:false}` for a network failure, a
       * non-2xx and an unparseable body alike, so "we could not ask" and "no"
       * are the same answer here BY CONSTRUCTION. Asserted because the
       * alternative — treating an unreachable settlement as permission — is the
       * failure mode that turns an outage into an estate disclosure.
       */
      settlement.checkStageAccess = (): Promise<never> => {
        throw new Error('the double must never be asked to invent an answer');
      };
      settlement.checkStageAccess = () =>
        Promise.resolve({ allowed: false as const, caseId: null });
      await expect(
        service.listEstateContacts(EXECUTOR, 'bearer-abc', OWNER),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('records the AUTHORITY before releasing any plaintext', async () => {
      const { service, settlement, events, decrypted } = await estateWithTwoContacts();
      settlement.allowed = true;
      /*
       * ORDER AGAINST THE DECRYPTS, not position in the event list — the
       * M19 PR4 lesson `asset.estate.viewed` learned. Emitted after the decrypt
       * loop, a failure part-way through leaves executor-attributed
       * `crypto.field.decrypted` events on the decedent's trail with NO record
       * of what authorised them, in exactly the §5.1 case the trail is kept
       * for. So the measurement is how many names had been decrypted AT THE
       * MOMENT the event fired, which is the thing that actually has to be
       * zero.
       */
      let decryptsWhenRecorded = -1;
      const realEmit = events.contactEstateViewed.bind(events);
      events.contactEstateViewed = (actor, owner, detail): Promise<void> => {
        decryptsWhenRecorded = decrypted.length;
        return realEmit(actor, owner, detail);
      };

      await service.listEstateContacts(EXECUTOR, 'bearer-abc', OWNER);

      expect(decryptsWhenRecorded).toBe(0);
      // Anti-vacuity: the call really did decrypt afterwards, so the zero above
      // is an ORDERING and not a route that read nothing.
      expect(decrypted.length).toBe(2);
      expect(events.estateViews).toEqual([
        { actor: EXECUTOR, owner: OWNER, caseId: 'case-1', count: 2 },
      ]);
    });

    it('counts the AUTHORISED scope, and names no contact in the trail', async () => {
      const { service, settlement, events } = await estateWithTwoContacts();
      settlement.allowed = true;
      await service.listEstateContacts(EXECUTOR, 'bearer-abc', OWNER);
      // The count is the scope the grant covered. Naming the contacts would put
      // the very PII this event records the disclosure of into the trail.
      expect(JSON.stringify(events.estateViews)).not.toContain('attorney');
      expect(JSON.stringify(events.estateViews)).not.toContain('accountant');
    });

    it('does NOT thaw the grant path — an ordinary role-holder stays frozen', async () => {
      /*
       * THE POSITIVE CONTROL FOR THE WHOLE BLOCK, and the reason this is two
       * arms rather than one widened query. `GRANTEE` holds no effective grant
       * here (the roles double returns none), and the executor arm must not
       * have become a back door for them: they are not this estate's executor,
       * so settlement refuses, and `listForOwner` still refuses too.
       */
      const { service, settlement } = await estateWithTwoContacts();
      settlement.allowed = false;
      await expect(service.listForOwner(GRANTEE, OWNER)).rejects.toBeInstanceOf(ForbiddenException);
      // ...and with the rung open for the EXECUTOR, the grantee's own path is
      // unchanged: the two arms do not see each other.
      settlement.allowed = true;
      await expect(service.listForOwner(GRANTEE, OWNER)).rejects.toBeInstanceOf(ForbiddenException);
    });
  });

  /**
   * THE GRANTEE-CANDIDATE PROJECTION (M15 PR3).
   *
   * This is the one profile response a `vault`-audience session may read, so
   * its shape is exactly what a leaked vault handoff would buy at this service.
   * Every assertion here is about what it does NOT contain.
   */
  describe('grantee candidates', () => {
    it('returns three fields for linked contacts, and nothing for unlinked ones', async () => {
      const { service, repo } = build();
      const linked = await service.create(OWNER, {
        name: 'Ada Grantee',
        email: 'ada@example.com',
        phone: '555-0100',
        notes: 'has the spare keys',
        relationship: 'sibling',
      });
      await service.create(OWNER, { name: 'Unlinked Ursula' });
      repo.link(linked.id, GRANTEE);

      const candidates = await service.granteeCandidates(OWNER);
      expect(candidates).toEqual([{ contactId: linked.id, userId: GRANTEE, name: 'Ada Grantee' }]);
      // An unlinked contact has no account and so no published recovery key —
      // it could only ever render a row the owner cannot choose.
      expect(JSON.stringify(candidates)).not.toContain('Ursula');
      // And none of the contact's own detail crosses.
      const text = JSON.stringify(candidates);
      expect(text).not.toContain('ada@example.com');
      expect(text).not.toContain('555-0100');
      expect(text).not.toContain('spare keys');
      expect(text).not.toContain('sibling');
    });

    it('spends ONE decrypt per row, like the summary list (M13 PR2)', async () => {
      const { service, repo, decrypted } = build();
      const a = await service.create(OWNER, {
        name: 'Ada',
        email: 'a@example.com',
        phone: '1',
        address: '2',
        notes: '3',
      });
      repo.link(a.id, GRANTEE);

      decrypted.length = 0;
      await service.granteeCandidates(OWNER);
      // The name and nothing else. A projection that read the full row would
      // put four extra audited decrypts on the owner's trail per grantee shown.
      expect(decrypted).toEqual(['contact.name']);
    });

    it('still runs the PEP per row — the narrower route is not the exempt one', async () => {
      const { service, repo, authz } = build();
      const linked = await service.create(OWNER, { name: 'Ada' });
      repo.link(linked.id, GRANTEE);
      expect(await service.granteeCandidates(OWNER)).toHaveLength(1);

      // A policy that denies must empty the list rather than be bypassed. The
      // owner is always permitted by owner.cedar, so this is the only way to
      // show the decision is consulted at all rather than assumed.
      jest.spyOn(authz, 'can').mockReturnValue(false);
      expect(await service.granteeCandidates(OWNER)).toEqual([]);
    });

    it('is SELF-ONLY: it takes no owner and answers about the caller alone', async () => {
      const { service, repo } = build();
      const mine = await service.create(OWNER, { name: 'Mine' });
      repo.link(mine.id, GRANTEE);
      const theirs = await service.create(GRANTEE, { name: 'Theirs' });
      repo.link(theirs.id, OWNER);

      // Nobody has a legitimate reason to choose grantees for someone else's
      // vault, so unlike `listForOwner` there is nowhere here to name another
      // estate — the §5.5 cross-owner read has no counterpart on this route.
      expect(await service.granteeCandidates(OWNER)).toEqual([
        { contactId: mine.id, userId: GRANTEE, name: 'Mine' },
      ]);
      expect(await service.granteeCandidates(GRANTEE)).toEqual([
        { contactId: theirs.id, userId: OWNER, name: 'Theirs' },
      ]);
    });
  });
});
