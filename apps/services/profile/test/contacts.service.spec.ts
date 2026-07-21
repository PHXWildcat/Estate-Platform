import { ForbiddenException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { FieldCrypto, LocalKmsProvider, type DekRecord, type DekRepository } from '@estate/crypto';
import { ProfileAuthz } from '../src/authz.service';
import type { ProfileConfig } from '../src/config';
import { ContactsService } from '../src/contacts.service';
import type { ContactInsert, ContactRow } from '../src/contacts.repo';
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

/** In-memory contacts repo. */
class FakeContactsRepo {
  readonly rows: ContactRow[] = [];
  private seq = 0;
  insert(row: ContactInsert): Promise<string> {
    const id = `f0000000-0000-4000-8000-00000000000${++this.seq}`;
    this.rows.push({ ...row, id });
    return Promise.resolve(id);
  }
  findById(id: string): Promise<ContactRow | null> {
    return Promise.resolve(this.rows.find((r) => r.id === id) ?? null);
  }
  listByOwner(ownerUserId: string): Promise<ContactRow[]> {
    return Promise.resolve(this.rows.filter((r) => r.owner_user_id === ownerUserId));
  }
  update(): Promise<boolean> {
    return Promise.resolve(true);
  }
  softDelete(): Promise<boolean> {
    return Promise.resolve(true);
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
  contactCreated(_actor: string, id: string): Promise<void> {
    this.created.push(id);
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
  const cipher = new FieldCipher(crypto);
  const repo = new FakeContactsRepo();
  const roles = new FakeRolesRepo();
  const events = new FakeEvents();
  const authz = new ProfileAuthz(new PolicyDecisionPoint(loadBundledPolicies()));
  const config = { emailIndexKey: Buffer.alloc(32, 7) } as unknown as ProfileConfig;
  const service = new ContactsService(
    repo as never,
    roles as never,
    cipher,
    authz,
    events as never,
    config,
    () => new Date(),
  );
  return { service, repo, roles, events };
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
