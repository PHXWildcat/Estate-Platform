import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { coreResource, ProfileAuthz } from '../src/authz.service';
import { FamilyService } from '../src/family.service';
import type { FamilyMemberInsert, FamilyMemberRow } from '../src/family.repo';
import { ProfileService } from '../src/profile.service';
import type { ProfileRow } from '../src/profile.repo';
import { buildCipher, noopEvents } from './support';

const OWNER = 'a1111111-1111-4111-8111-111111111111';
const OTHER = 'b2222222-2222-4222-8222-222222222222';

const authz = (): ProfileAuthz => new ProfileAuthz(new PolicyDecisionPoint(loadBundledPolicies()));

class FakeProfileRepo {
  row: ProfileRow | null = null;
  upsert(row: ProfileRow): Promise<void> {
    this.row = row;
    return Promise.resolve();
  }
  findByUserId(userId: string): Promise<ProfileRow | null> {
    return Promise.resolve(this.row && this.row.user_id === userId ? this.row : null);
  }
}

class FakeFamilyRepo {
  readonly rows: FamilyMemberRow[] = [];
  private seq = 0;
  insert(row: FamilyMemberInsert): Promise<string> {
    const id = `c0000000-0000-4000-8000-00000000000${++this.seq}`;
    this.rows.push({ ...row, id });
    return Promise.resolve(id);
  }
  listByOwner(userId: string): Promise<FamilyMemberRow[]> {
    return Promise.resolve(this.rows.filter((r) => r.user_id === userId));
  }
  update(): Promise<boolean> {
    return Promise.resolve(true);
  }
  softDelete(): Promise<boolean> {
    return Promise.resolve(true);
  }
}

describe('ProfileService (own-only)', () => {
  function build() {
    const repo = new FakeProfileRepo();
    const service = new ProfileService(repo as never, buildCipher(), authz(), noopEvents);
    return { repo, service };
  }

  it('upserts encrypted fields and reads them back decrypted (owner)', async () => {
    const { repo, service } = build();
    await service.upsert(OWNER, {
      legalName: 'Owner Name',
      ssn: '123456789',
      maritalStatus: 'single',
      stateOfResidence: 'NY',
    });
    // SSN stored full + last4, both as ciphertext; last4 derived server-side.
    expect((repo.row as ProfileRow).legal_name_ct.toString('utf8')).not.toContain('Owner');
    expect((repo.row as ProfileRow).state_of_residence).toBe('NY');

    const view = await service.getOwn(OWNER);
    expect(view.legalName).toBe('Owner Name');
    expect(view.ssnLast4).toBe('6789');
    expect(view.maritalStatus).toBe('single');
  });

  it('404s when no profile exists yet', async () => {
    const { service } = build();
    await expect(service.getOwn(OWNER)).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe('FamilyService (own-only)', () => {
  function build() {
    const repo = new FakeFamilyRepo();
    const service = new FamilyService(repo as never, buildCipher(), authz(), noopEvents);
    return { repo, service };
  }

  it('creates and lists family members decrypted for the owner', async () => {
    const { service } = build();
    const created = await service.create(OWNER, {
      relation: 'child',
      name: 'Kiddo',
      isMinor: true,
    });
    const list = await service.list(OWNER);
    expect(list).toHaveLength(1);
    expect(list[0]?.id).toBe(created.id);
    expect(list[0]?.name).toBe('Kiddo');
    expect(list[0]?.isMinor).toBe(true);
  });

  it('family members are own-only: a non-owner is denied (deny by default)', () => {
    // Family reads/writes model the resource owner as the caller, so only
    // owner.cedar can permit — a foreign owner's resource is never allowed.
    expect(() =>
      authz().assertCan(OTHER, 'read', coreResource('FamilyMember', OWNER, OWNER)),
    ).toThrow(ForbiddenException);
  });
});
