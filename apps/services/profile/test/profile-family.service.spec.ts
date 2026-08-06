import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
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

  /**
   * The defect this block pins (M13 PR1): the upsert was a full replace, and
   * `GET /v1/profile` returns `ssnLast4` but NEVER `ssn`. So no client could
   * round-trip the row, and editing any other field wrote NULL over `ssn_ct` and
   * `ssn_last4_ct` — silent destruction of the most sensitive column in the
   * product, latent only because nothing called the route until M13 PR2 built a
   * form over it.
   */
  describe('an edit never destroys a field it did not send', () => {
    it('carries the SSN through an unrelated edit, and keeps the ciphertext byte-identical', async () => {
      const { repo, service } = build();
      await service.upsert(OWNER, {
        legalName: 'Owner Name',
        ssn: '123456789',
        dob: '1950-04-02',
        maritalStatus: 'single',
        stateOfResidence: 'NY',
      });
      const before = repo.row as ProfileRow;
      const ssnCtBefore = Buffer.from(before.ssn_ct as Buffer);

      // What the M13 PR2 form does: change one thing, send what it knows.
      await service.upsert(OWNER, { legalName: 'Owner Name', stateOfResidence: 'AZ' });

      const after = repo.row as ProfileRow;
      expect(after.state_of_residence).toBe('AZ');
      expect(after.ssn_ct).not.toBeNull();
      // Byte-identical: the value was carried as ciphertext, never decrypted and
      // re-encrypted (which would put the plaintext SSN through this process and
      // emit a crypto.field.decrypted on every unrelated edit).
      expect(after.ssn_ct).toEqual(ssnCtBefore);
      // Everything else the caller omitted is equally untouched.
      expect(after.dob_ct).toEqual(before.dob_ct);
      expect(after.marital_status).toBe('single');

      const view = await service.getOwn(OWNER);
      expect(view.ssnLast4).toBe('6789');
      expect(view.dob).toBe('1950-04-02');
      expect(view.stateOfResidence).toBe('AZ');
    });

    it('an explicit null clears the field, and the derived last-4 follows the SSN', async () => {
      const { repo, service } = build();
      await service.upsert(OWNER, {
        legalName: 'Owner Name',
        ssn: '123456789',
        phone: '555-0100',
      });
      expect((repo.row as ProfileRow).ssn_last4_ct).not.toBeNull();

      await service.upsert(OWNER, { legalName: 'Owner Name', ssn: null, phone: null });

      const after = repo.row as ProfileRow;
      expect(after.ssn_ct).toBeNull();
      // The last four are derived, so clearing the SSN must not leave them behind.
      expect(after.ssn_last4_ct).toBeNull();
      expect(after.phone_ct).toBeNull();
      expect((await service.getOwn(OWNER)).ssnLast4).toBeNull();
    });

    it('setting a new SSN recomputes the last four rather than carrying the old ones', async () => {
      const { service } = build();
      await service.upsert(OWNER, { legalName: 'Owner Name', ssn: '123456789' });
      expect((await service.getOwn(OWNER)).ssnLast4).toBe('6789');

      await service.upsert(OWNER, { legalName: 'Owner Name', ssn: '987654321' });
      expect((await service.getOwn(OWNER)).ssnLast4).toBe('4321');
    });

    it('refuses the write when the stored row was encrypted under a retired DEK', async () => {
      const { repo, service } = build();
      await service.upsert(OWNER, { legalName: 'Owner Name', ssn: '123456789' });

      // Stand in for a crypto-shred: the row's key is no longer the active one,
      // so its bytes cannot be carried onto a row stamped with the live key id.
      (repo.row as ProfileRow).dek_id = 'f0000000-0000-4000-8000-0000000000ff';

      await expect(
        service.upsert(OWNER, { legalName: 'Owner Name', stateOfResidence: 'AZ' }),
      ).rejects.toBeInstanceOf(ConflictException);
    });
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
