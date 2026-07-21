import { Injectable, NotFoundException } from '@nestjs/common';
import { coreResource, ProfileAuthz } from './authz.service';
import { EventsService } from './events.service';
import { FieldCipher } from './field-cipher';
import { FamilyRepo, type FamilyMemberInsert, type FamilyMemberRow } from './family.repo';
import type { FamilyMemberInput } from './schemas';

export interface FamilyMemberView {
  id: string;
  relation: string;
  name: string;
  dob: string | null;
  isMinor: boolean | null;
  notes: string | null;
}

/** Own family-member CRUD (children/parents/spouse for wills & guardianship). */
@Injectable()
export class FamilyService {
  constructor(
    private readonly repo: FamilyRepo,
    private readonly cipher: FieldCipher,
    private readonly authz: ProfileAuthz,
    private readonly events: EventsService,
  ) {}

  private async encryptRow(
    ownerUserId: string,
    input: FamilyMemberInput,
  ): Promise<FamilyMemberInsert> {
    // Pre-create the DEK so concurrent encrypts share one key (see contacts).
    await this.cipher.getOrCreateDek(ownerUserId);
    const [name, dob, notes] = await Promise.all([
      this.cipher.encrypt(ownerUserId, 'family.name', input.name),
      this.cipher.encrypt(ownerUserId, 'family.dob', input.dob),
      this.cipher.encrypt(ownerUserId, 'family.notes', input.notes),
    ]);
    return {
      user_id: ownerUserId,
      relation: input.relation,
      name_ct: name.ciphertext as Buffer,
      dob_ct: dob.ciphertext,
      is_minor: input.isMinor ?? null,
      notes_ct: notes.ciphertext,
      dek_id: name.dekId,
    };
  }

  async create(callerUserId: string, input: FamilyMemberInput): Promise<{ id: string }> {
    this.authz.assertCan(
      callerUserId,
      'create',
      coreResource('FamilyMember', callerUserId, callerUserId),
    );
    const id = await this.repo.insert(await this.encryptRow(callerUserId, input));
    await this.events.familyMemberCreated(callerUserId, id);
    return { id };
  }

  async update(callerUserId: string, id: string, input: FamilyMemberInput): Promise<void> {
    this.authz.assertCan(callerUserId, 'update', coreResource('FamilyMember', id, callerUserId));
    const ok = await this.repo.update(id, callerUserId, await this.encryptRow(callerUserId, input));
    if (!ok) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.events.familyMemberUpdated(callerUserId, id);
  }

  async remove(callerUserId: string, id: string): Promise<void> {
    this.authz.assertCan(callerUserId, 'delete', coreResource('FamilyMember', id, callerUserId));
    const ok = await this.repo.softDelete(id, callerUserId);
    if (!ok) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.events.familyMemberDeleted(callerUserId, id);
  }

  async list(callerUserId: string): Promise<FamilyMemberView[]> {
    this.authz.assertCan(
      callerUserId,
      'read',
      coreResource('FamilyMember', callerUserId, callerUserId),
    );
    const rows = await this.repo.listByOwner(callerUserId);
    return Promise.all(rows.map((row) => this.toView(callerUserId, row)));
  }

  private async toView(callerUserId: string, row: FamilyMemberRow): Promise<FamilyMemberView> {
    const dec = (field: string, ciphertext: Buffer | null): Promise<string | null> =>
      this.cipher.decrypt({
        ownerUserId: callerUserId,
        dekId: row.dek_id,
        field,
        ciphertext,
        actorId: callerUserId,
        purpose: 'family_read',
      });
    const [name, dob, notes] = await Promise.all([
      dec('family.name', row.name_ct),
      dec('family.dob', row.dob_ct),
      dec('family.notes', row.notes_ct),
    ]);
    return {
      id: row.id,
      relation: row.relation,
      name: name as string,
      dob,
      isMinor: row.is_minor,
      notes,
    };
  }
}
