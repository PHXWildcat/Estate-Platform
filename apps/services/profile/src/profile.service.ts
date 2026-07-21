import { Injectable, NotFoundException } from '@nestjs/common';
import { coreResource, ProfileAuthz } from './authz.service';
import { EventsService } from './events.service';
import { FieldCipher } from './field-cipher';
import { ProfileRepo, type ProfileRow } from './profile.repo';
import type { ProfileUpsertInput } from './schemas';

/** Decrypted profile view returned to an authorized caller. */
export interface ProfileView {
  userId: string;
  legalName: string;
  dob: string | null;
  ssnLast4: string | null;
  address: string | null;
  phone: string | null;
  occupation: string | null;
  maritalStatus: string | null;
  stateOfResidence: string | null;
}

/**
 * Own-profile operations. The profile is 1:1 with the auth user; only the
 * owner may read or write it (owner.cedar). SSN is stored in full plus a
 * separate last-4 for display; neither gets a blind index (docs/02 §8).
 */
@Injectable()
export class ProfileService {
  constructor(
    private readonly repo: ProfileRepo,
    private readonly cipher: FieldCipher,
    private readonly authz: ProfileAuthz,
    private readonly events: EventsService,
  ) {}

  async upsert(callerUserId: string, input: ProfileUpsertInput): Promise<void> {
    // Own-only write: the resource owner IS the caller, so only owner.cedar
    // can permit it; no grant path exists for writes.
    this.authz.assertCan(
      callerUserId,
      'update',
      coreResource('Profile', callerUserId, callerUserId),
    );

    // Pre-create the DEK so the concurrent field encrypts below all share one
    // key (a concurrent getOrCreateDek race would otherwise mint several).
    await this.cipher.getOrCreateDek(callerUserId);
    const ssnLast4 = input.ssn ? input.ssn.slice(-4) : undefined;
    const [legalName, dob, ssn, ssnL4, address, phone, occupation] = await Promise.all([
      this.cipher.encrypt(callerUserId, 'profile.legal_name', input.legalName),
      this.cipher.encrypt(callerUserId, 'profile.dob', input.dob),
      this.cipher.encrypt(callerUserId, 'profile.ssn', input.ssn),
      this.cipher.encrypt(callerUserId, 'profile.ssn_last4', ssnLast4),
      this.cipher.encrypt(callerUserId, 'profile.address', input.address),
      this.cipher.encrypt(callerUserId, 'profile.phone', input.phone),
      this.cipher.encrypt(callerUserId, 'profile.occupation', input.occupation),
    ]);

    const row: ProfileRow = {
      user_id: callerUserId,
      legal_name_ct: legalName.ciphertext as Buffer,
      dob_ct: dob.ciphertext,
      ssn_ct: ssn.ciphertext,
      ssn_last4_ct: ssnL4.ciphertext,
      address_ct: address.ciphertext,
      phone_ct: phone.ciphertext,
      occupation_ct: occupation.ciphertext,
      marital_status: input.maritalStatus ?? null,
      state_of_residence: input.stateOfResidence ?? null,
      dek_id: legalName.dekId,
    };
    await this.repo.upsert(row);
    await this.events.profileUpserted(callerUserId, callerUserId);
  }

  async getOwn(callerUserId: string): Promise<ProfileView> {
    this.authz.assertCan(callerUserId, 'read', coreResource('Profile', callerUserId, callerUserId));
    const row = await this.repo.findByUserId(callerUserId);
    if (!row) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const dec = (field: string, ciphertext: Buffer | null): Promise<string | null> =>
      this.cipher.decrypt({
        ownerUserId: callerUserId,
        dekId: row.dek_id,
        field,
        ciphertext,
        actorId: callerUserId,
        purpose: 'profile_read',
      });
    const [legalName, dob, ssnLast4, address, phone, occupation] = await Promise.all([
      dec('profile.legal_name', row.legal_name_ct),
      dec('profile.dob', row.dob_ct),
      dec('profile.ssn_last4', row.ssn_last4_ct),
      dec('profile.address', row.address_ct),
      dec('profile.phone', row.phone_ct),
      dec('profile.occupation', row.occupation_ct),
    ]);
    return {
      userId: row.user_id,
      legalName: legalName as string,
      dob,
      ssnLast4,
      address,
      phone,
      occupation,
      maritalStatus: row.marital_status,
      stateOfResidence: row.state_of_residence,
    };
  }
}
