import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
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

  /**
   * Create or update the caller's profile. An ABSENT optional field is left as
   * it was; an explicit `null` clears it (see `Clearable` in schemas.ts for why
   * that distinction has to exist).
   *
   * PRESERVATION CARRIES CIPHERTEXT, NEVER PLAINTEXT. The alternative — decrypt
   * the fields the caller did not send and re-encrypt them — would put the full
   * SSN through this process's memory on every unrelated edit and emit a
   * `crypto.field.decrypted` on `profile.ssn` each time, turning a change of
   * state-of-residence into a logged read of the most sensitive value we hold.
   * Copying the stored bytes forward is both cheaper and strictly less
   * disclosure: the value is never available to this code at all.
   *
   * That is sound only while the carried bytes and the newly written ones share
   * one key, which they do — the row has a single `dek_id` column, all of an
   * owner's fields use their one active DEK, and a partial unique index enforces
   * that there is only ever one. If the stored row was written under a DEK that
   * is no longer the active one, the carry is refused rather than performed
   * (see below): the only way that happens is a crypto-shred, and stamping
   * unreadable bytes with a live key id would replace an honest "this was
   * erased" with a row that looks intact and decrypts to nothing. The M4 rule —
   * a shredded record is Gone, not a fresh live key.
   */
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
    const dekId = await this.cipher.getOrCreateDek(callerUserId);
    const stored = await this.repo.findByUserId(callerUserId);
    if (stored !== null && stored.dek_id !== dekId) {
      throw new ConflictException({ error: 'profile_key_retired' });
    }

    // `undefined` ⇒ carry the stored ciphertext; `null` ⇒ clear; a value ⇒ encrypt.
    const field = async (
      column: keyof ProfileRow & `${string}_ct`,
      aad: string,
      value: string | null | undefined,
    ): Promise<Buffer | null> => {
      if (value === undefined) {
        return stored?.[column] ?? null;
      }
      const { ciphertext } = await this.cipher.encrypt(callerUserId, aad, value);
      return ciphertext;
    };

    // The last four are DERIVED, so they follow the SSN exactly: carried when it
    // is carried, cleared when it is cleared, recomputed when it is set. A
    // separately-supplied last-4 could otherwise disagree with the stored SSN.
    const ssnLast4 =
      input.ssn === undefined || input.ssn === null ? input.ssn : input.ssn.slice(-4);

    const [legalName, dob, ssn, ssnL4, address, phone, occupation] = await Promise.all([
      this.cipher.encrypt(callerUserId, 'profile.legal_name', input.legalName),
      field('dob_ct', 'profile.dob', input.dob),
      field('ssn_ct', 'profile.ssn', input.ssn),
      field('ssn_last4_ct', 'profile.ssn_last4', ssnLast4),
      field('address_ct', 'profile.address', input.address),
      field('phone_ct', 'profile.phone', input.phone),
      field('occupation_ct', 'profile.occupation', input.occupation),
    ]);

    // Plaintext columns follow the same three-way rule, without the ciphertext.
    const plain = <T>(value: T | null | undefined, current: T | null): T | null =>
      value === undefined ? current : value;

    const row: ProfileRow = {
      user_id: callerUserId,
      legal_name_ct: legalName.ciphertext as Buffer,
      dob_ct: dob,
      ssn_ct: ssn,
      ssn_last4_ct: ssnL4,
      address_ct: address,
      phone_ct: phone,
      occupation_ct: occupation,
      marital_status: plain(input.maritalStatus, stored?.marital_status ?? null),
      state_of_residence: plain(input.stateOfResidence, stored?.state_of_residence ?? null),
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
