import { ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { emailBlindIndex } from '@estate/crypto';
import { coreResource, ProfileAuthz } from './authz.service';
import { CLOCK, CONFIG, type Clock } from './di-tokens';
import type { ProfileConfig } from './config';
import { EventsService } from './events.service';
import { FieldCipher } from './field-cipher';
import { ContactsRepo, type ContactInsert, type ContactRow } from './contacts.repo';
import { RolesRepo } from './roles.repo';
import type { ContactInput } from './schemas';

export interface ContactView {
  id: string;
  ownerUserId: string;
  name: string;
  email: string | null;
  phone: string | null;
  address: string | null;
  relationship: string | null;
  professionalKind: string | null;
  notes: string | null;
}

/**
 * Estate contact repository operations + the docs/03 §5.5 ABAC read boundary.
 *
 * Writes are owner-only (owner.cedar). Reads go through the PEP with a resolved
 * `grantees` set: the owner always sees their contacts; a role-holder sees ONLY
 * the specific contacts an effective grant names (scope_id) — or all of them
 * only under an explicit estate-wide grant. A role-holder can never enumerate
 * contacts their grant does not cover.
 */
@Injectable()
export class ContactsService {
  constructor(
    private readonly repo: ContactsRepo,
    private readonly roles: RolesRepo,
    private readonly cipher: FieldCipher,
    private readonly authz: ProfileAuthz,
    private readonly events: EventsService,
    @Inject(CONFIG) private readonly config: ProfileConfig,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  private async encryptRow(ownerUserId: string, input: ContactInput): Promise<ContactInsert> {
    // Materialize the owner's DEK first: concurrent getOrCreateDek calls would
    // otherwise race and mint several DEKs, encrypting fields under different
    // keys within one row. After this, every parallel encrypt shares one DEK.
    await this.cipher.getOrCreateDek(ownerUserId);
    const [name, email, phone, address, notes] = await Promise.all([
      this.cipher.encrypt(ownerUserId, 'contact.name', input.name),
      this.cipher.encrypt(ownerUserId, 'contact.email', input.email),
      this.cipher.encrypt(ownerUserId, 'contact.phone', input.phone),
      this.cipher.encrypt(ownerUserId, 'contact.address', input.address),
      this.cipher.encrypt(ownerUserId, 'contact.notes', input.notes),
    ]);
    return {
      owner_user_id: ownerUserId,
      name_ct: name.ciphertext as Buffer,
      email_ct: email.ciphertext,
      // Blind index only when an email exists; enables per-owner dedupe/lookup
      // without decryption (SSNs deliberately get none — docs/02 §8).
      email_bidx: input.email ? emailBlindIndex(this.config.emailIndexKey, input.email) : null,
      phone_ct: phone.ciphertext,
      address_ct: address.ciphertext,
      relationship: input.relationship ?? null,
      professional_kind: input.professionalKind ?? null,
      linked_user_id: null,
      notes_ct: notes.ciphertext,
      dek_id: name.dekId,
    };
  }

  async create(callerUserId: string, input: ContactInput): Promise<{ id: string }> {
    this.authz.assertCan(
      callerUserId,
      'create',
      coreResource('Contact', callerUserId, callerUserId),
    );
    const id = await this.repo.insert(await this.encryptRow(callerUserId, input));
    await this.events.contactCreated(callerUserId, id);
    return { id };
  }

  async update(callerUserId: string, id: string, input: ContactInput): Promise<void> {
    this.authz.assertCan(callerUserId, 'update', coreResource('Contact', id, callerUserId));
    const ok = await this.repo.update(id, callerUserId, await this.encryptRow(callerUserId, input));
    if (!ok) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.events.contactUpdated(callerUserId, id);
  }

  async remove(callerUserId: string, id: string): Promise<void> {
    this.authz.assertCan(callerUserId, 'delete', coreResource('Contact', id, callerUserId));
    const ok = await this.repo.softDelete(id, callerUserId);
    if (!ok) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.events.contactDeleted(callerUserId, id);
  }

  /**
   * ABAC-gated single read. The `grantees` set is resolved from effective
   * grants and passed to the PEP; owner.cedar (owner) or profile.cedar
   * (grantee named on THIS contact) must permit, else a generic 403.
   */
  async getOne(callerUserId: string, ownerUserId: string, contactId: string): Promise<ContactView> {
    const grantees = await this.resolveGrantees(callerUserId, ownerUserId, contactId);
    this.authz.assertCan(
      callerUserId,
      'read',
      coreResource('Contact', contactId, ownerUserId, grantees),
    );
    const row = await this.repo.findById(contactId);
    if (!row || row.owner_user_id !== ownerUserId) {
      throw new NotFoundException({ error: 'not_found' });
    }
    return this.toView(callerUserId, row);
  }

  /**
   * ABAC-gated list. Owner sees all; a role-holder sees only the contacts their
   * effective grants name (or all under an estate-wide grant). A caller with no
   * effective grant and who is not the owner gets a generic 403 — nothing leaks.
   */
  async listForOwner(callerUserId: string, ownerUserId: string): Promise<ContactView[]> {
    const isOwner = callerUserId === ownerUserId;
    const grants = isOwner
      ? []
      : await this.roles.effectiveContactReadGrants(ownerUserId, callerUserId, this.clock());
    const estateWide = grants.some((g) => g.scope_type === 'estate' && g.scope_id === null);
    const namedIds = new Set(
      grants.map((g) => g.scope_id).filter((id): id is string => id !== null),
    );

    // Collection-level gate: owner, or a caller holding ANY effective grant.
    if (!isOwner && !estateWide && namedIds.size === 0) {
      throw new ForbiddenException({ error: 'forbidden' });
    }

    const rows = await this.repo.listByOwner(ownerUserId);
    const visible = rows.filter((row) => {
      const grantees = isOwner || estateWide || namedIds.has(row.id) ? [callerUserId] : [];
      // Every returned row is individually re-checked through the PEP.
      return this.authz.can(
        callerUserId,
        'read',
        coreResource('Contact', row.id, ownerUserId, grantees),
      );
    });
    return Promise.all(visible.map((row) => this.toView(callerUserId, row)));
  }

  /** Resolve whether `callerUserId` holds an effective read grant over `contactId`. */
  private async resolveGrantees(
    callerUserId: string,
    ownerUserId: string,
    contactId: string,
  ): Promise<string[]> {
    if (callerUserId === ownerUserId) {
      return []; // owner path uses owner.cedar; no grantee set needed
    }
    const grants = await this.roles.effectiveContactReadGrants(
      ownerUserId,
      callerUserId,
      this.clock(),
    );
    const named = grants.some(
      (g) => (g.scope_type === 'estate' && g.scope_id === null) || g.scope_id === contactId,
    );
    return named ? [callerUserId] : [];
  }

  private async toView(callerUserId: string, row: ContactRow): Promise<ContactView> {
    // Contact PII is encrypted under the OWNER's DEK; the actor performing the
    // (audited) decryption is the caller — the delegated-read case.
    const dec = (field: string, ciphertext: Buffer | null): Promise<string | null> =>
      this.cipher.decrypt({
        ownerUserId: row.owner_user_id,
        dekId: row.dek_id,
        field,
        ciphertext,
        actorId: callerUserId,
        purpose: 'contact_read',
      });
    const [name, email, phone, address, notes] = await Promise.all([
      dec('contact.name', row.name_ct),
      dec('contact.email', row.email_ct),
      dec('contact.phone', row.phone_ct),
      dec('contact.address', row.address_ct),
      dec('contact.notes', row.notes_ct),
    ]);
    return {
      id: row.id,
      ownerUserId: row.owner_user_id,
      name: name as string,
      email,
      phone,
      address,
      relationship: row.relationship,
      professionalKind: row.professional_kind,
      notes,
    };
  }
}
