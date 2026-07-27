import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  createServerEphemeral,
  decodeGroupElement,
  deriveKeysetAuthKey,
  encodeGroupElement,
  verifyClientSession,
  verifyKeysetProof,
  type VaultKeysetPayload,
} from '@estate/vault-crypto';
import { CLOCK, type Clock } from './di-tokens';
import { Db, isUniqueViolation, type Queryable } from './db';
import { EmergencyRepo } from './emergency.repo';
import { EventsService } from './events.service';
import { HandshakesRepo } from './handshakes.repo';
import { ItemsRepo, type ItemRow } from './items.repo';
import { KeysetsRepo } from './keysets.repo';
import { VaultSessionsRepo } from './sessions.repo';
import { VaultAuthz, vaultItemResource, vaultResource } from './authz.service';
import { generateOpaqueToken, hashToken } from './tokens';
import type { VaultSessionContext } from './vault-session.guard';
import type { VaultItemType } from './schemas';

/** An SRP challenge is a one-shot, short-lived thing. */
export const HANDSHAKE_TTL_MS = 2 * 60 * 1000;
/**
 * Matches identity's access-token TTL. An open vault is the highest-value state
 * in the product, so it expires on the same clock as the session that opened
 * it rather than lingering.
 */
export const VAULT_SESSION_TTL_MS = 15 * 60 * 1000;

export interface KeysetStatus {
  readonly enrolled: boolean;
  readonly updatedAt: string | null;
}

export interface SrpChallenge {
  readonly handshakeId: string;
  readonly srpSalt: string;
  readonly kdfParams: unknown;
  readonly serverPublic: string;
}

export interface VaultOpened {
  readonly serverProof: string;
  readonly wrappedMasterKey: string;
  readonly vaultSession: {
    readonly id: string;
    readonly token: string;
    readonly expiresAt: string;
  };
}

export interface VaultItemDto {
  readonly id: string;
  readonly itemType: VaultItemType;
  readonly blob: string;
  readonly blobVersion: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface VaultItemPage {
  readonly items: readonly VaultItemDto[];
  readonly nextCursor: string | null;
}

function toDto(row: ItemRow): VaultItemDto {
  return {
    id: row.id,
    itemType: row.item_type,
    blob: row.blob_ct.toString('base64'),
    blobVersion: row.blob_version,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

function encodeCursor(row: ItemRow): string {
  return Buffer.from(`${row.updated_at.toISOString()}|${row.id}`, 'utf8').toString('base64url');
}

function decodeCursor(cursor: string): { updatedAt: Date; id: string } {
  const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  const separator = decoded.lastIndexOf('|');
  if (separator <= 0) throw new ConflictException({ error: 'invalid_cursor' });
  const updatedAt = new Date(decoded.slice(0, separator));
  const id = decoded.slice(separator + 1);
  if (Number.isNaN(updatedAt.getTime()) || id.length === 0) {
    throw new ConflictException({ error: 'invalid_cursor' });
  }
  return { updatedAt, id };
}

/**
 * The vault service.
 *
 * Read this file with one question in mind: where could the server learn
 * something about a vault's contents? The answer has to stay "nowhere". Blobs
 * arrive encrypted and leave encrypted; the SRP exchange proves the caller
 * knows the vault password without the password ever being sent; and the only
 * plaintext columns are an item-type enum and timestamps.
 */
@Injectable()
export class VaultService {
  constructor(
    private readonly db: Db,
    private readonly keysets: KeysetsRepo,
    private readonly items: ItemsRepo,
    private readonly handshakes: HandshakesRepo,
    private readonly sessions: VaultSessionsRepo,
    private readonly emergency: EmergencyRepo,
    private readonly authz: VaultAuthz,
    private readonly events: EventsService,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  async keysetStatus(actorUserId: string): Promise<KeysetStatus> {
    this.authz.assertCan(actorUserId, 'read', vaultResource(actorUserId));
    const keyset = await this.keysets.findByUser(this.db, actorUserId);
    return {
      enrolled: keyset !== null,
      updatedAt: keyset ? keyset.updated_at.toISOString() : null,
    };
  }

  /** First-time enrollment. Refuses to overwrite: replacing needs proof. */
  async createKeyset(
    actorUserId: string,
    accountSessionId: string,
    payload: VaultKeysetPayload,
  ): Promise<KeysetStatus> {
    this.authz.assertCan(actorUserId, 'manage', vaultResource(actorUserId));

    const status = await this.db.withTransaction(actorUserId, async (tx) => {
      const existing = await this.keysets.lockByUser(tx, actorUserId);
      if (existing) throw new ConflictException({ error: 'keyset_exists' });
      await this.keysets.insert(tx, {
        userId: actorUserId,
        srpVerifier: Buffer.from(payload.srpVerifier, 'base64'),
        srpSalt: Buffer.from(payload.srpSalt, 'base64'),
        wrappedMasterKey: Buffer.from(payload.wrappedMasterKey, 'base64'),
        kdfParams: payload.kdfParams,
      });
      const created = await this.keysets.findByUser(tx, actorUserId);
      return { enrolled: true, updatedAt: created!.updated_at.toISOString() };
    });

    await this.events.keysetCreated(actorUserId, accountSessionId);
    return status;
  }

  /**
   * Password change.
   *
   * Guarded by step-up AND an open vault session, but neither is sufficient on
   * its own: the request must also carry an HMAC over the new keyset under the
   * key both sides derived from the SRP session. Without that, anyone holding
   * exfiltrated bearer tokens could overwrite the keyset with a wrapping of a
   * fresh random master key and destroy every item irrecoverably - reading the
   * vault would be protected by cryptography while destroying it was protected
   * only by tokens. The proof makes replacement require knowledge of the
   * CURRENT vault password.
   */
  async replaceKeyset(
    actorUserId: string,
    accountSessionId: string,
    vaultSession: VaultSessionContext,
    payload: VaultKeysetPayload,
    proof: string,
  ): Promise<KeysetStatus> {
    this.authz.assertCan(actorUserId, 'manage', vaultResource(actorUserId));

    const valid = await verifyKeysetProof(
      new Uint8Array(vaultSession.keysetAuthKey),
      payload,
      proof,
    );
    if (!valid) throw new ForbiddenException({ error: 'invalid_keyset_proof' });

    const now = this.clock();
    const result = await this.db.withTransaction(actorUserId, async (tx) => {
      const existing = await this.keysets.lockByUser(tx, actorUserId);
      if (!existing) throw new NotFoundException({ error: 'keyset_not_found' });
      await this.keysets.replace(tx, {
        userId: actorUserId,
        srpVerifier: Buffer.from(payload.srpVerifier, 'base64'),
        srpSalt: Buffer.from(payload.srpSalt, 'base64'),
        wrappedMasterKey: Buffer.from(payload.wrappedMasterKey, 'base64'),
        kdfParams: payload.kdfParams,
      });
      // Sibling sessions die with the old password: a password change is what
      // someone does when they think a session is compromised.
      const revoked = await this.sessions.revokeAllForUserExcept(tx, {
        userId: actorUserId,
        exceptId: vaultSession.id,
        reason: 'keyset_rotated',
        at: now,
      });
      const updated = await this.keysets.findByUser(tx, actorUserId);
      return { revoked, updatedAt: updated!.updated_at.toISOString() };
    });

    await this.events.keysetUpdated(actorUserId, accountSessionId, {
      revokedSessions: result.revoked,
    });
    return { enrolled: true, updatedAt: result.updatedAt };
  }

  /** SRP leg 1: hand back the challenge and the parameters to derive under. */
  async startUnlock(actorUserId: string, accountSessionId: string): Promise<SrpChallenge> {
    this.authz.assertCan(actorUserId, 'read', vaultResource(actorUserId));

    const keyset = await this.keysets.findByUser(this.db, actorUserId);
    if (!keyset) {
      await this.events.openFailed(actorUserId, accountSessionId, 'no_keyset');
      throw new NotFoundException({ error: 'keyset_not_found' });
    }

    const now = this.clock();
    await this.handshakes.deleteExpired(this.db, now);

    const verifier = decodeGroupElement(keyset.srp_verifier.toString('base64'), 'verifier');
    const ephemeral = await createServerEphemeral(verifier);
    const handshake = await this.handshakes.insert(this.db, {
      userId: actorUserId,
      serverPublic: Buffer.from(encodeGroupElement(ephemeral.B), 'base64'),
      serverSecret: Buffer.from(encodeGroupElement(ephemeral.b), 'base64'),
      expiresAt: new Date(now.getTime() + HANDSHAKE_TTL_MS),
    });

    return {
      handshakeId: handshake.id,
      srpSalt: keyset.srp_salt.toString('base64'),
      kdfParams: keyset.kdf_params,
      serverPublic: encodeGroupElement(ephemeral.B),
    };
  }

  /**
   * SRP leg 2. The wrapped master key is released ONLY after the client's proof
   * verifies - it is the one response in this service that is worth stealing,
   * so it is behind the one check that cannot be faked without the password.
   */
  async finishUnlock(
    actorUserId: string,
    accountSessionId: string,
    input: { handshakeId: string; clientPublic: string; clientProof: string },
  ): Promise<VaultOpened> {
    this.authz.assertCan(actorUserId, 'read', vaultResource(actorUserId));
    const now = this.clock();

    const handshake = await this.handshakes.claim(this.db, {
      id: input.handshakeId,
      userId: actorUserId,
      now,
    });
    if (!handshake) {
      await this.events.openFailed(actorUserId, accountSessionId, 'no_handshake');
      throw new UnauthorizedException({ error: 'srp_failed' });
    }

    const keyset = await this.keysets.findByUser(this.db, actorUserId);
    if (!keyset) {
      await this.events.openFailed(actorUserId, accountSessionId, 'no_keyset');
      throw new UnauthorizedException({ error: 'srp_failed' });
    }

    const verified = await verifyClientSession({
      userId: actorUserId,
      salt: new Uint8Array(keyset.srp_salt),
      verifier: decodeGroupElement(keyset.srp_verifier.toString('base64'), 'verifier'),
      ephemeral: {
        B: decodeGroupElement(handshake.server_public.toString('base64'), 'server public value'),
        b: decodeGroupElement(handshake.server_secret.toString('base64'), 'server secret'),
      },
      A: decodeGroupElement(input.clientPublic, 'client public value'),
      M1: new Uint8Array(Buffer.from(input.clientProof, 'base64')),
    });
    if (!verified) {
      await this.events.openFailed(actorUserId, accountSessionId, 'bad_proof');
      throw new UnauthorizedException({ error: 'srp_failed' });
    }

    // The id has to exist before the keyset-auth key, which is derived from it.
    const vaultSessionId = randomUUID();
    const token = generateOpaqueToken();
    const keysetAuthKey = await deriveKeysetAuthKey(verified.sessionKey, vaultSessionId);
    const expiresAt = new Date(now.getTime() + VAULT_SESSION_TTL_MS);

    await this.sessions.create(this.db, {
      id: vaultSessionId,
      userId: actorUserId,
      tokenHash: hashToken(token),
      accountSessionId,
      keysetAuthKey: Buffer.from(keysetAuthKey),
      expiresAt,
    });

    await this.events.opened(actorUserId, accountSessionId, vaultSessionId);
    return {
      serverProof: Buffer.from(verified.M2).toString('base64'),
      wrappedMasterKey: keyset.wrapped_master_key.toString('base64'),
      vaultSession: { id: vaultSessionId, token, expiresAt: expiresAt.toISOString() },
    };
  }

  async lock(
    actorUserId: string,
    accountSessionId: string,
    vaultSession: VaultSessionContext,
  ): Promise<void> {
    await this.sessions.revoke(this.db, vaultSession.id, 'locked', this.clock());
    await this.events.sessionRevoked(actorUserId, accountSessionId, vaultSession.id, 'locked');
  }

  /**
   * List items.
   *
   * Returns whole blobs, because the server has no metadata to list: titles and
   * usernames live inside the ciphertext. That is the zero-knowledge trade -
   * the client decrypts locally to render a list - and it is why blobs are size
   * capped and this endpoint is paginated.
   */
  async listItems(
    actorUserId: string,
    accountSessionId: string,
    query: { limit: number; cursor?: string | undefined },
  ): Promise<VaultItemPage> {
    this.authz.assertCan(actorUserId, 'read', vaultResource(actorUserId));

    const rows = await this.items.listByUser(this.db, {
      userId: actorUserId,
      limit: query.limit,
      ...(query.cursor ? { cursor: decodeCursor(query.cursor) } : {}),
    });

    await this.events.itemsListed(actorUserId, accountSessionId, rows.length);
    const last = rows.length === query.limit ? rows[rows.length - 1] : undefined;
    return {
      items: rows.map(toDto),
      nextCursor: last ? encodeCursor(last) : null,
    };
  }

  async createItem(
    actorUserId: string,
    accountSessionId: string,
    input: { id: string; itemType: VaultItemType; blob: string },
  ): Promise<VaultItemDto> {
    this.authz.assertCan(actorUserId, 'create', vaultResource(actorUserId));

    const row = await this.db
      .withTransaction(actorUserId, (tx: Queryable) =>
        this.items.insert(tx, {
          id: input.id,
          userId: actorUserId,
          itemType: input.itemType,
          blob: Buffer.from(input.blob, 'base64'),
        }),
      )
      .catch((err: unknown) => {
        // The client generates item ids (they are bound into the blob's AAD),
        // so a repeat is a retry of a request that already succeeded.
        if (isUniqueViolation(err)) throw new ConflictException({ error: 'item_exists' });
        throw err;
      });

    await this.events.itemCreated(actorUserId, accountSessionId, row.id, row.item_type);
    return toDto(row);
  }

  async getItem(
    actorUserId: string,
    accountSessionId: string,
    itemId: string,
  ): Promise<VaultItemDto> {
    const row = await this.items.findLiveById(this.db, itemId);
    if (!row) throw new NotFoundException({ error: 'not_found' });
    this.authz.assertCan(actorUserId, 'read', vaultItemResource(itemId, row.user_id));

    await this.events.itemAccessed(actorUserId, accountSessionId, itemId);
    return toDto(row);
  }

  /**
   * Update an item. `If-Match` carries the blob version the client encrypted
   * against; the new blob is bound by AAD to version N+1, so the server MUST
   * store exactly that or the item stops decrypting.
   */
  async updateItem(
    actorUserId: string,
    accountSessionId: string,
    itemId: string,
    ifMatch: number,
    input: { itemType: VaultItemType; blob: string },
  ): Promise<VaultItemDto> {
    const row = await this.db.withTransaction(actorUserId, async (tx) => {
      const locked = await this.items.lockLiveById(tx, itemId);
      if (!locked) throw new NotFoundException({ error: 'not_found' });
      this.authz.assertCan(actorUserId, 'update', vaultItemResource(itemId, locked.user_id));
      if (locked.blob_version !== ifMatch) {
        throw new ConflictException({ error: 'version_conflict' });
      }
      return this.items.update(tx, {
        id: itemId,
        itemType: input.itemType,
        blob: Buffer.from(input.blob, 'base64'),
        nextVersion: locked.blob_version + 1,
      });
    });

    await this.events.itemUpdated(actorUserId, accountSessionId, itemId, row.blob_version);
    return toDto(row);
  }

  async deleteItem(actorUserId: string, accountSessionId: string, itemId: string): Promise<void> {
    const now = this.clock();
    await this.db.withTransaction(actorUserId, async (tx) => {
      const locked = await this.items.lockLiveById(tx, itemId);
      if (!locked) throw new NotFoundException({ error: 'not_found' });
      this.authz.assertCan(actorUserId, 'delete', vaultItemResource(itemId, locked.user_id));
      await this.items.softDelete(tx, itemId, now);
    });

    await this.events.itemDeleted(actorUserId, accountSessionId, itemId);
  }

  /**
   * Start over after a forgotten vault password.
   *
   * This DESTROYS the vault; it does not recover it. Nobody - including this
   * service - can decrypt the existing items, so the only coherent escape from
   * a lost password is to abandon them and enroll fresh.
   *
   * The destruction is cryptographic, not physical: this transaction destroys
   * EVERY wrapping of the old master key, after which the retained item rows
   * are permanently opaque - structure preserved, meaning destroyed, which is
   * the crypto-shredding primitive CLAUDE.md specifies for erasure.
   *
   * "Every wrapping" is the load-bearing word, and the M6 security review found
   * an earlier revision getting it wrong. There are two:
   *   1. `vault_keysets.wrapped_master_key`, overwritten by the replace below
   *      (the version trigger deliberately never kept a copy), and
   *   2. `emergency_access_configs.wrapped_master_key_recovery` - a SECOND live
   *      wrapping under the recovery key, whose halves are held by the server
   *      and the grantees. Leaving it behind meant a grantee could still wait
   *      out the period, release, and reconstruct the master key the user had
   *      been told was destroyed. The escrow therefore comes down here too.
   * The grantee keypair goes with it: its private half is wrapped under the key
   * being destroyed, so a published public key would only invite other owners
   * to seal shares nobody can ever open.
   *
   * Necessarily gated by session + step-up rather than by proof: you cannot
   * prove knowledge of a password you have lost. That makes this the one route
   * where stolen bearer tokens can destroy (never read) a vault; the
   * compensating controls are step-up freshness, this distinct audit action,
   * and owner notification when the notification port lands.
   */
  async reset(
    actorUserId: string,
    accountSessionId: string,
    payload: VaultKeysetPayload,
  ): Promise<{ itemsDestroyed: number }> {
    this.authz.assertCan(actorUserId, 'manage', vaultResource(actorUserId));
    const now = this.clock();

    const result = await this.db.withTransaction(actorUserId, async (tx) => {
      const existing = await this.keysets.lockByUser(tx, actorUserId);
      if (!existing) throw new NotFoundException({ error: 'keyset_not_found' });

      const itemsDestroyed = await this.items.softDeleteAllForUser(tx, actorUserId, now);
      await this.keysets.replace(tx, {
        userId: actorUserId,
        srpVerifier: Buffer.from(payload.srpVerifier, 'base64'),
        srpSalt: Buffer.from(payload.srpSalt, 'base64'),
        wrappedMasterKey: Buffer.from(payload.wrappedMasterKey, 'base64'),
        kdfParams: payload.kdfParams,
      });

      // The second wrapping, and the keypair that depends on the old key.
      const escrowRetired = await this.emergency.softDeleteAllForOwner(tx, actorUserId, now);
      await this.emergency.deleteConfig(tx, actorUserId);
      await this.keysets.clearRecoveryKeyPair(tx, actorUserId);

      const revoked = await this.sessions.revokeAllForUserExcept(tx, {
        userId: actorUserId,
        exceptId: null,
        reason: 'vault_reset',
        at: now,
      });
      return { itemsDestroyed, revoked, escrowRetired };
    });

    await this.events.reset(actorUserId, accountSessionId, {
      itemsDestroyed: result.itemsDestroyed,
      revokedSessions: result.revoked,
      escrowPoliciesRetired: result.escrowRetired,
    });
    return { itemsDestroyed: result.itemsDestroyed };
  }
}
