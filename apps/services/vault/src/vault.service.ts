import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
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
import { CLOCK, NOTIFIER, type Clock } from './di-tokens';
import { Db, isUniqueViolation, type Queryable } from './db';
import type { NotificationPort } from './notifications';
import { EmergencyRepo } from './emergency.repo';
import { EventsService } from './events.service';
import { HandshakesRepo } from './handshakes.repo';
import { ItemsRepo, RESTORABLE_REASONS, type ItemRow, type VersionRow } from './items.repo';
import { KeysetsRepo } from './keysets.repo';
import { VaultSessionsRepo } from './sessions.repo';
import { VaultAuthz, vaultItemResource, vaultResource } from './authz.service';
import { generateOpaqueToken, hashToken } from './tokens';
import type { VaultSessionContext } from './vault-session.guard';
import { UuidSchema, type VaultItemType } from './schemas';

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
  /**
   * The version the blob is SEALED AGAINST. A client decrypts with this and
   * re-seals against `blobVersion + 1`; it is not the concurrency token and a
   * restore can move it backwards (migration 005).
   */
  readonly blobVersion: number;
  /** The concurrency token. This is what `If-Match` carries. */
  readonly revision: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface VaultItemPage {
  readonly items: readonly VaultItemDto[];
  readonly nextCursor: string | null;
}

/**
 * One prior version of an item, as a client receives it (M27 PR1b).
 *
 * `blob` and `blobVersion` travel together for the same reason they do on
 * `VaultItemDto`: the version is inside the AAD, so ciphertext handed over at
 * any other number is ciphertext that will never open. `revision` is the
 * HANDLE — what a restore names — and is per-item, never the shadow table's
 * `version_seq`, which is a platform-wide sequential id and stays server-side.
 */
export interface VaultVersionDto {
  readonly revision: number;
  readonly itemType: VaultItemType;
  readonly blob: string;
  readonly blobVersion: number;
  readonly versionedAt: string;
}

export interface VaultVersionPage {
  readonly versions: readonly VaultVersionDto[];
  readonly nextCursor: string | null;
}

function toVersionDto(row: VersionRow): VaultVersionDto {
  return {
    revision: row.revision,
    itemType: row.item_type,
    blob: row.blob_ct.toString('base64'),
    blobVersion: row.blob_version,
    versionedAt: row.versioned_at.toISOString(),
  };
}

/**
 * THE CAPTURED IMAGE AND THE LIVE ROW MUST NAME THE SAME OWNER, and a
 * disagreement RAISES rather than filtering (M27 PR1b).
 *
 * The reader drives from the live row and reaches the shadow table by
 * `row_id`, which is sound while an item id names one item forever. Item ids
 * are CLIENT-SUPPLIED, though, so the pairing is only as durable as the
 * guarantee that a row is never removed and its id never reissued. Today no
 * hard delete exists on `vault_items` and this can never fire.
 *
 * It throws instead of dropping the row precisely BECAUSE it cannot fire: a
 * silent filter would turn the day that guarantee breaks into a restore
 * surface quietly showing fewer versions, whereas this turns it into a loud
 * failure on the request that first sees it. It is the invariant a future
 * erasure path has to preserve, stated where that path will run into it.
 */
function assertImageOwners(rows: readonly VersionRow[], userId: string): void {
  for (const row of rows) {
    if (row.image_user_id !== userId) {
      throw new InternalServerErrorException({ error: 'version_owner_mismatch' });
    }
  }
}

/**
 * EXPORTED FOR THE GRANTEE READER (M27 PR3b). `emergency.service.ts` serves the
 * owner's items to a released grantee and must hand back the same shape on the
 * same cursor grammar — a second mapper and a second codec would be two things
 * to keep in step, and the cursor pair in particular could disagree about a
 * malformed value while looking identical.
 */
export function toDto(row: ItemRow): VaultItemDto {
  return {
    id: row.id,
    itemType: row.item_type,
    blob: row.blob_ct.toString('base64'),
    blobVersion: row.blob_version,
    revision: row.revision,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

/**
 * BOTH keyset cursors are `<iso timestamp>|<uuid>` and differ only in WHICH
 * timestamp they carry — `updated_at` for the live list, `deleted_at` for the
 * restorable one (M27 PR1b). One encoder and one parser rather than a near-copy
 * per list: a second parser is a second thing to get wrong, and the two could
 * disagree about a malformed cursor while looking identical.
 */
export function encodeCursor(at: Date, id: string): string {
  return Buffer.from(`${at.toISOString()}|${id}`, 'utf8').toString('base64url');
}

export function decodeCursor(cursor: string): { at: Date; id: string } {
  const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  const separator = decoded.lastIndexOf('|');
  if (separator <= 0) throw new ConflictException({ error: 'invalid_cursor' });
  const at = new Date(decoded.slice(0, separator));
  const id = decoded.slice(separator + 1);
  /*
   * BOTH HALVES, NOT JUST THE TIMESTAMP (M27 PR3b review).
   *
   * `id.length === 0` was the only check on the id, so a cursor of the shape
   * `<valid ISO>|zzz` decoded happily and reached the repo, where the
   * parameter binds against a `uuid` column and Postgres raises 22P02. That
   * leaves the filter with a non-HttpException and the caller gets 500
   * `internal_error` — an OUTAGE's face on a malformed input, and the one
   * answer this function exists to make impossible. Every other malformed
   * cursor already answered `invalid_cursor`; this one arm did not.
   *
   * `UuidSchema.safeParse` rather than a local regex, so the cursor's idea of
   * an id and the routes' idea of an id cannot drift apart.
   */
  if (Number.isNaN(at.getTime()) || !UuidSchema.safeParse(id).success) {
    throw new ConflictException({ error: 'invalid_cursor' });
  }
  return { at, id };
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
    @Inject(NOTIFIER) private readonly notifier: NotificationPort,
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
      ...(query.cursor
        ? { cursor: ((c) => ({ updatedAt: c.at, id: c.id }))(decodeCursor(query.cursor)) }
        : {}),
    });

    await this.events.itemsListed(actorUserId, accountSessionId, rows.length, 'live');
    const last = rows.length === query.limit ? rows[rows.length - 1] : undefined;
    return {
      items: rows.map(toDto),
      nextCursor: last ? encodeCursor(last.updated_at, last.id) : null,
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
    const row = await this.items.findLiveById(this.db, actorUserId, itemId);
    if (!row) throw new NotFoundException({ error: 'not_found' });
    this.authz.assertCan(actorUserId, 'read', vaultItemResource(itemId, row.user_id));

    await this.events.itemAccessed(actorUserId, accountSessionId, itemId);
    return toDto(row);
  }

  /**
   * Update an item.
   *
   * TWO NUMBERS, TWO JOBS, and M27 PR1a split them because one value could not
   * hold both. `If-Match` carries `revision` — the trigger-maintained counter
   * that never repeats — and that is what decides whether this write races
   * another. `blob_version` is the AEAD binding: the client sealed the new blob
   * against `blob_version + 1`, so the server MUST store exactly that or the
   * item stops decrypting.
   *
   * Equality on `revision` is a sound change detector because the schema, not a
   * convention at this call site, guarantees the value is never reused. It was
   * NOT sound on `blob_version`: M27's version restore puts a captured version
   * back, so a row could return to a number a client still held and a stale
   * write would pass this check with no conflict and silently overwrite the
   * restore. Migration 005 carries the demonstration.
   */
  async updateItem(
    actorUserId: string,
    accountSessionId: string,
    itemId: string,
    ifMatch: number,
    input: { itemType: VaultItemType; blob: string },
  ): Promise<VaultItemDto> {
    const row = await this.db.withTransaction(actorUserId, async (tx) => {
      const locked = await this.items.lockLiveById(tx, actorUserId, itemId);
      if (!locked) throw new NotFoundException({ error: 'not_found' });
      this.authz.assertCan(actorUserId, 'update', vaultItemResource(itemId, locked.user_id));
      if (locked.revision !== ifMatch) {
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

  /**
   * PRIOR VERSIONS OF ONE ITEM (M27 PR1b).
   *
   * The reader drives from the live row with ownership fused, so a caller who
   * does not own the item and a caller naming an item that does not exist get
   * the SAME 404 — and the shadow table, which has no `user_id` column of its
   * own, is never reached with an id the caller has not been proven to own.
   */
  async listItemVersions(
    actorUserId: string,
    accountSessionId: string,
    itemId: string,
    input: { limit: number; cursor?: number | undefined },
  ): Promise<VaultVersionPage> {
    this.authz.assertCan(actorUserId, 'read_history', vaultItemResource(itemId, actorUserId));

    // Existence is asked FIRST and separately, because the row-returning query
    // cannot tell "not yours" from "yours with no history": both are zero rows.
    // Answering 404 for the second would tell an owner their own item is gone.
    const owned = await this.items.existsForOwner(this.db, actorUserId, itemId);
    if (!owned) throw new NotFoundException({ error: 'not_found' });

    const rows = await this.items.listVersions(this.db, {
      userId: actorUserId,
      itemId,
      limit: input.limit + 1,
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
    });
    assertImageOwners(rows, actorUserId);

    const page = rows.slice(0, input.limit);
    const next = rows.length > input.limit ? (page[page.length - 1]?.revision ?? null) : null;

    // A version read is a DISCLOSURE of ciphertext the caller had already
    // stopped holding, so it is recorded on the same terms as `getItem`.
    await this.events.itemAccessed(actorUserId, accountSessionId, itemId);
    return {
      versions: page.map(toVersionDto),
      nextCursor: next === null ? null : String(next),
    };
  }

  /**
   * The retired items a restore surface may offer (M27 PR1b).
   *
   * Keyed on `RESTORABLE_REASONS`, which is DERIVED from `REASON_DISPOSITION`'s
   * total map rather than listed here. A row retired by `vault_reset` is absent
   * because its blob is cryptographically dead — offering it would produce an
   * AEAD failure on click, which is a control firing wearing the face of an
   * outage.
   *
   * IT RECORDS, BECAUSE IT DISCLOSES. Every row here carries `blob_ct` in full,
   * exactly as `listItems` does, so this route is a bulk ciphertext read and
   * belongs in the audit trail on the same terms as its sibling — the fact that
   * the items are deleted makes the read MORE interesting to an investigator,
   * not less. That is why `accountSessionId` is a parameter: without it the
   * event could not be attributed to a session and the omission would be
   * structural rather than a choice.
   */
  async listRestorableItems(
    actorUserId: string,
    accountSessionId: string,
    query: { limit: number; cursor?: string | undefined },
  ): Promise<VaultItemPage> {
    this.authz.assertCan(actorUserId, 'read_history', vaultResource(actorUserId));

    const rows = await this.items.listRestorable(this.db, {
      userId: actorUserId,
      restorable: RESTORABLE_REASONS,
      // One more than asked for, so "is there a next page" is answered by the
      // rows themselves rather than by `rows.length === limit`, which cannot
      // tell a full last page from a full page with more behind it.
      limit: query.limit + 1,
      ...(query.cursor
        ? { cursor: ((c) => ({ deletedAt: c.at, id: c.id }))(decodeCursor(query.cursor)) }
        : {}),
    });
    const page = rows.slice(0, query.limit);
    const last = page[page.length - 1];

    await this.events.itemsListed(actorUserId, accountSessionId, page.length, 'restorable');
    return {
      items: page.map(toDto),
      nextCursor:
        rows.length > query.limit && last?.deleted_at
          ? encodeCursor(last.deleted_at, last.id)
          : null,
    };
  }

  /**
   * Bring a retired item back (M27 PR1b).
   *
   * THREE ANSWERS FROM ONE LOCKED READ, because they need three different
   * remedies and must not share a token: an item that is not yours or not there
   * is a uniform 404; an item already live is a success that changed nothing
   * and emits no event; an item whose blob the keyset outlived is
   * `item_unrestorable`, which is neither a 404 (the row is there and the owner
   * can see it) nor a 500 (nothing failed).
   *
   * NO `If-Match`. Undelete writes no content and cannot lose an update — there
   * is nothing to overwrite on a retired row — and gating recovery behind a
   * token the caller would have to fetch first makes the protective action
   * harder than the permissive one, which is the rule this milestone exists to
   * honour rather than invert.
   */
  async undeleteItem(
    actorUserId: string,
    accountSessionId: string,
    itemId: string,
  ): Promise<VaultItemDto> {
    const outcome = await this.db.withTransaction(actorUserId, async (tx) => {
      const locked = await this.items.lockAnyById(tx, actorUserId, itemId);
      if (!locked) throw new NotFoundException({ error: 'not_found' });
      this.authz.assertCan(actorUserId, 'undelete', vaultItemResource(itemId, locked.user_id));
      if (locked.deleted_at === null) return { row: locked, changed: false };

      const restored = await this.items.undelete(tx, {
        id: itemId,
        userId: actorUserId,
        restorable: RESTORABLE_REASONS,
      });
      // The statement restates the restorable set in its own WHERE, so a reset
      // that landed between the lock and the write is refused here rather than
      // silently reviving a dead blob.
      if (!restored) throw new ConflictException({ error: 'item_unrestorable' });
      return { row: restored, changed: true };
    });

    if (outcome.changed) {
      await this.events.itemRestored(actorUserId, accountSessionId, itemId, {
        kind: 'undelete',
        revision: outcome.row.revision,
      });
    }
    return toDto(outcome.row);
  }

  /**
   * Put a prior version of a LIVE item back (M27 PR1b).
   *
   * This is the shape that answers `packages/auth-guard/src/session.ts`, whose
   * refusal of `deleteItem` to the extension audience rests on an overwrite
   * being "recoverable". An extension can overwrite every item and cannot
   * delete one, so the recovery that argument needs is this verb specifically —
   * undelete would not touch it.
   *
   * `If-Match` IS required here, and against `revision`: this overwrites live
   * content, so it is exactly the operation a stale writer can lose an update
   * through. The restored `blob_version` may move DOWN and that is not a
   * conflict — since migration 005 the two numbers are different jobs.
   */
  async restoreItemVersion(
    actorUserId: string,
    accountSessionId: string,
    itemId: string,
    input: { revision: number; ifMatch: number },
  ): Promise<VaultItemDto> {
    const row = await this.db.withTransaction(actorUserId, async (tx) => {
      const locked = await this.items.lockLiveById(tx, actorUserId, itemId);
      if (!locked) throw new NotFoundException({ error: 'not_found' });
      this.authz.assertCan(actorUserId, 'restore', vaultItemResource(itemId, locked.user_id));
      if (locked.revision !== input.ifMatch) {
        throw new ConflictException({ error: 'version_conflict' });
      }
      if (locked.revision === input.revision) {
        // Restoring the version you are already at is not an error, but it must
        // not be a WRITE either: it would burn a revision and capture an image
        // for a change that did not happen.
        return locked;
      }
      const restored = await this.items.restoreVersion(tx, {
        id: itemId,
        userId: actorUserId,
        revision: input.revision,
      });
      // No such image for this item, or an image the reader would not offer.
      if (!restored) throw new NotFoundException({ error: 'version_not_found' });
      return restored;
    });

    if (row.revision !== input.ifMatch) {
      await this.events.itemRestored(actorUserId, accountSessionId, itemId, {
        kind: 'version',
        fromRevision: input.revision,
        revision: row.revision,
        blobVersion: row.blob_version,
      });
    }
    return toDto(row);
  }

  async deleteItem(actorUserId: string, accountSessionId: string, itemId: string): Promise<void> {
    const now = this.clock();
    await this.db.withTransaction(actorUserId, async (tx) => {
      const locked = await this.items.lockLiveById(tx, actorUserId, itemId);
      if (!locked) throw new NotFoundException({ error: 'not_found' });
      this.authz.assertCan(actorUserId, 'delete', vaultItemResource(itemId, locked.user_id));
      // 'user_delete': the keyset is untouched by this route, so the blob stays
      // openable and the row is restorable (migration 004, docs/03 §6uu).
      await this.items.softDelete(tx, itemId, now, 'user_delete');
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

      // 'vault_reset': the keyset is REPLACED just below, in this same
      // transaction, so every blob this touches is cryptographically dead. This
      // is the discriminator's whole reason for existing — the stamp is
      // byte-identical to `deleteItem`'s and means the opposite thing.
      //
      // ONE CALL COVERS BOTH POPULATIONS, and it has to. Rows the owner had
      // ALREADY deleted before this reset keep `deleted_reason = 'user_delete'`
      // unless something relabels them, and their blobs die here exactly as
      // dead as the live ones — the column would still say restorable, and
      // PR1b's list believes the column. Splitting that into two statements
      // reintroduces a window `undeleteItem` can run in; see the repo method.
      const { destroyed: itemsDestroyed, relabelled: itemsRelabelled } =
        await this.items.retireAllForUser(tx, actorUserId, now, 'vault_reset');
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
      return { itemsDestroyed, itemsRelabelled, revoked, escrowRetired };
    });

    await this.events.reset(actorUserId, accountSessionId, {
      itemsDestroyed: result.itemsDestroyed,
      itemsRelabelled: result.itemsRelabelled,
      revokedSessions: result.revoked,
      escrowPoliciesRetired: result.escrowRetired,
    });
    // The compensating control this route's docstring promised "when the
    // notification port lands" (M9): the owner is TOLD their vault was
    // destroyed. Best-effort with the standard bookkeeping — a failed send
    // records delivered_at null and never unwinds the reset.
    //
    // READ THE OUTCOME. M14 changed `notify()` from throwing on non-delivery to
    // returning one, and updated every call site except this one — so for a
    // while this `catch` was unreachable and `deliveredAt` was stamped
    // unconditionally: EVERY reset recorded its notification as delivered, even
    // when notifications were down or the user had no recipient row. On the one
    // route where a bearer token destroys a Zone A vault, the only compensating
    // control the docstring names was asserting something false. Found by the
    // M14 security review; the sibling site in emergency.service.ts had been
    // updated correctly, so the two disagreed.
    let deliveredAt: Date | null = null;
    let recipientVerified = false;
    try {
      const outcome = await this.notifier.notify({
        kind: 'reset',
        ownerUserId: actorUserId,
        policyId: null,
      });
      deliveredAt = outcome.delivered ? this.clock() : null;
      recipientVerified = outcome.recipientVerified;
    } catch {
      // The port narrows failures to outcomes now, so reaching here means an
      // adapter broke its own contract. Recorded as a non-delivery either way.
    }
    await this.emergency.recordNotification(this.db, {
      policyId: null,
      userId: actorUserId,
      kind: 'reset',
      channel: this.notifier.channel,
      deliveredAt,
    });
    // ...and the same PROCEED-AND-RECORD fact every other notification carries
    // (M14 PR2). Reset was the one path that could never emit it, because it
    // discarded the outcome — so a vault destroyed and "announced" to an
    // unproved address left no evidence of that anywhere.
    if (deliveredAt !== null && !recipientVerified) {
      await this.events.audit.emit({
        action: 'vault.emergency.unverified_recipient',
        actorId: null,
        actorType: 'system',
        onBehalfOf: actorUserId,
        resourceType: 'vault',
        resourceId: null,
        sessionId: accountSessionId,
        detail: { kind: 'reset' },
      });
    }
    return { itemsDestroyed: result.itemsDestroyed };
  }
}
