import { randomUUID } from 'node:crypto';
import { open, seal } from './aead';
import {
  AuditEmitFailedError,
  DekConflictError,
  DekDestroyedError,
  DekNotFoundError,
} from './errors';
import type { KmsKeyProvider } from './kms';

/** A wrapped per-user data key, as persisted in each cluster's `deks` table. */
export interface DekRecord {
  dekId: string;
  userId: string;
  kekAlias: string;
  wrappedKey: Buffer;
  createdAt: Date;
  /** Non-null ⇒ crypto-shredded: legal erasure per docs/02 conventions. */
  destroyedAt: Date | null;
}

/** Storage boundary — each service persists DEK rows in its own cluster. */
export interface DekRepository {
  findActiveByUser(userId: string): Promise<DekRecord | null>;
  findById(dekId: string): Promise<DekRecord | null>;
  insert(record: DekRecord): Promise<void>;
  /** Crypto-shredding: only a privileged retention job may call this. */
  markDestroyed(dekId: string, at: Date): Promise<void>;
}

export type ActorType = 'user' | 'service' | 'operator' | 'system';

/** What gets audited on every field decryption. IDs and enums only — no values. */
export interface DecryptAuditEvent {
  action: 'crypto.field.decrypted';
  userId: string;
  dekId: string;
  field: string;
  purpose: string;
  actorId: string;
  actorType: ActorType;
}

/**
 * Sink for decryption audit events. FieldCrypto fails CLOSED on sink errors:
 * if the audit event cannot be emitted, the plaintext is withheld.
 */
export type DecryptAuditSink = (event: DecryptAuditEvent) => void | Promise<void>;

export interface FieldCryptoOptions {
  kekAlias: string;
  /** Unwrapped-DEK cache TTL. Short by design; unwraps are the KMS audit signal. */
  dekCacheTtlMs?: number;
  dekCacheMaxSize?: number;
}

interface CacheEntry {
  key: Buffer;
  expiresAt: number;
}

/**
 * Per-user envelope encryption for Zone B fields (docs/01 §4, docs/02
 * conventions). Every decryption emits an audit event before plaintext is
 * released — this is structural, not a convention callers can forget.
 */
export class FieldCrypto {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly ttlMs: number;
  private readonly maxSize: number;

  constructor(
    private readonly kms: KmsKeyProvider,
    private readonly deks: DekRepository,
    private readonly auditSink: DecryptAuditSink,
    private readonly options: FieldCryptoOptions,
  ) {
    this.ttlMs = options.dekCacheTtlMs ?? 5 * 60 * 1000;
    this.maxSize = options.dekCacheMaxSize ?? 1000;
  }

  /** Returns the user's active DEK id, creating (and persisting) one if needed. */
  async getOrCreateDek(userId: string): Promise<string> {
    const existing = await this.deks.findActiveByUser(userId);
    if (existing) {
      return existing.dekId;
    }
    const { plaintextKey, wrappedKey } = await this.kms.generateDataKey(this.options.kekAlias);
    const record: DekRecord = {
      dekId: randomUUID(),
      userId,
      kekAlias: this.options.kekAlias,
      wrappedKey,
      createdAt: new Date(),
      destroyedAt: null,
    };
    try {
      await this.deks.insert(record);
    } catch (err) {
      if (err instanceof DekConflictError) {
        // A concurrent request won the insert. Discard our minted key and
        // adopt the winner's DEK so the user never ends up with two.
        plaintextKey.fill(0);
        const winner = await this.deks.findActiveByUser(userId);
        if (!winner) {
          // Conflict but no active row: the winner was destroyed in between.
          throw new DekNotFoundError();
        }
        return winner.dekId;
      }
      throw err;
    }
    this.cacheKey(record.dekId, plaintextKey);
    return record.dekId;
  }

  /** Encrypt a field value under the user's active DEK. */
  async encryptField(
    userId: string,
    field: string,
    plaintext: Buffer | string,
  ): Promise<{ ciphertext: Buffer; dekId: string }> {
    const dekId = await this.getOrCreateDek(userId);
    const record = await this.requireActiveDek(dekId);
    const key = await this.unwrap(record);
    const pt = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
    return { ciphertext: seal(key, pt, fieldAad(userId, field)), dekId };
  }

  /**
   * Decrypt a field value. Order of operations is a security invariant:
   *  1. resolve the DEK (destroyed ⇒ DekDestroyedError — the value is erased);
   *  2. decrypt;
   *  3. emit the audit event; if the sink rejects, plaintext is zeroed and
   *     withheld (fail closed).
   */
  async decryptField(input: {
    userId: string;
    dekId: string;
    field: string;
    ciphertext: Buffer;
    actorId: string;
    actorType: ActorType;
    purpose: string;
  }): Promise<Buffer> {
    const record = await this.requireActiveDek(input.dekId);
    const key = await this.unwrap(record);
    const plaintext = open(key, input.ciphertext, fieldAad(input.userId, input.field));
    try {
      await this.auditSink({
        action: 'crypto.field.decrypted',
        userId: input.userId,
        dekId: input.dekId,
        field: input.field,
        purpose: input.purpose,
        actorId: input.actorId,
        actorType: input.actorType,
      });
    } catch {
      plaintext.fill(0); // best-effort zeroization before the buffer is dropped
      throw new AuditEmitFailedError();
    }
    return plaintext;
  }

  /**
   * Crypto-shredding entry point (legal erasure). After this resolves, every
   * ciphertext under this DEK is permanently irrecoverable.
   */
  async destroyDek(dekId: string): Promise<void> {
    await this.deks.markDestroyed(dekId, new Date());
    const entry = this.cache.get(dekId);
    if (entry) {
      entry.key.fill(0);
      this.cache.delete(dekId);
    }
  }

  private async requireActiveDek(dekId: string): Promise<DekRecord> {
    const record = await this.deks.findById(dekId);
    if (!record) {
      throw new DekNotFoundError();
    }
    if (record.destroyedAt !== null) {
      throw new DekDestroyedError();
    }
    return record;
  }

  private async unwrap(record: DekRecord): Promise<Buffer> {
    const cached = this.cache.get(record.dekId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.key;
    }
    const key = await this.kms.unwrapDataKey(record.kekAlias, record.wrappedKey);
    this.cacheKey(record.dekId, key);
    return key;
  }

  private cacheKey(dekId: string, key: Buffer): void {
    if (this.cache.size >= this.maxSize) {
      // Evict the oldest entry (Map preserves insertion order).
      const oldest = this.cache.keys().next();
      if (!oldest.done) {
        this.cache.get(oldest.value)?.key.fill(0);
        this.cache.delete(oldest.value);
      }
    }
    this.cache.set(dekId, { key, expiresAt: Date.now() + this.ttlMs });
  }
}

function fieldAad(userId: string, field: string): Buffer {
  return Buffer.from(`estate.field.v1|${userId}|${field}`, 'utf8');
}
