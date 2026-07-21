import { FieldCrypto, LocalKmsProvider, type DekRecord, type DekRepository } from '@estate/crypto';
import { FieldCipher } from '../src/field-cipher';

/** In-memory DekRepository for the real FieldCrypto (no Postgres needed). */
export class MemoryDeks implements DekRepository {
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

/** A real FieldCipher over a real FieldCrypto with an in-memory DEK store. */
export function buildCipher(): FieldCipher {
  const crypto = new FieldCrypto(LocalKmsProvider.generate(), new MemoryDeks(), () => undefined, {
    kekAlias: 'core/kek',
  });
  return new FieldCipher(crypto);
}

/** No-op events double capturing nothing (services under test don't assert on it). */
export const noopEvents = new Proxy(
  {},
  { get: () => (): Promise<void> => Promise.resolve() },
) as never;
