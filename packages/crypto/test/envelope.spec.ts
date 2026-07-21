import {
  FieldCrypto,
  type DecryptAuditEvent,
  type DekRecord,
  type DekRepository,
} from '../src/dek';
import {
  AuditEmitFailedError,
  DecryptionFailedError,
  DekDestroyedError,
  DekNotFoundError,
} from '../src/errors';
import { LocalKmsProvider } from '../src/kms';

class InMemoryDekRepository implements DekRepository {
  readonly records = new Map<string, DekRecord>();

  findActiveByUser(userId: string): Promise<DekRecord | null> {
    for (const r of this.records.values()) {
      if (r.userId === userId && r.destroyedAt === null) return Promise.resolve(r);
    }
    return Promise.resolve(null);
  }
  findById(dekId: string): Promise<DekRecord | null> {
    return Promise.resolve(this.records.get(dekId) ?? null);
  }
  insert(record: DekRecord): Promise<void> {
    this.records.set(record.dekId, record);
    return Promise.resolve();
  }
  markDestroyed(dekId: string, at: Date): Promise<void> {
    const r = this.records.get(dekId);
    if (r) r.destroyedAt = at;
    return Promise.resolve();
  }
}

const USER = '3b241101-e2bb-4255-8caf-4136c566a962';
const ACTOR = { actorId: '9f8b6c1d-0000-4000-8000-000000000001', actorType: 'service' as const };

function makeCrypto(auditSink?: (e: DecryptAuditEvent) => void | Promise<void>) {
  const kms = LocalKmsProvider.generate();
  const repo = new InMemoryDekRepository();
  const events: DecryptAuditEvent[] = [];
  const crypto = new FieldCrypto(kms, repo, auditSink ?? ((e) => void events.push(e)), {
    kekAlias: 'core-cluster',
  });
  return { crypto, repo, events };
}

describe('FieldCrypto envelope encryption', () => {
  it('round-trips a field and reuses the user DEK', async () => {
    const { crypto, repo } = makeCrypto();
    const a = await crypto.encryptField(USER, 'email', 'alice@example.com');
    const b = await crypto.encryptField(USER, 'phone', '+1-555-0100');
    expect(a.dekId).toBe(b.dekId); // one active DEK per user
    expect(repo.records.size).toBe(1);

    const pt = await crypto.decryptField({
      userId: USER,
      dekId: a.dekId,
      field: 'email',
      ciphertext: a.ciphertext,
      ...ACTOR,
      purpose: 'test',
    });
    expect(pt.toString('utf8')).toBe('alice@example.com');
  });

  it('gives different users different DEKs', async () => {
    const { crypto } = makeCrypto();
    const a = await crypto.encryptField(USER, 'email', 'a@example.com');
    const b = await crypto.encryptField(
      '7c9e6679-7425-40de-944b-e07fc1f90ae7',
      'email',
      'b@example.com',
    );
    expect(a.dekId).not.toBe(b.dekId);
  });

  it('emits an audit event on every decryption, with IDs only', async () => {
    const { crypto, events } = makeCrypto();
    const enc = await crypto.encryptField(USER, 'ssn', '000-00-0000');
    await crypto.decryptField({
      userId: USER,
      dekId: enc.dekId,
      field: 'ssn',
      ciphertext: enc.ciphertext,
      ...ACTOR,
      purpose: 'document.generation',
    });
    expect(events).toHaveLength(1);
    const evt = events[0]!;
    expect(evt).toMatchObject({
      action: 'crypto.field.decrypted',
      userId: USER,
      dekId: enc.dekId,
      field: 'ssn',
      purpose: 'document.generation',
      actorId: ACTOR.actorId,
      actorType: 'service',
    });
    // the audit event must never carry the value itself
    expect(JSON.stringify(evt)).not.toContain('000-00-0000');
  });

  it('fails CLOSED when the audit sink rejects: no plaintext released', async () => {
    const { crypto } = makeCrypto(() => {
      throw new Error('kafka down');
    });
    const enc = await crypto.encryptField(USER, 'email', 'alice@example.com');
    await expect(
      crypto.decryptField({
        userId: USER,
        dekId: enc.dekId,
        field: 'email',
        ciphertext: enc.ciphertext,
        ...ACTOR,
        purpose: 'test',
      }),
    ).rejects.toThrow(AuditEmitFailedError);
  });

  it('binds ciphertext to its field: a swapped column fails to decrypt', async () => {
    const { crypto } = makeCrypto();
    const enc = await crypto.encryptField(USER, 'email', 'alice@example.com');
    await expect(
      crypto.decryptField({
        userId: USER,
        dekId: enc.dekId,
        field: 'notes', // attacker moved the ciphertext to another column
        ciphertext: enc.ciphertext,
        ...ACTOR,
        purpose: 'test',
      }),
    ).rejects.toThrow(DecryptionFailedError);
  });

  it('binds ciphertext to its user: a cross-tenant splice fails to decrypt', async () => {
    const { crypto } = makeCrypto();
    const enc = await crypto.encryptField(USER, 'email', 'alice@example.com');
    await expect(
      crypto.decryptField({
        userId: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
        dekId: enc.dekId,
        field: 'email',
        ciphertext: enc.ciphertext,
        ...ACTOR,
        purpose: 'test',
      }),
    ).rejects.toThrow(DecryptionFailedError);
  });

  it('crypto-shredding makes ciphertext permanently irrecoverable', async () => {
    const { crypto } = makeCrypto();
    const enc = await crypto.encryptField(USER, 'email', 'alice@example.com');
    await crypto.destroyDek(enc.dekId);
    await expect(
      crypto.decryptField({
        userId: USER,
        dekId: enc.dekId,
        field: 'email',
        ciphertext: enc.ciphertext,
        ...ACTOR,
        purpose: 'test',
      }),
    ).rejects.toThrow(DekDestroyedError);
    // a destroyed DEK is also no longer the user's active key
    const next = await crypto.encryptField(USER, 'email', 'alice@example.com');
    expect(next.dekId).not.toBe(enc.dekId);
  });

  it('rejects an unknown DEK id', async () => {
    const { crypto } = makeCrypto();
    await expect(
      crypto.decryptField({
        userId: USER,
        dekId: '00000000-0000-4000-8000-000000000000',
        field: 'email',
        ciphertext: Buffer.from('junk'),
        ...ACTOR,
        purpose: 'test',
      }),
    ).rejects.toThrow(DekNotFoundError);
  });
});
