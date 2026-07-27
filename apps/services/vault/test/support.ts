import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import {
  createVaultEnrollment,
  decodeGroupElement,
  encodeGroupElement,
  finishUnlock,
  MIN_ITERATIONS,
  prepareUnlock,
  proveUnlock,
  toBase64,
  type VaultKeysetPayload,
} from '@estate/vault-crypto';
import { EventsService } from '../src/events.service';
import type { Queryable } from '../src/db';
import type { VaultSessionContext } from '../src/vault-session.guard';

/** The floor rather than the default: unit tests derive keys for real. */
export const TEST_ITERATIONS = MIN_ITERATIONS;

export class MemoryProducer implements AuditProducer {
  readonly messages: Array<{ topic: string; key: string; value: string }> = [];

  send(message: { topic: string; key: string; value: string }): Promise<void> {
    this.messages.push(message);
    return Promise.resolve();
  }
}

export interface CapturedEvents {
  readonly events: EventsService;
  readonly producer: MemoryProducer;
  actions(): string[];
  payloads(): string;
}

export function capturingEvents(now = new Date('2026-07-25T12:00:00.000Z')): CapturedEvents {
  const producer = new MemoryProducer();
  const events = new EventsService(producer, () => now);
  return {
    events,
    producer,
    actions: (): string[] =>
      producer.messages.map((m) => (JSON.parse(m.value) as { action: string }).action),
    payloads: (): string => producer.messages.map((m) => m.value).join('\n'),
  };
}

export function auditEmitter(producer: AuditProducer, now = new Date()): AuditEmitter {
  return new AuditEmitter(producer, () => now);
}

/**
 * A query surface that refuses raw SQL. Unit tests exercise service logic
 * against fakes; anything that reaches for the database here is a test that
 * belongs in the integration suite.
 */
export function fakeDb(): Queryable {
  return {
    query: (): Promise<never[]> => {
      throw new Error('unit tests must not issue raw SQL');
    },
  };
}

export function vaultSession(overrides: Partial<VaultSessionContext> = {}): VaultSessionContext {
  return {
    id: '1f2e3d4c-5b6a-4978-8869-0a1b2c3d4e5f',
    userId: 'd0b3a1c2-3e4f-4a5b-8c7d-9e0f1a2b3c4d',
    accountSessionId: 'aa11bb22-cc33-4d44-8e55-ff6677889900',
    keysetAuthKey: Buffer.alloc(32, 7),
    expiresAt: new Date('2026-07-25T12:15:00.000Z'),
    ...overrides,
  };
}

/**
 * A complete enrollment, ready to hand to the service. Uses the real client
 * crypto so tests exercise the same payloads a browser would produce.
 */
export async function enrollmentFor(
  userId: string,
  password = 'a long enough vault password',
): Promise<{ payload: VaultKeysetPayload; secretKey: string; masterKey: CryptoKey }> {
  const { enrollment, masterKey } = await createVaultEnrollment({
    userId,
    password,
    iterations: TEST_ITERATIONS,
  });
  return { payload: enrollment.payload, secretKey: enrollment.secretKey, masterKey };
}

/**
 * Drive a full SRP unlock against the running service, exactly as a client
 * would: start, derive locally, prove, verify the server back.
 */
export async function unlockVault(input: {
  userId: string;
  password: string;
  secretKey: string;
  start: () => Promise<{
    handshakeId: string;
    srpSalt: string;
    kdfParams: unknown;
    serverPublic: string;
  }>;
  verify: (body: {
    handshakeId: string;
    clientPublic: string;
    clientProof: string;
  }) => Promise<{ serverProof: string; wrappedMasterKey: string; vaultSessionId: string }>;
}): Promise<{ masterKey: CryptoKey; keysetAuthKey: Uint8Array }> {
  const challenge = await input.start();
  const preparation = await prepareUnlock({
    userId: input.userId,
    password: input.password,
    secretKey: input.secretKey,
    kdfParams: challenge.kdfParams,
    srpSalt: challenge.srpSalt,
  });
  const { m1, session } = await proveUnlock(preparation, challenge.serverPublic);

  const opened = await input.verify({
    handshakeId: challenge.handshakeId,
    clientPublic: preparation.publicA,
    clientProof: m1,
  });

  return finishUnlock({
    preparation,
    session,
    serverM2: opened.serverProof,
    wrappedMasterKey: opened.wrappedMasterKey,
    vaultSessionId: opened.vaultSessionId,
  });
}

/** Re-exported so specs do not each reach into @estate/vault-crypto. */
export { decodeGroupElement, encodeGroupElement, toBase64 };
