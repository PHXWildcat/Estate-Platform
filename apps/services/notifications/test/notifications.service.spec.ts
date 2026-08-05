import type { FieldCrypto } from '@estate/crypto';
import type { Queryable } from '../src/db';
import type { Db } from '../src/db';
import { StubEmailSender, type EmailSender } from '../src/email';
import { EventsService } from '../src/events.service';
import { NotificationsService } from '../src/notifications.service';
import type { RecipientsRepo, RecipientRow } from '../src/recipients.repo';
import type { SendsRepo } from '../src/sends.repo';

const USER = 'b6c9a1de-0000-4000-8000-000000000001';
const DEK = 'd0000000-0000-4000-8000-00000000000d';

interface Emitted {
  action: string;
  detail: unknown;
  onBehalfOf: string | null;
  resourceId: string | null;
}

function eventsDouble(): { events: EventsService; emitted: Emitted[] } {
  const emitted: Emitted[] = [];
  // Capture at the PRODUCER (send of the serialized record), so these tests
  // exercise the real AuditEmitter shape validation on every emitted event —
  // a malformed audit envelope fails the test, not just the type checker.
  const producer = {
    send: (record: { topic: string; key: string; value: string }): Promise<void> => {
      emitted.push(JSON.parse(record.value) as Emitted);
      return Promise.resolve();
    },
  };
  const events = new EventsService(producer, () => new Date('2026-08-04T00:00:00.000Z'));
  return { events, emitted };
}

function cryptoDouble(plaintextEmail: string): FieldCrypto {
  return {
    encryptField: (_userId: string, _field: string, plaintext: Buffer | string) =>
      Promise.resolve({
        ciphertext: Buffer.from(`ct:${String(plaintext)}`),
        dekId: DEK,
      }),
    decryptField: (input: { ciphertext: Buffer }) => {
      if (input.ciphertext.toString('utf8') === 'ct:SHREDDED') {
        return Promise.reject(new Error('DekDestroyedError'));
      }
      return Promise.resolve(Buffer.from(plaintextEmail, 'utf8'));
    },
  } as unknown as FieldCrypto;
}

function harness(options: { recipient: RecipientRow | null; email?: EmailSender }): {
  service: NotificationsService;
  emitted: Emitted[];
  recorded: Array<Record<string, unknown>>;
  stub: StubEmailSender;
  upserts: Array<{ userId: string; emailCt: Buffer; dekId: string }>;
} {
  const { events, emitted } = eventsDouble();
  const recorded: Array<Record<string, unknown>> = [];
  const upserts: Array<{ userId: string; emailCt: Buffer; dekId: string }> = [];
  const stub = new StubEmailSender();
  const db = {
    withTransaction: <T>(_actor: string, fn: (tx: Queryable) => Promise<T>): Promise<T> =>
      fn({ query: () => Promise.resolve([]) }),
  } as unknown as Db;
  const recipients = {
    find: () => Promise.resolve(options.recipient),
    upsert: (_tx: Queryable, input: { userId: string; emailCt: Buffer; dekId: string }) => {
      upserts.push(input);
      return Promise.resolve();
    },
  } as unknown as RecipientsRepo;
  const sends = {
    record: (input: Record<string, unknown>) => {
      recorded.push(input);
      return Promise.resolve('5e000000-0000-4000-8000-000000000005');
    },
  } as unknown as SendsRepo;
  const service = new NotificationsService(
    db,
    recipients,
    sends,
    events,
    cryptoDouble('owner@example.com'),
    options.email ?? stub,
  );
  return { service, emitted, recorded, stub, upserts };
}

const RECIPIENT: RecipientRow = {
  user_id: USER,
  email_ct: Buffer.from('ct:owner@example.com'),
  dek_id: DEK,
};

describe('NotificationsService.send', () => {
  it('decrypts the address, sends the rendered template, and records the send + audit', async () => {
    const { service, emitted, recorded, stub } = harness({ recipient: RECIPIENT });

    const result = await service.send({
      userId: USER,
      kind: 'settlement.case_opened',
      channel: 'push',
      deadline: '2026-08-09T00:00:00.000Z',
    });

    expect(result).toEqual({ delivered: true, channel: 'email' });
    expect(stub.sent).toHaveLength(1);
    expect(stub.sent[0]?.to).toBe('owner@example.com');
    expect(stub.sent[0]?.body).toContain('2026-08-09');
    expect(recorded[0]).toMatchObject({
      userId: USER,
      kind: 'settlement.case_opened',
      requestedChannel: 'push',
      channel: 'email',
      outcome: 'sent',
    });
    const sent = emitted.find((event) => event.action === 'notification.sent');
    expect(sent?.onBehalfOf).toBe(USER);
    expect(sent?.detail).toMatchObject({ outcome: 'sent', transport: 'stub' });
    // The audit stream never carries the address or the body.
    expect(JSON.stringify(emitted)).not.toContain('owner@example.com');
    expect(JSON.stringify(emitted)).not.toContain('report was filed');
  });

  it('records no_recipient when the store has no address — an outcome, not an error', async () => {
    const { service, recorded, stub } = harness({ recipient: null });

    const result = await service.send({
      userId: USER,
      kind: 'emergency.requested',
      channel: 'email',
    });

    expect(result).toEqual({ delivered: false, channel: 'email' });
    expect(stub.sent).toHaveLength(0);
    expect(recorded[0]).toMatchObject({ outcome: 'no_recipient', providerMessageId: null });
  });

  it('records carrier_failure when the carrier throws, and never surfaces the error', async () => {
    const failing: EmailSender = {
      transport: 'ses',
      deliversToRealChannels: true,
      send: () => Promise.reject(new Error('MessageRejected: owner@example.com')),
    };
    const { service, recorded, emitted } = harness({ recipient: RECIPIENT, email: failing });

    const result = await service.send({ userId: USER, kind: 'vault.reset', channel: 'email' });

    expect(result).toEqual({ delivered: false, channel: 'email' });
    expect(recorded[0]).toMatchObject({ outcome: 'carrier_failure' });
    expect(JSON.stringify(emitted)).not.toContain('owner@example.com');
  });

  it('treats a crypto-shredded recipient as carrier_failure — erasure means unreachable', async () => {
    const { service, recorded } = harness({
      recipient: { ...RECIPIENT, email_ct: Buffer.from('ct:SHREDDED') },
    });

    const result = await service.send({
      userId: USER,
      kind: 'emergency.released',
      channel: 'email',
    });

    expect(result).toEqual({ delivered: false, channel: 'email' });
    expect(recorded[0]).toMatchObject({ outcome: 'carrier_failure' });
  });
});

describe('NotificationsService.upsertRecipient', () => {
  it('encrypts under the user DEK, upserts, and audits without the address', async () => {
    const { service, emitted, upserts } = harness({ recipient: null });

    const result = await service.upsertRecipient({ userId: USER, email: 'owner@example.com' });

    expect(result).toEqual({ ok: true });
    expect(upserts[0]).toMatchObject({ userId: USER, dekId: DEK });
    expect(upserts[0]?.emailCt.toString('utf8')).toBe('ct:owner@example.com');
    const updated = emitted.find((event) => event.action === 'notification.recipient.updated');
    expect(updated?.onBehalfOf).toBe(USER);
    expect(updated?.detail).toEqual({});
    expect(JSON.stringify(emitted)).not.toContain('owner@example.com');
  });
});
