import { randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { InternalController } from '../src/internal.controller';
import type { NotificationsService } from '../src/notifications.service';

/**
 * The controller is a thin parse-then-delegate layer; what is worth pinning is
 * exactly that thinness: a malformed body is refused BEFORE the service runs
 * (the refusal never echoes the payload — it may carry an address), and a
 * valid one reaches the service verbatim. The credential guard itself is
 * proven in the auth-guard suite and on the live stack.
 */
describe('InternalController', () => {
  const build = (): {
    controller: InternalController;
    calls: { send: unknown[]; upsert: unknown[] };
  } => {
    const calls: { send: unknown[]; upsert: unknown[] } = { send: [], upsert: [] };
    const service = {
      send: (input: unknown): Promise<{ delivered: boolean; channel: string }> => {
        calls.send.push(input);
        return Promise.resolve({ delivered: true, channel: 'email' });
      },
      upsertRecipient: (input: unknown): Promise<{ ok: true }> => {
        calls.upsert.push(input);
        return Promise.resolve({ ok: true });
      },
    } as unknown as NotificationsService;
    return { controller: new InternalController(service), calls };
  };

  it('send: parses the content-free wire and delegates', async () => {
    const { controller, calls } = build();
    const userId = randomUUID();
    const body = { userId, kind: 'settlement.case_opened', channel: 'email' };
    await expect(controller.send(body)).resolves.toEqual({ delivered: true, channel: 'email' });
    expect(calls.send).toEqual([body]);
  });

  it('send: a smuggled content field is refused before the service runs', () => {
    const { controller, calls } = build();
    // parseBody throws synchronously — the service is never even scheduled.
    expect(() =>
      controller.send({
        userId: randomUUID(),
        kind: 'settlement.case_opened',
        channel: 'email',
        subject: 'attacker words',
      }),
    ).toThrow(BadRequestException);
    expect(calls.send).toEqual([]);
  });

  it('upsertRecipient: parses and delegates', async () => {
    const { controller, calls } = build();
    const body = { userId: randomUUID(), email: 'owner@example.com' };
    await expect(controller.upsertRecipient(body)).resolves.toEqual({ ok: true });
    expect(calls.upsert).toEqual([body]);
  });

  it('upsertRecipient: refuses a malformed address without echoing it', async () => {
    const { controller, calls } = build();
    try {
      await controller.upsertRecipient({ userId: randomUUID(), email: 'not-an-address' });
      throw new Error('expected BadRequestException');
    } catch (err) {
      expect(err).toBeInstanceOf(BadRequestException);
      expect(JSON.stringify((err as BadRequestException).getResponse())).not.toContain(
        'not-an-address',
      );
    }
    expect(calls.upsert).toEqual([]);
  });
});
