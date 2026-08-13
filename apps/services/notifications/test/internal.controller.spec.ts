import { randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import {
  InternalController,
  RecipientStatusController,
  RecipientsController,
  EmailChangeController,
  RecoveryController,
  SecurityController,
  VerificationController,
} from '../src/internal.controller';
import type { NotificationsService } from '../src/notifications.service';

/**
 * The controller is a thin parse-then-delegate layer; what is worth pinning is
 * exactly that thinness: a malformed body is refused BEFORE the service runs
 * (the refusal never echoes the payload — it may carry an address), and a
 * valid one reaches the service verbatim. The credential guard itself is
 * proven in the auth-guard suite and on the live stack.
 */
/** The shape identity actually mints: EV1- plus eight groups of four. */
const MINTED_CODE = 'EV1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';

describe('InternalController', () => {
  const build = (): {
    controller: InternalController;
    recipients: RecipientsController;
    verification: VerificationController;
    status: RecipientStatusController;
    security: SecurityController;
    recovery: RecoveryController;
    emailChange: EmailChangeController;
    calls: {
      send: unknown[];
      upsert: unknown[];
      verification: unknown[];
      markVerified: unknown[];
      status: unknown[];
      security: unknown[];
      recovery: unknown[];
      emailChange: unknown[];
      replace: unknown[];
    };
  } => {
    const calls = {
      send: [] as unknown[],
      upsert: [] as unknown[],
      verification: [] as unknown[],
      markVerified: [] as unknown[],
      status: [] as unknown[],
      security: [] as unknown[],
      recovery: [] as unknown[],
      emailChange: [] as unknown[],
      replace: [] as unknown[],
    };
    const service = {
      send: (input: unknown): Promise<{ delivered: boolean; channel: string }> => {
        calls.send.push(input);
        return Promise.resolve({ delivered: true, channel: 'email' });
      },
      upsertRecipient: (input: unknown): Promise<{ ok: true }> => {
        calls.upsert.push(input);
        return Promise.resolve({ ok: true });
      },
      sendAddressVerification: (
        input: unknown,
      ): Promise<{ delivered: boolean; channel: string }> => {
        calls.verification.push(input);
        return Promise.resolve({ delivered: true, channel: 'email' });
      },
      markRecipientVerified: (userId: unknown): Promise<{ ok: boolean }> => {
        calls.markVerified.push(userId);
        return Promise.resolve({ ok: true });
      },
      recipientStatus: (userId: unknown): Promise<{ verified: boolean }> => {
        calls.status.push(userId);
        return Promise.resolve({ verified: true });
      },
      sendAccountSecurity: (input: unknown): Promise<{ delivered: boolean; channel: string }> => {
        calls.security.push(input);
        return Promise.resolve({ delivered: true, channel: 'email' });
      },
      sendPasswordReset: (input: unknown): Promise<{ delivered: boolean; channel: string }> => {
        calls.recovery.push(input);
        return Promise.resolve({ delivered: true, channel: 'email' });
      },
      sendEmailChange: (input: unknown): Promise<{ delivered: boolean; channel: string }> => {
        calls.emailChange.push(input);
        return Promise.resolve({ delivered: true, channel: 'email' });
      },
      replaceRecipient: (input: unknown): Promise<{ ok: true }> => {
        calls.replace.push(input);
        return Promise.resolve({ ok: true });
      },
    } as unknown as NotificationsService;
    return {
      controller: new InternalController(service),
      recipients: new RecipientsController(service),
      verification: new VerificationController(service),
      status: new RecipientStatusController(service),
      security: new SecurityController(service),
      recovery: new RecoveryController(service),
      emailChange: new EmailChangeController(service),
      calls,
    };
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

  it('upsertRecipient: parses and delegates (separate controller since the M9 review)', async () => {
    const { recipients, calls } = build();
    const body = { userId: randomUUID(), email: 'owner@example.com' };
    await expect(recipients.upsertRecipient(body)).resolves.toEqual({ ok: true });
    expect(calls.upsert).toEqual([body]);
  });

  it('the seven surfaces are separate classes, so they can carry separate guards', () => {
    // The split is only real if a guard can bind to one without the others:
    // sending estate kinds is vault + settlement + profile, repointing and
    // vouching for an address is identity alone, mailing a code is identity
    // alone on a DIFFERENT secret, and reading the verified bit is its own
    // edge again. A guard binds exactly one token, so one class per capability
    // is what makes the partition real rather than described.
    const { controller, recipients, verification, status } = build();
    const { security, recovery, emailChange } = build();
    const surfaces = [
      controller,
      recipients,
      verification,
      status,
      security,
      recovery,
      emailChange,
    ];
    expect(new Set(surfaces.map((s) => s.constructor.name)).size).toBe(7);
    expect('upsertRecipient' in controller).toBe(false);
    expect('send' in recipients).toBe(false);
    // The code-bearing route lives nowhere near the broadly-held send surface.
    expect('send' in verification).toBe(false);
    expect('sendAddressVerification' in controller).toBe(false);
    // M17: the account-security surface is its own class with its own handler
    // name, so a future refactor cannot merge it into either neighbour by
    // accident — the reason `sendCode` is not called `send` either.
    expect('sendSecurity' in controller).toBe(false);
    expect('sendSecurity' in verification).toBe(false);
    expect('sendCode' in security).toBe(false);
    // M17 PR3: four send surfaces, four handler names, so no refactor can merge
    // the account-recovery channel into any of its neighbours by accident.
    expect('sendReset' in controller).toBe(false);
    expect('sendReset' in verification).toBe(false);
    expect('sendReset' in security).toBe(false);
    expect('sendCode' in recovery).toBe(false);
    // The read surface writes nothing.
    expect(Object.getOwnPropertyNames(RecipientStatusController.prototype)).toEqual([
      'constructor',
      'status',
    ]);
  });

  it('recovery: parses the code wire and delegates', async () => {
    const { recovery, calls } = build();
    const body = {
      userId: randomUUID(),
      kind: 'identity.password_reset',
      code: 'PR1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E',
    };
    await expect(recovery.sendReset(body)).resolves.toEqual({ delivered: true, channel: 'email' });
    expect(calls.recovery).toEqual([body]);
  });

  it('recovery: refuses a VERIFICATION code, an estate kind, and free text', () => {
    // The pattern is anchored on its own prefix, so this route cannot mail a
    // verification code and the verification route cannot mail a reset code —
    // the exclusion is in the wire as well as in the credential.
    const { recovery, calls } = build();
    const id = randomUUID();
    expect(() =>
      recovery.sendReset({ userId: id, kind: 'identity.password_reset', code: MINTED_CODE }),
    ).toThrow(BadRequestException);
    expect(() =>
      recovery.sendReset({ userId: id, kind: 'settlement.case_opened', code: 'PR1-K7MN' }),
    ).toThrow(BadRequestException);
    expect(() =>
      recovery.sendReset({
        userId: id,
        kind: 'identity.password_reset',
        code: 'YOUR-ESTATE-ACCOUNT-IS-LOCKED-CALL-NOW',
      }),
    ).toThrow(BadRequestException);
    expect(calls.recovery).toEqual([]);
  });

  it('email-change: parses the destination-naming wire and delegates', async () => {
    const { emailChange, calls } = build();
    const body = {
      userId: randomUUID(),
      kind: 'identity.email_change',
      code: 'EC1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E',
      email: 'candidate@example.com',
    };
    await expect(emailChange.sendChallenge(body)).resolves.toEqual({
      delivered: true,
      channel: 'email',
    });
    expect(calls.emailChange).toEqual([body]);
  });

  it('email-change: refuses a reset code, a non-address destination, and a foreign kind', () => {
    // The pattern is anchored on its own prefix (a PR1- code cannot be mailed
    // here), the destination must parse as an address (this is the ONE route
    // that names one, so what it accepts IS the exposure), and the kind list
    // is closed.
    const { emailChange, calls } = build();
    const id = randomUUID();
    const ok = {
      userId: id,
      kind: 'identity.email_change',
      code: 'EC1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E',
      email: 'candidate@example.com',
    };
    expect(() =>
      emailChange.sendChallenge({
        ...ok,
        code: 'PR1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E',
      }),
    ).toThrow(BadRequestException);
    expect(() => emailChange.sendChallenge({ ...ok, email: 'not-an-address' })).toThrow(
      BadRequestException,
    );
    expect(() => emailChange.sendChallenge({ ...ok, kind: 'identity.password_reset' })).toThrow(
      BadRequestException,
    );
    expect(calls.emailChange).toEqual([]);
  });

  it('replace: parses the path id and the body address, and delegates', async () => {
    const { recipients, calls } = build();
    const id = randomUUID();
    await expect(recipients.replaceRecipient(id, { email: 'proved@example.com' })).resolves.toEqual(
      { ok: true },
    );
    expect(calls.replace).toEqual([{ userId: id, email: 'proved@example.com' }]);
    expect(() => recipients.replaceRecipient('not-a-uuid', { email: 'a@b.c' })).toThrow(
      BadRequestException,
    );
  });

  it('security: parses the closed-kind wire and delegates', async () => {
    const { security, calls } = build();
    const body = { userId: randomUUID(), kind: 'identity.password_changed' };
    await expect(security.sendSecurity(body)).resolves.toEqual({
      delivered: true,
      channel: 'email',
    });
    expect(calls.security).toEqual([body]);
  });

  it('security: refuses an ESTATE kind, and refuses smuggled text', () => {
    // The exclusion is what makes the split real: this credential must not be
    // able to fire an estate alarm, and the estate credential must not be able
    // to fire this. Both directions are structural (three schemas, three
    // lists), and this is the half a wire test can observe.
    const { security, calls } = build();
    expect(() =>
      security.sendSecurity({ userId: randomUUID(), kind: 'settlement.case_opened' }),
    ).toThrow(BadRequestException);
    expect(() =>
      security.sendSecurity({
        userId: randomUUID(),
        kind: 'identity.password_changed',
        subject: 'attacker words',
      }),
    ).toThrow(BadRequestException);
    // …and the code-bearing kind is not reachable here either.
    expect(() =>
      security.sendSecurity({ userId: randomUUID(), kind: 'identity.address_verification' }),
    ).toThrow(BadRequestException);
    expect(calls.security).toEqual([]);
  });

  it('verification: parses the typed code wire and delegates', async () => {
    const { verification, calls } = build();
    const body = { userId: randomUUID(), code: MINTED_CODE };
    await expect(verification.sendCode(body)).resolves.toEqual({
      delivered: true,
      channel: 'email',
    });
    expect(calls.verification).toEqual([body]);
  });

  it('verification: refuses free text where the code goes', () => {
    // The deviation docs/03 §6c records is a CODE, not a text field. A caller
    // that could put a sentence here would have re-created the free-text field
    // the whole content doctrine exists to refuse.
    const { verification, calls } = build();
    for (const code of [
      'hello there',
      'https://evil.test/x',
      'ev1-lowercase',
      '',
      // The M14 review's finding: the old pattern was `/^[0-9A-Z-]+$/` with a
      // 64-character cap, so 47 characters of readable English passed and were
      // interpolated verbatim into a real message from the platform's verified
      // sender — a free-text field by another name, in the one wire the content
      // doctrine exists to keep text-free.
      'YOUR-ESTATE-VAULT-IS-LOCKED-CALL-1-800-555-0100',
      // I, L, O and U are precisely what the minting alphabet excludes.
      'EV1-IIII-LLLL-OOOO-UUUU-2222-3333-4444-5555',
      // Right alphabet, wrong shape.
      'EV1-K7MN',
    ]) {
      expect(() => verification.sendCode({ userId: randomUUID(), code })).toThrow(
        BadRequestException,
      );
    }
    expect(() =>
      verification.sendCode({ userId: randomUUID(), code: MINTED_CODE, subject: 'words' }),
    ).toThrow(BadRequestException);
    expect(calls.verification).toEqual([]);
  });

  it('path-borne user ids are validated like body-borne ones', () => {
    // A path parameter reaches the handler as whatever the router matched, so
    // a malformed id must be a 400 here rather than a database error two
    // layers down.
    const { recipients, status } = build();
    expect(() => recipients.markVerified('not-a-uuid')).toThrow(BadRequestException);
    expect(() => status.status('../../etc/passwd')).toThrow(BadRequestException);
  });

  it('status and mark-verified delegate the parsed id', async () => {
    const { recipients, status, calls } = build();
    const userId = randomUUID();
    await expect(recipients.markVerified(userId)).resolves.toEqual({ ok: true });
    await expect(status.status(userId)).resolves.toEqual({ verified: true });
    expect(calls.markVerified).toEqual([userId]);
    expect(calls.status).toEqual([userId]);
  });

  it('upsertRecipient: refuses a malformed address without echoing it', async () => {
    const { recipients, calls } = build();
    try {
      await recipients.upsertRecipient({ userId: randomUUID(), email: 'not-an-address' });
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
