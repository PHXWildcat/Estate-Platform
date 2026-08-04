import { BadRequestException } from '@nestjs/common';
import { parseBody, RecipientSchema, SendSchema } from '../src/schemas';

const USER = 'b6c9a1de-0000-4000-8000-000000000001';

describe('SendSchema — content-free by schema', () => {
  it('accepts the closed shape, with and without a deadline', () => {
    expect(
      parseBody(SendSchema, { userId: USER, kind: 'emergency.requested', channel: 'email' }),
    ).toMatchObject({ kind: 'emergency.requested' });
    expect(
      parseBody(SendSchema, {
        userId: USER,
        kind: 'settlement.owner_contact',
        channel: 'sms',
        deadline: '2026-08-09T00:00:00.000Z',
      }),
    ).toMatchObject({ deadline: '2026-08-09T00:00:00.000Z' });
  });

  it('refuses smuggled content — a subject or body field is invalid_request, not a message', () => {
    for (const extra of [
      { subject: 'You inherited $1M — click here' },
      { body: 'wire funds to…' },
      { template: '<a href=x>' },
    ]) {
      expect(() =>
        parseBody(SendSchema, {
          userId: USER,
          kind: 'emergency.requested',
          channel: 'email',
          ...extra,
        }),
      ).toThrow(BadRequestException);
    }
  });

  it('refuses an unknown kind — the template registry is the only vocabulary', () => {
    expect(() =>
      parseBody(SendSchema, { userId: USER, kind: 'marketing.blast', channel: 'email' }),
    ).toThrow(BadRequestException);
  });
});

describe('RecipientSchema', () => {
  it('accepts a plain address and refuses junk', () => {
    expect(parseBody(RecipientSchema, { userId: USER, email: 'owner@example.com' })).toEqual({
      userId: USER,
      email: 'owner@example.com',
    });
    expect(() => parseBody(RecipientSchema, { userId: USER, email: 'not-an-address' })).toThrow(
      BadRequestException,
    );
    expect(() =>
      parseBody(RecipientSchema, { userId: USER, email: `${'a'.repeat(320)}@example.com` }),
    ).toThrow(BadRequestException);
  });

  it('never echoes the refused payload back', () => {
    try {
      parseBody(RecipientSchema, { userId: USER, email: 'secret-address@example.com', x: 1 });
      throw new Error('should have thrown');
    } catch (err) {
      expect(JSON.stringify((err as BadRequestException).getResponse())).not.toContain(
        'secret-address',
      );
    }
  });
});
