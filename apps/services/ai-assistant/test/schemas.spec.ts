import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';
import {
  BODY_LIMIT,
  CreateConversationSchema,
  MAX_TURN_CHARS,
  parseBody,
  TurnSchema,
  UuidSchema,
} from '../src/schemas';

/**
 * The request edge. Two properties are worth pinning here rather than
 * discovering later: a rejected body never comes back to the caller (in this
 * service the body is a PROMPT, the most sensitive request payload in the
 * product), and neither schema has a field in which a caller could name a
 * subject other than their own session's.
 */
describe('parseBody', () => {
  const Schema = z.object({ text: z.string() }).strict();

  it('returns the parsed value on success', () => {
    expect(parseBody(Schema, { text: 'hello' })).toEqual({ text: 'hello' });
  });

  it('rejects with exactly { error: invalid_request }', () => {
    try {
      parseBody(Schema, { text: 42 });
      throw new Error('expected BadRequestException');
    } catch (err) {
      expect(err).toBeInstanceOf(BadRequestException);
      expect((err as BadRequestException).getResponse()).toEqual({ error: 'invalid_request' });
    }
  });

  it('NEVER echoes the rejected payload — not in the body, not in the message', () => {
    // A distinctive value standing in for the thing that must not come back:
    // a fragment of somebody's estate, typed into a prompt.
    const secret = 'my-brother-gets-the-lake-house';
    try {
      parseBody(Schema, { text: secret, smuggled: secret });
      throw new Error('expected BadRequestException');
    } catch (err) {
      expect(err).toBeInstanceOf(BadRequestException);
      const exception = err as BadRequestException;
      expect(JSON.stringify(exception.getResponse())).not.toContain(secret);
      expect(exception.message).not.toContain(secret);
      // zod attaches the offending input to some issue codes; nothing derived
      // from the parse result may survive into the thrown object at all.
      expect(JSON.stringify(exception)).not.toContain(secret);
    }
  });

  it('rejects a non-object body without inspecting it', () => {
    expect(() => parseBody(Schema, 'not an object')).toThrow(BadRequestException);
    expect(() => parseBody(Schema, null)).toThrow(BadRequestException);
  });
});

describe('BODY_LIMIT', () => {
  it('is a prompt-sized ceiling, far below the 16 MiB document upload limit', () => {
    expect(BODY_LIMIT).toBe('256kb');
  });
});

describe('TurnSchema', () => {
  it('accepts a turn and trims it', () => {
    expect(parseBody(TurnSchema, { text: '  what is in my will?  ' })).toEqual({
      text: 'what is in my will?',
    });
  });

  it('refuses an empty or whitespace-only turn', () => {
    expect(() => parseBody(TurnSchema, { text: '' })).toThrow(BadRequestException);
    expect(() => parseBody(TurnSchema, { text: '    ' })).toThrow(BadRequestException);
  });

  it('refuses a turn over the character ceiling', () => {
    expect(() => parseBody(TurnSchema, { text: 'x'.repeat(MAX_TURN_CHARS + 1) })).toThrow(
      BadRequestException,
    );
    expect(parseBody(TurnSchema, { text: 'x'.repeat(MAX_TURN_CHARS) }).text).toHaveLength(
      MAX_TURN_CHARS,
    );
  });

  it('REFUSES a body that tries to name a subject, rather than stripping it', () => {
    // The subject of every read a turn can trigger comes from the verified
    // session. `.strict()` is what makes "there is no field for it" true of the
    // wire and not only of the service — a stripped key would let a client
    // believe it had been honoured.
    for (const smuggled of ['userId', 'onBehalfOf', 'ownerUserId', 'subject']) {
      expect(() => parseBody(TurnSchema, { text: 'hi', [smuggled]: 'someone-else' })).toThrow(
        BadRequestException,
      );
    }
  });
});

describe('CreateConversationSchema', () => {
  it('accepts an empty body', () => {
    expect(parseBody(CreateConversationSchema, {})).toEqual({});
  });

  it('refuses a title — the table has no such column, by design', () => {
    expect(() => parseBody(CreateConversationSchema, { title: 'Mum’s estate' })).toThrow(
      BadRequestException,
    );
  });
});

describe('UuidSchema', () => {
  it('accepts a UUID and refuses anything else', () => {
    expect(parseBody(UuidSchema, '3f0d1a2e-8b1c-4a5d-9e6f-7a8b9c0d1e2f')).toBe(
      '3f0d1a2e-8b1c-4a5d-9e6f-7a8b9c0d1e2f',
    );
    expect(() => parseBody(UuidSchema, '../../etc/passwd')).toThrow(BadRequestException);
    expect(() => parseBody(UuidSchema, '1')).toThrow(BadRequestException);
  });
});
