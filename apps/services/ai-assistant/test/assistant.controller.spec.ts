import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { CallerGuard, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import { AssistantController } from '../src/assistant.controller';
import { ConsentsController } from '../src/consents.controller';
import { CONSENT_SCOPES, type ConsentScope } from '../src/consent';
import type { ConsentsRepo } from '../src/consents.repo';
import type { ConversationService } from '../src/conversation.service';
import type { Db, Queryable } from '../src/db';
import type { EventsService } from '../src/events.service';

const USER = randomUUID();
const BEARER = 'the-callers-own-access-token';

function request(headers: Record<string, string | string[] | undefined> = {}): CallerRequest {
  return {
    headers: { authorization: `Bearer ${BEARER}`, ...headers },
    caller: {
      userId: USER,
      sessionId: randomUUID(),
      mfaLevel: 'stepup',
      stepupExpiresAt: new Date('2026-08-04T00:05:00Z'),
      audience: 'account',
    },
  };
}

/** Guards bound to a controller CLASS by `@UseGuards`. */
function classGuards(target: object): unknown[] {
  const meta: unknown = Reflect.getMetadata(GUARDS_METADATA, target);
  return Array.isArray(meta) ? (meta as unknown[]) : [];
}

/**
 * Guards bound to ONE route handler by a method-level `@UseGuards`. Read off
 * the property descriptor rather than off `Ctor.prototype.method`, so the
 * handler is never referenced as an unbound method.
 */
function routeGuards(ctor: { prototype: object }, method: string): unknown[] {
  const descriptor = Object.getOwnPropertyDescriptor(ctor.prototype, method);
  const handler: unknown = descriptor?.value;
  if (typeof handler !== 'function') {
    throw new Error(`no such route handler: ${method}`);
  }
  const meta: unknown = Reflect.getMetadata(GUARDS_METADATA, handler);
  return Array.isArray(meta) ? (meta as unknown[]) : [];
}

interface Recorded {
  name: string;
  args: unknown[];
}

function conversationService(calls: Recorded[]): ConversationService {
  const record =
    (name: string) =>
    (...args: unknown[]): Promise<unknown> => {
      calls.push({ name, args });
      return Promise.resolve({ ok: name });
    };
  return {
    create: record('create'),
    list: record('list'),
    transcript: record('transcript'),
    remove: record('remove'),
    takeTurn: record('takeTurn'),
  } as unknown as ConversationService;
}

/**
 * The controller layer is thin on purpose, so what these tests pin is exactly
 * that thinness plus the two things the routes themselves decide: WHERE the
 * subject comes from (always the verified session) and WHICH guards each route
 * carries.
 */
describe('AssistantController', () => {
  it('takes the subject from the verified session and forwards the caller’s own bearer', async () => {
    const calls: Recorded[] = [];
    const controller = new AssistantController(conversationService(calls));
    const conversationId = randomUUID();

    await controller.takeTurn(request(), conversationId, { text: 'what do I own?' });

    expect(calls).toEqual([
      { name: 'takeTurn', args: [USER, BEARER, conversationId, 'what do I own?'] },
    ]);
  });

  it('refuses a body that tries to name a subject, before the service runs', () => {
    const calls: Recorded[] = [];
    const controller = new AssistantController(conversationService(calls));
    // parseBody throws synchronously — the service is never even scheduled.
    expect(() =>
      controller.takeTurn(request(), randomUUID(), { text: 'hi', userId: randomUUID() }),
    ).toThrow(BadRequestException);
    expect(calls).toEqual([]);
  });

  it('refuses a non-UUID conversation id without reaching the service', () => {
    const calls: Recorded[] = [];
    const controller = new AssistantController(conversationService(calls));
    for (const id of ['../../v1/consents', 'not-a-uuid']) {
      expect(() => controller.transcript(request(), id)).toThrow(BadRequestException);
      expect(() => controller.remove(request(), id)).toThrow(BadRequestException);
    }
    expect(calls).toEqual([]);
  });

  it('refuses a create body carrying a title (no such column exists)', () => {
    const calls: Recorded[] = [];
    const controller = new AssistantController(conversationService(calls));
    expect(() => controller.create(request(), { title: 'Estate' })).toThrow(BadRequestException);
    expect(calls).toEqual([]);
  });

  it('an absent authorization header yields an empty bearer, which fails closed downstream', async () => {
    const calls: Recorded[] = [];
    const controller = new AssistantController(conversationService(calls));
    const req = request({ authorization: undefined });
    const conversationId = randomUUID();

    await controller.takeTurn(req, conversationId, { text: 'hi' });

    // '' is a wiring anomaly (CallerGuard would have rejected the request), and
    // the peer clients refuse to make a call at all on an empty bearer — so the
    // failure mode is "no data", never an unauthenticated read.
    expect(calls[0]?.args[1]).toBe('');
  });

  it('every conversation route sits behind CallerGuard and none behind StepUpGuard', () => {
    expect(classGuards(AssistantController)).toContain(CallerGuard);

    for (const method of ['create', 'list', 'transcript', 'remove', 'takeTurn']) {
      // Talking to the assistant about your own estate is not on docs/01 §5's
      // step-up list; the gate sits on the consent grant, which is where the
      // widening happens.
      expect(routeGuards(AssistantController, method)).not.toContain(StepUpGuard);
    }
  });
});

describe('ConsentsController', () => {
  interface Harness {
    controller: ConsentsController;
    granted: Set<ConsentScope>;
    events: Recorded[];
    dbTouched: boolean;
  }

  const build = (): Harness => {
    const harness: Harness = {
      controller: undefined as unknown as ConsentsController,
      granted: new Set<ConsentScope>(),
      events: [],
      dbTouched: false,
    };
    const tx: Queryable = { query: (): Promise<never[]> => Promise.resolve([]) };
    const db = {
      query: (): Promise<never[]> => Promise.resolve([]),
      withTransaction: <T>(_actorId: string, fn: (q: Queryable) => Promise<T>): Promise<T> => {
        harness.dbTouched = true;
        return fn(tx);
      },
    } as unknown as Db;
    const repo = {
      grantedScopes: (): Promise<Set<ConsentScope>> => Promise.resolve(new Set(harness.granted)),
      grant: (_tx: Queryable, _userId: string, scope: ConsentScope): Promise<boolean> => {
        const isNew = !harness.granted.has(scope);
        harness.granted.add(scope);
        return Promise.resolve(isNew);
      },
      revoke: (_tx: Queryable, _userId: string, scope: ConsentScope): Promise<boolean> =>
        Promise.resolve(harness.granted.delete(scope)),
    } as unknown as ConsentsRepo;
    const events = {
      consentGranted: (...args: unknown[]): Promise<void> => {
        harness.events.push({ name: 'consentGranted', args });
        return Promise.resolve();
      },
      consentRevoked: (...args: unknown[]): Promise<void> => {
        harness.events.push({ name: 'consentRevoked', args });
        return Promise.resolve();
      },
    } as unknown as EventsService;
    harness.controller = new ConsentsController(db, repo, events);
    return harness;
  };

  it('grants, audits, and answers with the committed set', async () => {
    const h = build();
    await expect(h.controller.grant(request(), 'assistant.enabled')).resolves.toEqual({
      granted: ['assistant.enabled'],
    });
    expect(h.events).toEqual([
      { name: 'consentGranted', args: [USER, { scope: 'assistant.enabled' }] },
    ]);
  });

  it('does not audit a no-op re-grant of a live scope', async () => {
    const h = build();
    await h.controller.grant(request(), 'assistant.assets');
    await h.controller.grant(request(), 'assistant.assets');
    expect(h.events).toHaveLength(1);
  });

  it('revokes and audits', async () => {
    const h = build();
    await h.controller.grant(request(), 'assistant.assets');
    h.events.length = 0;
    await expect(h.controller.revoke(request(), 'assistant.assets')).resolves.toEqual({
      granted: [],
    });
    expect(h.events).toEqual([
      { name: 'consentRevoked', args: [USER, { scope: 'assistant.assets' }] },
    ]);
  });

  it('refuses an unknown scope BEFORE touching the database', async () => {
    const h = build();
    for (const scope of ['assistant.everything', 'assistant.enabled ', '']) {
      await expect(h.controller.grant(request(), scope)).rejects.toBeInstanceOf(
        BadRequestException,
      );
      await expect(h.controller.revoke(request(), scope)).rejects.toBeInstanceOf(
        BadRequestException,
      );
    }
    expect(h.dbTouched).toBe(false);
  });

  it('answers { error: unknown_scope } and nothing else', async () => {
    const h = build();
    try {
      await h.controller.grant(request(), 'assistant.nope');
      throw new Error('expected BadRequestException');
    } catch (err) {
      expect((err as BadRequestException).getResponse()).toEqual({ error: 'unknown_scope' });
    }
  });

  it('knows every declared scope', async () => {
    const h = build();
    for (const scope of CONSENT_SCOPES) {
      await expect(h.controller.grant(request(), scope)).resolves.toBeDefined();
    }
    expect((await h.controller.list(request())).granted).toEqual([...CONSENT_SCOPES].sort());
  });

  /**
   * The asymmetry, asserted on the route metadata rather than on prose: the
   * PERMISSIVE action is step-up gated (a grant widens estate-data egress to a
   * third-party model provider — export-class under docs/01 §5), and the
   * PROTECTIVE one is not (the M6 emergency-access-denial precedent: switching
   * a capability off must never be harder than switching it on). Reversing
   * either of these two expectations is a red test, which is the only form of
   * the argument that survives a refactor.
   */
  it('grant carries StepUpGuard; revoke and list deliberately do not', () => {
    expect(classGuards(ConsentsController)).toContain(CallerGuard);

    expect(routeGuards(ConsentsController, 'grant')).toContain(StepUpGuard);
    expect(routeGuards(ConsentsController, 'grant')).toContain(CallerGuard);
    expect(routeGuards(ConsentsController, 'revoke')).not.toContain(StepUpGuard);
    expect(routeGuards(ConsentsController, 'list')).not.toContain(StepUpGuard);
  });
});
