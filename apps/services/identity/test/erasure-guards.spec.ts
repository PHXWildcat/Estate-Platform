/**
 * THE ERASURE ASYMMETRY IS A DECORATOR, SO IT IS ASSERTED AS ONE (M25 PR2).
 *
 * The whole ceremony rests on one inversion: requesting erasure needs a fresh
 * step-up, withdrawing it needs nothing but the session. Usually the permissive
 * action is gated and the protective one is free (grant vs revoke); here the
 * permissive action IS the destructive one, so the rule reverses shape.
 *
 * That inversion is easy to "fix" in review by somebody who reads the rule and
 * not the shape — adding `StepUpGuard` to the DELETE looks like tightening a
 * control and is actually the defect, because an owner whose session was
 * briefly taken could then arm the most irreversible process in the product and
 * be made to prove themselves before disarming it. So the absence is pinned
 * here as an ASSERTION rather than left as a comment nobody runs.
 *
 * ANCHORED ON THE RUNTIME'S OWN METADATA, not on source text. `@UseGuards`
 * writes `__guards__`, which is what Nest reads when it builds the pipeline —
 * so a guard applied through a different spelling, or removed, moves this. A
 * grep over the file would be a scan of what somebody wrote rather than of what
 * the framework will execute, and that difference is how a name-keyed fence in
 * this repo went blind for a whole milestone.
 */
import 'reflect-metadata';
import { ErasureController } from '../src/erasure.controller';
import { SESSION_AUDIENCE_METADATA } from '../src/session-audience.decorator';
import { SessionGuard } from '../src/session.guard';
import { StepUpGuard } from '../src/stepup.guard';

type Ctor = new (...args: never[]) => unknown;

const PROTOTYPE = ErasureController.prototype as unknown as Record<string, object>;

function guardsOn(method: 'get' | 'request' | 'cancel'): string[] {
  const guards = (Reflect.getMetadata('__guards__', PROTOTYPE[method] as object) ?? []) as Ctor[];
  return guards.map((g) => g.name).sort();
}

describe('account erasure route guards', () => {
  it('the metadata is readable at all (anti-vacuity)', () => {
    // An absence is asserted below, and an absence is what a broken reader
    // reports for everything. This proves the reader sees a guard when one is
    // there — without it, `not.toContain` passes on an empty array forever.
    expect(guardsOn('request')).toContain(SessionGuard.name);
    expect(guardsOn('get')).toContain(SessionGuard.name);
    expect(guardsOn('cancel')).toContain(SessionGuard.name);
  });

  it('REQUESTING erasure is step-up gated (docs/01 §5 names deletion requests)', () => {
    expect(guardsOn('request')).toEqual([SessionGuard.name, StepUpGuard.name].sort());
  });

  it('WITHDRAWING is NOT step-up gated, and that is the control', () => {
    // The protective action must never be harder than the permissive one.
    expect(guardsOn('cancel')).not.toContain(StepUpGuard.name);
    expect(guardsOn('cancel')).toEqual([SessionGuard.name]);
  });

  it('READING your own erasure state is not gated beyond the session either', () => {
    // Asking whether you are marked for erasure must not itself cost a factor:
    // the answer is about the caller, and a factor in front of it would make
    // checking harder than the thing being checked.
    expect(guardsOn('get')).toEqual([SessionGuard.name]);
  });

  it('the controller is ACCOUNT-AUDIENCE ONLY — undecorated, which is deny by default', () => {
    // A vault, extension or operator session must not reach the verb that marks
    // an account for destruction. `@AllowSessionAudiences` is what would widen
    // it, and its absence is the whole control (M15's rule: the union can only
    // widen, so a route that declares nothing admits `account` alone).
    for (const method of ['get', 'request', 'cancel'] as const) {
      expect(
        Reflect.getMetadata(SESSION_AUDIENCE_METADATA, PROTOTYPE[method] as object),
      ).toBeUndefined();
    }
    expect(Reflect.getMetadata(SESSION_AUDIENCE_METADATA, ErasureController)).toBeUndefined();
  });
});

/**
 * The handlers themselves. Thin by design — they unwrap the session and shape
 * the response — but "thin" is exactly where a wrong argument hides: passing
 * the SESSION id where the USER id belongs would authorize erasure against a
 * uuid that happens to exist, and no guard would notice.
 */
describe('account erasure handlers', () => {
  const USER = '11111111-1111-4111-8111-111111111111';
  const SESSION = '22222222-2222-4222-8222-222222222222';
  const state = { status: 'pending' as const, requestedAt: '2026-08-21T12:00:00.000Z' };

  function controller(): {
    ctl: ErasureController;
    seen: Array<{ fn: string; userId: string; sessionId: string | null }>;
  } {
    const seen: Array<{ fn: string; userId: string; sessionId: string | null }> = [];
    const service = {
      get: (userId: string) => {
        seen.push({ fn: 'get', userId, sessionId: null });
        return Promise.resolve(state);
      },
      request: (userId: string, sessionId: string | null) => {
        seen.push({ fn: 'request', userId, sessionId });
        return Promise.resolve(state);
      },
      cancel: (userId: string, sessionId: string | null) => {
        seen.push({ fn: 'cancel', userId, sessionId });
        return Promise.resolve(null);
      },
      runDueErasures: () => Promise.resolve(0),
    };
    return {
      ctl: new ErasureController(service as never),
      seen,
    };
  }

  const req = { headers: {}, auth: { userId: USER, sessionId: SESSION } } as never;

  it('passes the USER id as the subject, never the session id', async () => {
    const { ctl, seen } = controller();
    await ctl.get(req);
    await ctl.request(req);
    await ctl.cancel(req);
    expect(seen.map((s) => s.fn)).toEqual(['get', 'request', 'cancel']);
    // The assertion that matters: every subject is the user, and the session
    // travels only as provenance for the audit trail.
    expect(seen.every((s) => s.userId === USER)).toBe(true);
    expect(seen.filter((s) => s.fn !== 'get').every((s) => s.sessionId === SESSION)).toBe(true);
  });

  it('wraps the state under `erasure`, and passes the cancel answer through', async () => {
    const { ctl } = controller();
    await expect(ctl.get(req)).resolves.toEqual({ erasure: state });
    await expect(ctl.request(req)).resolves.toEqual({ erasure: state });
    // Null when nothing is outstanding — a client cannot tell a real cancel
    // from a no-op and has no reason to need to. Since M25 PR3 the handler no
    // longer HARD-CODES that null: a cancel that came too late answers with the
    // executing request, and a controller that discarded it would tell the
    // owner "withdrawn" about an erasure that is destroying keys.
    await expect(ctl.cancel(req)).resolves.toEqual({ erasure: null });
  });

  it('does not swallow a cancel that came too late', async () => {
    const late = { ...state, status: 'executing' as const };
    const service = { cancel: () => Promise.resolve(late) };
    const gate = new ErasureController(service as never);
    await expect(gate.cancel(req)).resolves.toEqual({ erasure: late });
  });

  it('refuses a request with no attached session — the wiring-mistake guard', async () => {
    const { ctl } = controller();
    await expect(ctl.request({ headers: {} })).rejects.toThrow();
  });
});
