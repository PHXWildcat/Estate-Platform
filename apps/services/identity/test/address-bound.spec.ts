/**
 * THE ADDRESS-KEYED BOUND (M17), on its own.
 *
 * This proves the PRIMITIVE. `auth.service.spec.ts` proves the decision that
 * uses it and `login-bound.int.spec.ts` proves the ledger half against real
 * Postgres — the M13 rule that when a rule exists at more than one layer, a
 * test must say which layer it is proving.
 *
 * Every case below is a way the bound could look like a rate limiter and not be
 * one: a window that never lapses is a permanent ban, a window that lapses per
 * ATTEMPT never fires, an eviction that fails closed is a denial-of-service
 * primitive against every user, and a bound that keys on the wrong thing does
 * not bound what it claims.
 */
import { randomBytes } from 'node:crypto';
import { AddressAttemptBound } from '../src/address-bound';
import { LOGIN_ADDRESS_BOUND } from '../src/rate-bounds';

const A = Buffer.from('bidx-address-a');
const B = Buffer.from('bidx-address-b');

/** A clock the test moves by hand; the bound never reads the real one. */
function fakeClock(start = new Date('2026-08-12T09:00:00.000Z')): {
  clock: () => Date;
  advance: (ms: number) => void;
} {
  let now = start.getTime();
  return {
    clock: () => new Date(now),
    advance: (ms: number) => {
      now += ms;
    },
  };
}

describe('AddressAttemptBound', () => {
  it('is not exhausted until the cap is REACHED, not before', () => {
    const { clock } = fakeClock();
    const bound = new AddressAttemptBound({ max: 3, windowMs: 1000, capacity: 10 }, clock);

    expect(bound.exhausted(A)).toBe(false);
    bound.record(A);
    bound.record(A);
    // One below: the interesting boundary, and the one an off-by-one gets wrong
    // in the direction that refuses an honest caller.
    expect(bound.exhausted(A)).toBe(false);
    bound.record(A);
    expect(bound.exhausted(A)).toBe(true);
  });

  it('bounds each address SEPARATELY', () => {
    // A bound that keyed on nothing (a global counter) would let one attacker
    // refuse every user in the product, which is the failure mode this whole
    // design is arranged around.
    const { clock } = fakeClock();
    const bound = new AddressAttemptBound({ max: 2, windowMs: 1000, capacity: 10 }, clock);

    bound.record(A);
    bound.record(A);
    expect(bound.exhausted(A)).toBe(true);
    expect(bound.exhausted(B)).toBe(false);
  });

  it('lapses after the window, so it is a cooldown and never a ban', () => {
    const { clock, advance } = fakeClock();
    const bound = new AddressAttemptBound({ max: 2, windowMs: 1000, capacity: 10 }, clock);

    bound.record(A);
    bound.record(A);
    expect(bound.exhausted(A)).toBe(true);

    advance(999);
    expect(bound.exhausted(A)).toBe(true); // still inside
    advance(1);
    expect(bound.exhausted(A)).toBe(false); // and out
  });

  it('measures the window from the FIRST attempt, so attempts cannot extend it', () => {
    // The defect this refuses: a window restarted by every attempt is one an
    // attacker keeps open forever, turning a cooldown into exactly the
    // renewable lockout M16 measured and closed on the step-up cap.
    const { clock, advance } = fakeClock();
    const bound = new AddressAttemptBound({ max: 2, windowMs: 1000, capacity: 10 }, clock);

    bound.record(A);
    advance(600);
    bound.record(A);
    expect(bound.exhausted(A)).toBe(true);

    advance(400); // 1000ms since the FIRST record, though only 400 since the last
    expect(bound.exhausted(A)).toBe(false);
  });

  it('a success clears the address, so a fumble does not cost the rest of the window', () => {
    const { clock } = fakeClock();
    const bound = new AddressAttemptBound({ max: 2, windowMs: 1000, capacity: 10 }, clock);

    bound.record(A);
    bound.clear(A);
    bound.record(A);
    expect(bound.exhausted(A)).toBe(false);
  });

  it('EVICTS THE LEAST RECENTLY SEEN when full, and eviction fails OPEN', () => {
    // Failing closed on eviction would let whoever fills the map deny logins to
    // every user in the product — strictly worse than the spraying it would be
    // trying to stop. The residual (an attacker can flush their own counter) is
    // recorded in docs/03 §6k rather than hidden.
    const { clock } = fakeClock();
    const bound = new AddressAttemptBound({ max: 1, windowMs: 60_000, capacity: 3 }, clock);

    bound.record(A);
    expect(bound.exhausted(A)).toBe(true);

    // Fill past capacity with unrelated addresses.
    for (let i = 0; i < 5; i += 1) {
      bound.record(randomBytes(16));
    }

    expect(bound.size).toBeLessThanOrEqual(3);
    expect(bound.exhausted(A)).toBe(false);
  });

  it('never grows past its capacity, whatever it is handed', () => {
    // The bound on the bound: without it, a caller submitting unique addresses
    // makes the rate limiter the memory-exhaustion vector.
    const { clock } = fakeClock();
    const bound = new AddressAttemptBound({ max: 5, windowMs: 60_000, capacity: 50 }, clock);

    for (let i = 0; i < 500; i += 1) {
      bound.record(randomBytes(16));
    }
    expect(bound.size).toBeLessThanOrEqual(50);
  });

  it('does not keep the blind index it was handed', () => {
    // What is stored is a truncated digest OF the blind index, so the process
    // never holds the platform's own correlatable identifier in a long-lived
    // structure. Asserted by walking the instance rather than trusting the
    // constructor — `#private` fields are unreachable, which is the property,
    // so what this can check is that no enumerable copy escaped.
    const { clock } = fakeClock();
    const bound = new AddressAttemptBound(LOGIN_ADDRESS_BOUND, clock);
    const secret = Buffer.from('a-very-distinctive-blind-index');
    bound.record(secret);

    expect(JSON.stringify(Object.entries(bound))).not.toContain('a-very-distinctive-blind-index');
    expect(Object.keys(bound)).not.toContain('windows');
  });

  it('the shipped login bound is tighter than the account ceiling it sits under', () => {
    // Not arithmetic for its own sake: the address half is meant to be what a
    // caller meets first in a single-process deployment, with the durable
    // account ceiling behind it. If this inverted, the in-memory half would
    // never fire and the only bound would be the evadable-by-restart one.
    expect(LOGIN_ADDRESS_BOUND.max).toBeLessThan(20);
    expect(LOGIN_ADDRESS_BOUND.windowMs).toBeGreaterThan(0);
    expect(LOGIN_ADDRESS_BOUND.capacity).toBeGreaterThan(1000);
  });
});
