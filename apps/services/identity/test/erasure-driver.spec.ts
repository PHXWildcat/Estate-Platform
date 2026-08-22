/**
 * THE ERASURE DRIVER'S LIFECYCLE (M25 PR3).
 *
 * Small surface, and every line of it decides something. The driver is the only
 * thing in the product that reaches an irreversible action without a request in
 * flight, so what it does at boot — and what it deliberately does NOT do — is
 * worth asserting rather than reading.
 *
 * FAKE TIMERS, NOT REAL ONES. A test that waited for an interval would be a
 * test that sometimes did not wait long enough, and the shape of that flake is
 * a green run for a driver that never ticked.
 */
import type { IdentityConfig } from '../src/config';
import { ErasureDriver } from '../src/erasure.driver';
import type { ErasureService } from '../src/erasure.service';

const NOW = new Date('2026-08-21T12:00:00.000Z');
const INTERVAL_MS = 60_000;

function driver(
  nodeEnv: IdentityConfig['nodeEnv'],
  run: () => Promise<number> = () => Promise.resolve(0),
): { driver: ErasureDriver; clocks: Date[] } {
  const clocks: Date[] = [];
  const erasure = {
    runDueErasures: (now: Date): Promise<number> => {
      clocks.push(now);
      return run();
    },
  } as unknown as ErasureService;
  const config = {
    nodeEnv,
    erasureDriverIntervalMs: INTERVAL_MS,
  } as unknown as IdentityConfig;
  return { driver: new ErasureDriver(erasure, config, () => NOW), clocks };
}

describe('the erasure driver', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('DOES NOT TICK under NODE_ENV=test, and that is a control not a convenience', () => {
    // Suites drive `runDueErasures` directly with an injected clock. A timer
    // racing a test that is asserting on a DEK's `destroyed_at` would make the
    // most irreversible path in the product the flakiest one — and a shred
    // fired by a stray tick is not a failure a rerun would explain.
    const { driver: d, clocks } = driver('test');
    d.onApplicationBootstrap();
    jest.advanceTimersByTime(INTERVAL_MS * 10);
    expect(clocks).toEqual([]);
    // Shutting down something that never started must also be safe.
    expect(() => d.onApplicationShutdown()).not.toThrow();
  });

  it('ticks on the configured interval, passing the injected clock', () => {
    // The anti-vacuity half of the assertion above: without it, "no ticks under
    // test" is equally consistent with a driver that never ticks at all.
    const { driver: d, clocks } = driver('production');
    d.onApplicationBootstrap();
    expect(clocks).toEqual([]);
    jest.advanceTimersByTime(INTERVAL_MS);
    expect(clocks).toEqual([NOW]);
    jest.advanceTimersByTime(INTERVAL_MS * 2);
    expect(clocks).toHaveLength(3);
    d.onApplicationShutdown();
  });

  it('NEVER KEEPS THE PROCESS ALIVE just to sweep', () => {
    // `unref` is what stops a container hanging on shutdown because an erasure
    // sweep is scheduled sixty seconds out.
    const unref = jest.fn();
    const spy = jest
      .spyOn(global, 'setInterval')
      .mockReturnValue({ unref } as unknown as NodeJS.Timeout);
    try {
      const { driver: d } = driver('development');
      d.onApplicationBootstrap();
      expect(spy).toHaveBeenCalledWith(expect.any(Function), INTERVAL_MS);
      expect(unref).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('a failed sweep is swallowed and the next tick still runs', async () => {
    // Errors are observability's problem (audit events), not the timer's. A
    // rejection escaping here would be an unhandled rejection that could take
    // the process down — and every step of the leg re-reads the fact it
    // changes, so the retry resumes rather than repeating.
    let calls = 0;
    const { driver: d, clocks } = driver('production', () => {
      calls += 1;
      return calls === 1 ? Promise.reject(new Error('pg down')) : Promise.resolve(1);
    });
    d.onApplicationBootstrap();
    jest.advanceTimersByTime(INTERVAL_MS);
    await Promise.resolve();
    jest.advanceTimersByTime(INTERVAL_MS);
    await Promise.resolve();
    expect(clocks).toHaveLength(2);
    d.onApplicationShutdown();
  });

  it('stops on shutdown, and stays stopped', () => {
    const { driver: d, clocks } = driver('production');
    d.onApplicationBootstrap();
    jest.advanceTimersByTime(INTERVAL_MS);
    d.onApplicationShutdown();
    jest.advanceTimersByTime(INTERVAL_MS * 5);
    expect(clocks).toHaveLength(1);
    // Idempotent: a second shutdown must not throw on an already-cleared timer.
    expect(() => d.onApplicationShutdown()).not.toThrow();
  });
});
