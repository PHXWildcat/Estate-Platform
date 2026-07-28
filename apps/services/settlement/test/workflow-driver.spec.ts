import type { SettlementService } from '../src/settlement.service';
import { SettlementWorkflowDriver } from '../src/workflow-driver';
import { NOW, testConfig } from './support';

function fakeService(): { sweeps: Date[]; service: SettlementService } {
  const sweeps: Date[] = [];
  const service = {
    runContactSweep: (now: Date): Promise<{ attempts: number }> => {
      sweeps.push(now);
      return Promise.resolve({ attempts: 0 });
    },
  } as unknown as SettlementService;
  return { sweeps, service };
}

describe('SettlementWorkflowDriver (deliberately powerless scheduling)', () => {
  afterEach(() => {
    jest.useRealTimers();
  });

  it('does not start under NODE_ENV=test (suites drive the sweep directly)', () => {
    jest.useFakeTimers();
    const { sweeps, service } = fakeService();
    const driver = new SettlementWorkflowDriver(service, testConfig(), () => NOW);
    driver.onApplicationBootstrap();
    jest.advanceTimersByTime(10 * 60_000);
    expect(sweeps).toHaveLength(0);
    driver.onApplicationShutdown();
  });

  it('sweeps on the configured interval outside test, and stops on shutdown', () => {
    jest.useFakeTimers();
    const { sweeps, service } = fakeService();
    const driver = new SettlementWorkflowDriver(
      service,
      testConfig({ nodeEnv: 'development', driverIntervalMs: 1_000 }),
      () => NOW,
    );
    driver.onApplicationBootstrap();
    jest.advanceTimersByTime(3_500);
    expect(sweeps).toHaveLength(3);
    driver.onApplicationShutdown();
    jest.advanceTimersByTime(5_000);
    expect(sweeps).toHaveLength(3);
  });

  it('a sweep failure is swallowed and the next tick still fires', async () => {
    jest.useFakeTimers();
    let calls = 0;
    const service = {
      runContactSweep: (): Promise<{ attempts: number }> => {
        calls += 1;
        return Promise.reject(new Error('transient'));
      },
    } as unknown as SettlementService;
    const driver = new SettlementWorkflowDriver(
      service,
      testConfig({ nodeEnv: 'development', driverIntervalMs: 1_000 }),
      () => NOW,
    );
    driver.onApplicationBootstrap();
    jest.advanceTimersByTime(2_500);
    // Let the rejected promises settle inside the fake-timer window.
    await Promise.resolve();
    expect(calls).toBe(2);
    driver.onApplicationShutdown();
  });
});
