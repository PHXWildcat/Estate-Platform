import { FATAL_EXIT_GRACE_MS, handleFatal, type FatalDeps } from '../src/fatal';

/** Capture the fatal path's effects instead of applying them to the runner. */
function recordingDeps(): FatalDeps & { exitCode: number | null; armed: number | null } {
  const deps = {
    exitCode: null as number | null,
    armed: null as number | null,
    setExitCode: (code: number): void => {
      deps.exitCode = code;
    },
    armForcedExit: (_fn: () => void, ms: number): void => {
      deps.armed = ms;
    },
  };
  return deps;
}

describe('audit fatal path', () => {
  let errors: string[];

  beforeEach(() => {
    errors = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown): boolean => {
      errors.push(String(chunk));
      return true;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('RELEASES OPEN HANDLES so a failed worker can actually exit', async () => {
    // The defect: `process.exitCode = 1` only takes effect once the event loop
    // drains, and the common failure (broker unreachable at start) happens
    // AFTER PG_CLIENT has connected — so its socket held the loop open and the
    // container sat "up" forever with a dead audit trail, restart policy never
    // firing. Closing the handles is what lets the process end.
    const deps = recordingDeps();
    let closed = 0;
    await handleFatal(
      new Error('broker unreachable'),
      {
        close: (): Promise<void> => {
          closed += 1;
          return Promise.resolve();
        },
      },
      deps,
    );
    expect(closed).toBe(1);
    expect(deps.exitCode).toBe(1);
  });

  it('arms a forced exit as the belt for a handle it could not release', async () => {
    const deps = recordingDeps();
    await handleFatal(new Error('x'), null, deps);
    expect(deps.armed).toBe(FATAL_EXIT_GRACE_MS);
  });

  it('still exits when there is nothing open yet', async () => {
    // Config/context failures happen before any handle exists.
    const deps = recordingDeps();
    await handleFatal(new Error('bad config'), null, deps);
    expect(deps.exitCode).toBe(1);
  });

  it('a cleanup failure never masks the original cause', async () => {
    const deps = recordingDeps();
    await expect(
      handleFatal(
        new Error('broker unreachable'),
        {
          close: (): Promise<void> => Promise.reject(new Error('pg end failed')),
        },
        deps,
      ),
    ).resolves.toBeUndefined();
    expect(deps.exitCode).toBe(1);
    expect(deps.armed).toBe(FATAL_EXIT_GRACE_MS);
  });

  it('logs the failure by name, and never an event payload', async () => {
    const deps = recordingDeps();
    await handleFatal(new Error('connection refused'), null, deps);
    const line = errors.join('');
    expect(line).toContain('audit_service_fatal');
    expect(line).toContain('connection refused');
  });

  it('handles a non-Error rejection without leaking its shape', async () => {
    const deps = recordingDeps();
    await handleFatal({ ssn: '123-45-6789' }, null, deps);
    const line = errors.join('');
    expect(line).toContain('unknown');
    expect(line).not.toContain('123-45-6789');
    expect(deps.exitCode).toBe(1);
  });
});
