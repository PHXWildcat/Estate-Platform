import { log } from './logger';

/** Grace period before a stuck process is killed outright. */
export const FATAL_EXIT_GRACE_MS = 5_000;

/** Seams so the fatal path is testable without ending the test runner. */
export interface FatalDeps {
  setExitCode(code: number): void;
  /** Arm the last-resort kill. Production schedules an unref'd timer. */
  armForcedExit(fn: () => void, ms: number): void;
}

const PROCESS_DEPS: FatalDeps = {
  setExitCode: (code) => {
    process.exitCode = code;
  },
  armForcedExit: (fn, ms) => {
    // Unref'd, so it cannot itself keep a healthy process alive — it only
    // fires if something else already has.
    setTimeout(fn, ms).unref();
  },
};

/**
 * A FAILED WORKER MUST ACTUALLY EXIT.
 *
 * `process.exitCode` alone only takes effect once the event loop drains, and
 * by the time the common failure happens — `consumer.start()` unable to reach
 * the broker — PG_CLIENT has already connected, so its open socket holds the
 * loop open forever. The container then sits "up" with a dead audit trail:
 * docker's restart policy never fires, an orchestrator sees a running process,
 * and the only symptom is silence — in the one service whose silence docs/01
 * §6 treats as a paging signal.
 *
 * Releasing the handles lets the process exit on its own, which also flushes
 * the log line rather than truncating it the way an immediate `process.exit`
 * would. The forced exit is the belt for a handle we failed to release.
 */
export async function handleFatal(
  err: unknown,
  handles: { close(): Promise<void> } | null,
  deps: FatalDeps = PROCESS_DEPS,
): Promise<void> {
  // Infrastructure failure detail only — never event payloads (which are the
  // only place PII could appear, and they are handled without throwing).
  log({
    level: 'error',
    msg: 'audit_service_fatal',
    error: err instanceof Error ? `${err.name}: ${err.message}` : 'unknown',
  });
  deps.setExitCode(1);
  try {
    await handles?.close();
  } catch {
    // Already failing; a cleanup error must not mask the original cause.
  }
  deps.armForcedExit(() => process.exit(1), FATAL_EXIT_GRACE_MS);
}
