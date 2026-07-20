/**
 * Minimal structured JSON-lines logger.
 *
 * The entry shape is deliberately closed: a level, an enum-ish message
 * token, and scalar identifiers (topic/partition/offset/seq/counters).
 * There is no code path that accepts an arbitrary object or a payload, so
 * event content — which may contain the PII a schema rejection is protecting
 * us from — can never reach the log stream (docs/01 §6: logs carry entity
 * IDs, never values).
 *
 * Writes through `process.stdout.write` rather than `console.log` so the
 * repo-wide `no-console` rule keeps guarding every other file.
 */
export type LogLevel = 'info' | 'warn' | 'error';

export interface LogEntry {
  level: LogLevel;
  msg: string;
  [id: string]: string | number | boolean;
}

export function log(entry: LogEntry): void {
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`);
}
