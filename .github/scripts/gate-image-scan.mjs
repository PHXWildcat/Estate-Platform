/**
 * Gate a grype JSON report for one container image.
 *
 * Why this is not simply `grype --fail-on high`:
 *
 * A distroless runtime still contains Debian packages (libssl3, libc6, …) and
 * the bundled node binary, none of which this repo can patch — there is no
 * package manager in the image, and the fix is for the base vendor to rebuild.
 * Several of these CVEs are even marked "won't fix" upstream. Blocking every PR
 * on that cadence produces a permanently red pipeline that people learn to
 * ignore, which is strictly worse for security than a gate that only fires on
 * things a developer here can actually act on.
 *
 * So the gate splits by ownership:
 *   * APPLICATION packages (our npm dependency tree) — BLOCKING. These are ours:
 *     bump the dependency.
 *   * BASE-IMAGE packages (deb/binary/etc.) — REPORTED, not blocking. The
 *     compensating control is rebasing: images rebuild from a floating patch tag
 *     on every CI run, and the tracked follow-up is Renovate-driven digest
 *     pinning plus a scheduled rebuild so a fresh base lands automatically.
 *
 * WHY THERE IS A REFUSAL PATH ABOVE ALL OF THAT (M49 PR2).
 *
 * Until 2026-09-04 the split above was the WHOLE gate, and it read the report as
 * `(report.matches ?? []).filter(…)`. `??` coalesces an ABSENT key to zero
 * findings, so every one of these passed with `application (blocking): 0` and
 * exit 0 — measured, each one:
 *
 *     {}                                  a report with no matches key
 *     {"error":"database is invalid"}     grype telling us it could not scan
 *     []                                  a JSON array where an object belongs
 *     {"Matches":[]}                      a schema rename one grype minor away
 *
 * A vulnerability gate that answers "nothing to block" when the scan did not
 * happen is worse than no gate, because it fails in the reassuring direction:
 * the image proceeds to push and the run is green. The failure that prompted
 * this — grype dying and writing a 0-byte report on #177 — was the SURVIVABLE
 * half of the class, because a parse error at least went red.
 *
 * The anti-vacuity argument was already written down in the SBOM step of the
 * very workflow that calls this file: "syft can exit 0 having catalogued
 * nothing, and an empty document is a useless artifact that looks like a good
 * one." That step counts packages and retries. The step deciding whether
 * vulnerable code ships did neither. This file is that rule applied to the
 * other member of the pair.
 *
 * TWO OUTCOMES, TWO TOKENS, AND TWO EXIT CODES, because they need different
 * remedies and a control firing must not read as an outage:
 *   * BLOCKING (exit 1) — the scan ran and found something ours. Bump the
 *     dependency. Retrying this just prints it three times.
 *   * REFUSED (exit 2) — the scan did not produce a usable report. Re-run it;
 *     look at the scanner. This says nothing about the image, and it is the
 *     ONLY outcome the caller's retry loop may repeat. A single code for both
 *     would make the loop either retry real findings or not retry anything.
 *   * MISUSE (exit 3) — the caller passed the wrong arguments.
 *
 * AND A FOURTH THAT WAS WEARING THE FIRST ONE'S CODE. Until the review of this
 * PR, nothing caught a throw. `main` ran unguarded, so any TypeError inside it
 * reached node's default handler and exited 1 — BLOCKING — which the caller
 * reads as "a vulnerability in an application dependency" and pointedly does
 * NOT retry. Three inputs reached it: a `descriptor.db.status` of null (the
 * shape a nil status serialises to, i.e. exactly the no-database case), a
 * `matches` array containing null, and an unwritable GITHUB_STEP_SUMMARY —
 * the last printing `application (blocking): 0` immediately before exiting
 * under the code that means the opposite. The gate falling over says nothing
 * about the image, so it is a REFUSAL, and it is now caught and reported as
 * one. This file's own defect, one path over.
 *
 * Usage: node gate-image-scan.mjs <grype.json> <image-name>
 */
import { appendFileSync, readFileSync } from 'node:fs';
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const BLOCKING_SEVERITIES = new Set(['High', 'Critical']);
/** grype's package types for a JavaScript dependency tree. */
const APPLICATION_TYPES = new Set(['npm', 'javascript', 'node-pkg']);

/**
 * How stale grype's vulnerability database may be before its answer stops
 * counting as a scan.
 *
 * The runner fetches a fresh database every job — nothing persists a grype
 * cache between runs — so in the normal case `built` is hours old and this
 * never fires. It fires when grype falls back to something it already had,
 * which is the case where `valid: true` is true and MEANINGLESS: a database a
 * fortnight old cannot see a fortnight of CVEs, and the gate would report a
 * confident zero.
 *
 * Seven days rather than one because the remedy for a genuinely unreachable
 * database is the retry loop in the caller, not a red pipeline — this is the
 * backstop for the case the retry cannot detect, and a backstop that fires on
 * ordinary jitter is the permanently-red gate this file's header argues
 * against.
 */
export const MAX_DB_AGE_DAYS = 7;

/** Exit codes. The caller retries EXIT_REFUSED and nothing else. */
export const EXIT_CLEAN = 0;
export const EXIT_BLOCKED = 1;
export const EXIT_REFUSED = 2;
export const EXIT_MISUSE = 3;

/**
 * Does this report prove a scan actually happened?
 *
 * Returns null when it does, or a human reason when it does not. Anchored on
 * what grype's OWN report carries rather than on a shape we hope for: a real
 * report names its database under `descriptor.db.status`, with `valid` and the
 * `built` timestamp. Note the nesting — `descriptor.db.built` is `undefined`,
 * and reading that path yields a value that compares false against every
 * cutoff, which is how a staleness check silently becomes a no-op.
 *
 * Every unrecognised shape REFUSES rather than passing. A future grype that
 * renames these fields fails closed and someone updates this file; the
 * alternative is the bug this function exists to remove.
 */
export function scanRefusal(report, now = Date.now()) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    return `the report is ${Array.isArray(report) ? 'a JSON array' : String(report)}, not a grype report object`;
  }
  if (!Array.isArray(report.matches)) {
    return report.matches === undefined
      ? 'the report has no `matches` key — grype did not produce findings, which is not the same as finding none'
      : "the report's `matches` is not an array";
  }
  const status = report.descriptor?.db?.status;
  // `== null` deliberately, covering undefined AND null: optional chaining stops
  // at undefined, so a serialised nil status arrives as null and sails past an
  // `=== undefined` guard into a TypeError one line down.
  if (status == null || typeof status !== 'object') {
    return `the report names no usable vulnerability database (\`descriptor.db.status\` is ${JSON.stringify(status)}) — nothing establishes that a database was loaded`;
  }
  if (status.valid !== true) {
    return `the vulnerability database reported itself invalid (valid: ${JSON.stringify(status.valid)}) — a scan against no database finds nothing`;
  }
  const built = Date.parse(status.built ?? '');
  if (Number.isNaN(built)) {
    return `the vulnerability database has no readable build date (built: ${JSON.stringify(status.built)})`;
  }
  const ageDays = (now - built) / 86_400_000;
  if (ageDays > MAX_DB_AGE_DAYS) {
    return `the vulnerability database was built ${ageDays.toFixed(1)} days ago (limit ${MAX_DB_AGE_DAYS}) — it cannot see anything disclosed since`;
  }
  for (const [i, m] of report.matches.entries()) {
    const why = unreadableMatch(m, i);
    if (why)
      return `${why} — a finding this gate cannot read must not be counted as one it may ignore`;
  }
  return null;
}

/**
 * Severities grype can emit. Anything outside this set means the report is not
 * the schema this gate reads, and an UNREAD finding must never be a silently
 * non-blocking one — that is the same defect as the absent `matches` key, one
 * level in: `BLOCKING_SEVERITIES.has(undefined)` is false, so a renamed field
 * or a lower-cased severity would quietly empty the blocking bucket.
 */
const KNOWN_SEVERITIES = new Set(['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']);

/** A match this gate cannot read, described for the refusal message. */
export function unreadableMatch(m, i) {
  if (m === null || typeof m !== 'object')
    return `matches[${i}] is ${JSON.stringify(m)}, not an object`;
  const sev = m.vulnerability?.severity;
  if (typeof sev !== 'string')
    return `matches[${i}] has no severity string (got ${JSON.stringify(sev)})`;
  if (!KNOWN_SEVERITIES.has(sev))
    return `matches[${i}] has severity ${JSON.stringify(sev)}, which is outside grype's vocabulary`;
  if (typeof m.artifact?.type !== 'string')
    return `matches[${i}] has no artifact.type string (got ${JSON.stringify(m.artifact?.type)})`;
  return null;
}

/** Split the high/critical findings into the two ownership classes. */
export function classify(report) {
  const severe = (report.matches ?? []).filter((m) =>
    BLOCKING_SEVERITIES.has(m.vulnerability?.severity),
  );
  return {
    severe,
    application: severe.filter((m) => APPLICATION_TYPES.has(m.artifact?.type)),
    base: severe.filter((m) => !APPLICATION_TYPES.has(m.artifact?.type)),
  };
}

const describe = (m) =>
  `${m.artifact?.name}@${m.artifact?.version} ${m.vulnerability?.id} ` +
  `(${m.vulnerability?.severity}, fix: ${m.vulnerability?.fix?.state ?? 'unknown'})`;

/**
 * Read the report, diagnosing every way it can fail to be one.
 *
 * The old code read and parsed in two expressions with no try/catch, so an
 * absent file died with a raw ENOENT and a 0-byte file with
 * `SyntaxError: Unexpected end of JSON input` at a line number — naming neither
 * the image nor the scanner. That cost a diagnostic cycle on #177.
 */
export function readReport(reportPath) {
  let raw;
  try {
    raw = readFileSync(reportPath, 'utf8');
  } catch (err) {
    return {
      error: `no readable report at ${reportPath} (${err.code ?? err.message}) — the scanner wrote nothing`,
    };
  }
  if (raw.trim() === '') {
    return {
      error: `the report at ${reportPath} is empty (${raw.length} bytes) — the scanner exited without writing one`,
    };
  }
  try {
    // Strip a UTF-8 BOM if the report was produced by a shell that adds one
    // (PowerShell redirection does); JSON.parse rejects it with a bewildering error.
    return { report: JSON.parse(raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw) };
  } catch (err) {
    return { error: `the report at ${reportPath} is not valid JSON (${err.message})` };
  }
}

export function main(argv, opts = {}) {
  const err = opts.err ?? console.error;
  const imageName = argv[1];
  try {
    return decide(argv, opts);
  } catch (e) {
    // THE FOURTH OUTCOME. Anything that throws in here is the gate falling
    // over, which says nothing about the image — so it is a refusal, and it
    // must not be delivered under the blocking finding's code, which the
    // caller does not retry. Reported with the stack, because an unexpected
    // throw is a bug in this file and the next person needs the line.
    err(
      `::error::${imageName ?? 'image'}: REFUSED — the gate itself failed (${e && e.stack ? e.stack.split('\n')[0] : e}). This is not a finding about the image; the scan did not complete.`,
    );
    return EXIT_REFUSED;
  }
}

function decide(argv, { now = Date.now(), log = console.log, err = console.error } = {}) {
  const [reportPath, imageName] = argv;
  // No default image name. It used to be 'image', which mislabelled every log
  // line and the job-summary heading rather than failing, so a caller that
  // dropped the argument produced a plausible report about nothing nameable.
  if (!reportPath || !imageName) {
    err('::error::usage: node gate-image-scan.mjs <grype.json> <image-name>');
    return EXIT_MISUSE;
  }

  const { report, error } = readReport(reportPath);
  if (error) {
    err(
      `::error::${imageName}: REFUSED — ${error}. This is not a finding about the image; the scan did not run.`,
    );
    return EXIT_REFUSED;
  }

  const refusal = scanRefusal(report, now);
  if (refusal) {
    err(
      `::error::${imageName}: REFUSED — ${refusal}. This is not a finding about the image; the scan did not run.`,
    );
    return EXIT_REFUSED;
  }

  const { severe, application, base } = classify(report);

  log(`\n${imageName}: ${severe.length} high/critical finding(s)`);
  log(`  application (blocking): ${application.length}`);
  log(`  base image (reported):  ${base.length}`);
  for (const m of application) {
    log(`  BLOCKING  ${describe(m)}`);
  }
  for (const m of base.slice(0, 20)) {
    log(`  base      ${describe(m)}`);
  }
  if (base.length > 20) {
    log(`  base      … ${base.length - 20} more`);
  }

  // Surface the split in the job summary so base drift stays visible without
  // digging through logs.
  if (process.env.GITHUB_STEP_SUMMARY) {
    const lines = [
      `### ${imageName}`,
      '',
      `- application high/critical (blocking): **${application.length}**`,
      `- base-image high/critical (reported): ${base.length}`,
      ...application.map((m) => `  - :x: ${describe(m)}`),
      '',
    ];
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n'));
  }

  if (application.length > 0) {
    err(
      `::error::${imageName}: ${application.length} high/critical vulnerability in an application dependency — bump it`,
    );
    return EXIT_BLOCKED;
  }
  return EXIT_CLEAN;
}

// Both sides are resolved before comparing, because each carries a different
// distortion — see the same guard in assert-stack-counts.mjs for the symlink
// case that made an earlier copy of this idiom never run.
const entryPoint =
  process.argv[1] === undefined ? undefined : pathToFileURL(realpathSync(process.argv[1])).href;
if (import.meta.url === entryPoint) {
  process.exit(main(process.argv.slice(2)));
}
