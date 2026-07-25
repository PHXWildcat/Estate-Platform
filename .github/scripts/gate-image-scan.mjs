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
 * Usage: node gate-image-scan.mjs <grype.json> <image-name>
 */
import { appendFileSync, readFileSync } from 'node:fs';

const [, , reportPath, imageName = 'image'] = process.argv;

const BLOCKING_SEVERITIES = new Set(['High', 'Critical']);
/** grype's package types for a JavaScript dependency tree. */
const APPLICATION_TYPES = new Set(['npm', 'javascript', 'node-pkg']);

// Strip a UTF-8 BOM if the report was produced by a shell that adds one
// (PowerShell redirection does); JSON.parse rejects it with a bewildering error.
const raw = readFileSync(reportPath, 'utf8');
const report = JSON.parse(raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw);
const severe = (report.matches ?? []).filter((m) =>
  BLOCKING_SEVERITIES.has(m.vulnerability?.severity),
);

const application = severe.filter((m) => APPLICATION_TYPES.has(m.artifact?.type));
const base = severe.filter((m) => !APPLICATION_TYPES.has(m.artifact?.type));

const describe = (m) =>
  `${m.artifact?.name}@${m.artifact?.version} ${m.vulnerability?.id} ` +
  `(${m.vulnerability?.severity}, fix: ${m.vulnerability?.fix?.state ?? 'unknown'})`;

console.log(`\n${imageName}: ${severe.length} high/critical finding(s)`);
console.log(`  application (blocking): ${application.length}`);
console.log(`  base image (reported):  ${base.length}`);
for (const m of application) {
  console.log(`  BLOCKING  ${describe(m)}`);
}
for (const m of base.slice(0, 20)) {
  console.log(`  base      ${describe(m)}`);
}
if (base.length > 20) {
  console.log(`  base      … ${base.length - 20} more`);
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
  console.error(
    `::error::${imageName}: ${application.length} high/critical vulnerability in an application dependency — bump it`,
  );
  process.exit(1);
}
