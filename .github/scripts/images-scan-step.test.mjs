/**
 * The scan step's RETRY DECISION, driven rather than argued.
 *
 * `images.yml`'s "Scan image for vulnerabilities" step repeats the scan when the
 * gate refuses (exit 2) and never when it finds something (exit 1). That rule
 * lives in shell, in a workflow no unit test can reach, and it is exactly the
 * kind of logic that reads correct and behaves otherwise: `$?` after an `if`,
 * errexit interacting with a command substitution, a stale report surviving
 * into the next attempt.
 *
 * WHY THIS FILE EXISTS AT ALL. M49 PR2's first commit message claimed the loop
 * was driven by a harness. It was — in a scratch directory, not in the tree, so
 * the claim was true of the author's afternoon and false of the repository, and
 * the loop shipped with no test. Its own review caught that. This is the
 * harness, in the repo, where a later edit to the workflow runs it.
 *
 * IT MUST TEST THE WORKFLOW, NOT A COPY OF IT. The block is EXTRACTED from
 * images.yml at run time and its two external commands replaced with stubs. The
 * extractor throws if the matrix substitution did not apply, if either stub did
 * not take, or if any real `docker`/`node` invocation survived — because a
 * hand-copied harness proves the copy, and a substitution that silently missed
 * would drive the real scanner or nothing at all.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKFLOW = join(HERE, '..', 'workflows', 'images.yml');
const dirs = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
const scratch = () => {
  const d = mkdtempSync(join(tmpdir(), 'images-scan-step-'));
  dirs.push(d);
  return d;
};

/** Pull the step's `run:` body out of the real workflow. */
export function extractScanStep(source) {
  const lines = source.split('\n');
  const start = lines.findIndex((l) => l.includes('- name: Scan image for vulnerabilities'));
  assert.ok(start >= 0, 'the scan step is gone or renamed — this harness has lost its subject');
  const runAt = lines.findIndex((l, i) => i > start && /^\s*run: \|/.test(l));
  assert.ok(runAt > start, 'the scan step no longer has a `run:` block');
  const indent = lines[runAt + 1].match(/^\s*/)[0];
  const body = [];
  for (let i = runAt + 1; i < lines.length; i++) {
    if (lines[i].trim() !== '' && !lines[i].startsWith(indent)) break;
    body.push(lines[i].slice(indent.length));
  }
  assert.ok(
    body.length > 5,
    `the extracted step is only ${body.length} lines — extraction is broken`,
  );

  const before = body.join('\n');
  let script = before.replace(/\$\{\{ matrix\.app \}\}/g, 'operator-web');
  assert.notEqual(
    script,
    before,
    'no matrix substitution applied — the step no longer names matrix.app',
  );

  const withStubs = script
    .replace(
      /if ! docker run [^\n]*\\\n\s*"docker-archive:[^\n]*> "\$out"; then/,
      'if ! "$STUB_GRYPE" > "$out"; then',
    )
    .replace(
      /if node \.github\/scripts\/gate-image-scan\.mjs "\$out" operator-web; then/,
      'if "$STUB_GATE" "$out"; then',
    )
    .replace(/sleep \$\(\(attempt \* 10\)\)/, ': # sleep elided');
  assert.ok(withStubs.includes('$STUB_GRYPE'), 'the grype stub did not take');
  assert.ok(withStubs.includes('$STUB_GATE'), 'the gate stub did not take');
  assert.doesNotMatch(withStubs, /docker run/, 'a real docker invocation survived substitution');
  assert.doesNotMatch(
    withStubs,
    /gate-image-scan\.mjs/,
    'a real gate invocation survived substitution',
  );
  assert.doesNotMatch(
    withStubs,
    /sleep \d|sleep \$/,
    'the backoff would make this suite sleep for real',
  );
  return withStubs;
}

const bin = (dir, name, body) => {
  const p = join(dir, name);
  writeFileSync(p, body);
  chmodSync(p, 0o755);
  return p;
};

/**
 * Run the extracted step with a scanner stub and a gate stub whose verdicts are
 * read one per attempt from a file, so a sequence like "refuse, refuse, clean"
 * is expressible.
 */
const drive = ({ verdicts, grypeExits = 0 }) => {
  const dir = scratch();
  const script = bin(dir, 'scan.sh', extractScanStep(readFileSync(WORKFLOW, 'utf8')));
  const grype = bin(dir, 'grype', `#!/bin/bash\necho '{"stub":"report"}'\nexit ${grypeExits}\n`);
  const gate = bin(
    dir,
    'gate',
    `#!/bin/bash
n=$(cat "$COUNT"); n=$((n+1)); echo "$n" > "$COUNT"
code=$(awk -v i="$n" 'NR==i{print; exit}' "$VERDICTS")
[ -z "$code" ] && code=$(tail -1 "$VERDICTS")
exit "$code"
`,
  );
  const count = join(dir, 'count');
  const vfile = join(dir, 'verdicts');
  writeFileSync(count, '0');
  writeFileSync(vfile, verdicts.join('\n') + '\n');
  const r = spawnSync('bash', [script], {
    encoding: 'utf8',
    env: { ...process.env, STUB_GRYPE: grype, STUB_GATE: gate, COUNT: count, VERDICTS: vfile },
  });
  return { status: r.status, calls: Number(readFileSync(count, 'utf8')), out: r.stdout + r.stderr };
};

test('a clean scan exits 0 after one attempt', () => {
  const r = drive({ verdicts: [0] });
  assert.equal(r.status, 0);
  assert.equal(r.calls, 1);
});

test('a BLOCKING finding is reported at once and never retried', () => {
  // Retrying an answer would delay a real result and print it three times.
  const r = drive({ verdicts: [1, 1, 1] });
  assert.equal(r.status, 1);
  assert.equal(r.calls, 1);
});

test('a REFUSAL is retried, and a scan that then succeeds passes', () => {
  const r = drive({ verdicts: [2, 0] });
  assert.equal(r.status, 0);
  assert.equal(r.calls, 2);
});

test('a refusal that never clears exhausts three attempts and fails', () => {
  const r = drive({ verdicts: [2, 2, 2] });
  assert.equal(r.status, 1);
  assert.equal(r.calls, 3);
  assert.match(r.out, /no usable report after 3 attempts/);
});

test('a refusal followed by a real finding reports the finding', () => {
  const r = drive({ verdicts: [2, 2, 1] });
  assert.equal(r.status, 1);
  assert.equal(r.calls, 3);
});

test('misuse is not retried either — only a refusal is', () => {
  const r = drive({ verdicts: [3] });
  assert.equal(r.status, 3);
  assert.equal(r.calls, 1);
});

test('a scanner that exits non-zero still consults the gate, and warns', () => {
  // The scanner dying is not itself the verdict: the gate reads whatever landed
  // in the report, which is how a 0-byte file becomes a diagnosed refusal.
  const r = drive({ verdicts: [2, 2, 2], grypeExits: 1 });
  assert.equal(r.calls, 3);
  assert.match(r.out, /grype attempt 1 exited non-zero/);
});

test('each attempt starts from an empty report, never a previous one', () => {
  // `: > "$out"` at the top of the loop. Without it a good report from attempt 1
  // could be re-read by attempt 2 and turn a refusal into a pass.
  const step = extractScanStep(readFileSync(WORKFLOW, 'utf8'));
  const loopBody = step.slice(step.indexOf('for attempt'));
  assert.match(loopBody, /:\s*>\s*"\$out"/);
});

test('the harness can fail: mutating the retried code breaks the contract', () => {
  // A positive control for this file. If the workflow retried exit 1 instead of
  // 2, these two cases would invert — so the suite above is discriminating and
  // not merely running.
  const real = extractScanStep(readFileSync(WORKFLOW, 'utf8'));
  const mutated = real.replace('[ "$rc" -ne 2 ]', '[ "$rc" -ne 1 ]');
  assert.notEqual(mutated, real, 'the retried code is no longer written as a literal 2');
  const dir = scratch();
  const script = bin(dir, 'scan.sh', mutated);
  const grype = bin(dir, 'grype', "#!/bin/bash\necho '{}'\n");
  const gate = bin(
    dir,
    'gate',
    '#!/bin/bash\nn=$(cat "$COUNT"); n=$((n+1)); echo "$n" > "$COUNT"\nexit 1\n',
  );
  const count = join(dir, 'count');
  writeFileSync(count, '0');
  const r = spawnSync('bash', [script], {
    encoding: 'utf8',
    env: {
      ...process.env,
      STUB_GRYPE: grype,
      STUB_GATE: gate,
      COUNT: count,
      VERDICTS: join(dir, 'v'),
    },
  });
  // Under the mutation a blocking finding is retried three times.
  assert.equal(Number(readFileSync(count, 'utf8')), 3);
  assert.equal(r.status, 1);
});
