/**
 * Opens — or updates — the one issue that says a scheduled gate is failing.
 *
 * WHY THIS EXISTS: an unwatched red gate is not a gate. The scheduled secret
 * sweep failed seventeen consecutive runs, every scheduled run that had ever
 * executed, and nobody noticed, because a scheduled run notifies nobody by
 * default: no PR to turn red, no push author to email, and the Actions tab shows
 * it only to someone already looking. The remediation came from reading the code,
 * not from any of the seventeen alarms.
 *
 * WHY A SCRIPT FILE rather than an inline `github-script` block: this repo
 * already keeps CI logic in `.github/scripts/` (`gate-image-scan.mjs`), a real
 * file can be tested without a live repository, and `${{ }}` interpolation into a
 * code path is a class of bug this repo has been bitten by often enough to avoid
 * on principle. Everything arrives through the environment.
 *
 * ONE ISSUE, MANY COMMENTS. Seventeen red days must produce one issue with
 * seventeen comments, never seventeen issues — a duplicate storm is the same
 * desensitization in a different costume. A prematurely closed report is
 * REOPENED rather than duplicated beside.
 *
 * Usage: node .github/scripts/notify-failure.mjs
 * Reads GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID,
 * GITHUB_SHA, GITHUB_EVENT_NAME, NOTIFY_WORKFLOW, NOTIFY_DETAILS.
 */

const LABEL = 'ci-failure';

/** Every field this needs, so a missing one fails loudly rather than half-working. */
function env(name, { required = true } = {}) {
  const value = process.env[name];
  if (required && (value === undefined || value === '')) {
    throw new Error(`${name} is required`);
  }
  return value ?? '';
}

export function issueTitle(workflow) {
  return `CI: scheduled ${workflow} run is failing`;
}

export function issueBody({ workflow, runUrl, sha, event, details }) {
  const lines = [
    `Scheduled run of **${workflow}** failed: ${runUrl}`,
    '',
    `Commit \`${sha.slice(0, 7)}\` · event \`${event}\``,
  ];
  if (details.trim() !== '') {
    lines.push('', details.trim());
  }
  return lines.join('\n');
}

/**
 * The find-or-create decision, isolated from HTTP so it can be tested. Open
 * issues are searched before closed ones: a gate that starts failing again after
 * someone closed the report should reopen that thread, not start a parallel one.
 */
export function decide({ title, openIssues, closedIssues }) {
  const open = openIssues.find((i) => i.title === title);
  if (open) return { action: 'comment', number: open.number };
  const closed = closedIssues.find((i) => i.title === title);
  if (closed) return { action: 'reopen', number: closed.number };
  return { action: 'create' };
}

async function main() {
  const token = env('GITHUB_TOKEN');
  const repo = env('GITHUB_REPOSITORY');
  const workflow = env('NOTIFY_WORKFLOW');
  const details = env('NOTIFY_DETAILS', { required: false });
  const runUrl = `${env('GITHUB_SERVER_URL')}/${repo}/actions/runs/${env('GITHUB_RUN_ID')}`;
  const title = issueTitle(workflow);
  const body = issueBody({
    workflow,
    runUrl,
    sha: env('GITHUB_SHA'),
    event: env('GITHUB_EVENT_NAME'),
    details,
  });

  const api = async (path, init = {}) => {
    const res = await fetch(`https://api.github.com/repos/${repo}${path}`, {
      ...init,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28',
        ...(init.body ? { 'content-type': 'application/json' } : {}),
      },
    });
    if (!res.ok && res.status !== 404) {
      throw new Error(`${init.method ?? 'GET'} ${path} -> ${res.status} ${await res.text()}`);
    }
    return res;
  };

  // The label is a search key, so a missing one would silently disable dedup and
  // produce exactly the issue storm the dedup exists to prevent.
  if ((await api(`/labels/${LABEL}`)).status === 404) {
    await api('/labels', {
      method: 'POST',
      body: JSON.stringify({
        name: LABEL,
        color: 'b60205',
        description: 'A scheduled or dispatched CI gate is failing',
      }),
    });
  }

  const list = async (state) =>
    (await (await api(`/issues?labels=${LABEL}&state=${state}&per_page=100`)).json()) ?? [];

  const decision = decide({
    title,
    openIssues: await list('open'),
    closedIssues: await list('closed'),
  });

  if (decision.action === 'comment') {
    await api(`/issues/${decision.number}/comments`, {
      method: 'POST',
      body: JSON.stringify({ body }),
    });
    console.log(`commented on #${decision.number}`);
    return;
  }

  if (decision.action === 'reopen') {
    await api(`/issues/${decision.number}`, {
      method: 'PATCH',
      body: JSON.stringify({ state: 'open' }),
    });
    await api(`/issues/${decision.number}/comments`, {
      method: 'POST',
      body: JSON.stringify({ body: `Failing again.\n\n${body}` }),
    });
    console.log(`reopened #${decision.number}`);
    return;
  }

  const created = await (
    await api('/issues', {
      method: 'POST',
      body: JSON.stringify({
        title,
        labels: [LABEL],
        body:
          `${body}\n\n---\n\nOpened by \`.github/scripts/notify-failure.mjs\` because a ` +
          `scheduled run has no PR to turn red and no push author to notify. Further ` +
          `failures are added as comments here rather than as new issues. Close it when ` +
          `the gate is green; it reopens itself if the failure returns.`,
      }),
    })
  ).json();
  console.log(`opened #${created.number}`);
}

if (process.argv[1] && process.argv[1].endsWith('notify-failure.mjs')) {
  await main();
}
