/**
 * THE SHIPPED ARTIFACT, OPENING A VAULT IN A REAL BROWSER.
 *
 * ═══ WHAT THIS RETIRES ═══
 *
 * M16 PR2b listed, as unexercised and owed: the offscreen document's lifecycle,
 * `chrome.offscreen.createDocument` from a service worker, the worker boundary,
 * and IndexedDB under a real `chrome-extension://` origin. Everything the
 * extension claims rested on a hand-written `chrome` double in jsdom, which
 * PR3b then showed was MORE GENEROUS THAN THE PLATFORM — the double supplied
 * `getManifest` unconditionally, an offscreen document does not have it, and
 * the extension consequently could never have unlocked a vault. That defect was
 * invisible to 477 green tests and cost a whole PR.
 *
 * This runs the EXTRACTED PACKAGE — the bytes `pack-extension.mjs` produced,
 * not the source tree — in Chrome, and drives a real SRP-6a unlock against a
 * stand-in vault speaking the real protocol.
 *
 * ═══ WHY IT LOADS OVER CDP ═══
 *
 * `--load-extension` is refused by Chrome 151 (measured; the flag was removed
 * around 137 after malware abuse). PR3b concluded from that that loading
 * "cannot be scripted" and "no CI job can ever stand in for it". Only the first
 * half was true: `Extensions.loadUnpacked` over the DevTools protocol works,
 * and this file is what that correction makes possible.
 *
 * ═══ WHAT IT DOES NOT PROVE, STATED ═══
 *
 * No fill. Filling needs `activeTab`, and activeTab needs a genuine user
 * invocation of the action — measured: a programmatic
 * `chrome.action.openPopup()` opens the popup and grants nothing. Driving a
 * real invocation needs an OS-level keystroke, which is a second moving part
 * (a display server and a synthetic input tool) for one assertion. The fill is
 * covered by `fill-into-page.spec.ts` and was driven by hand in PR3b; the
 * origin decision that governs it is covered by `origin-match.spec.ts`.
 *
 * Nor does it prove anything about the real vault SERVICE: the stand-in has no
 * sessions, audiences, step-up or guards. Those are the service's own suites,
 * and PR2a proved the transport live at the edge.
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CHROME =
  process.env.CHROME_BIN ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const EXT_DIR = process.env.EXT_DIR;
const PORT = Number(process.env.VAULT_PORT ?? 3111);
const DEBUG_PORT = Number(process.env.CDP_PORT ?? 9444);
if (!EXT_DIR) throw new Error('EXT_DIR must point at the extracted package');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * EVERY WAIT IS BOUNDED, and finding that out cost ten minutes.
 *
 * The first mutation run removed the packaged `lib/vault-crypto` — the exact
 * defect that shipped once and made the extension inert — and this harness
 * HUNG rather than failing. `chrome.runtime.sendMessage` to an offscreen
 * document whose module never initialised returns a promise that simply never
 * settles, and `Runtime.evaluate` with `awaitPromise` waits on it forever. In
 * CI that is a job that burns its whole `timeout-minutes` and reports a
 * timeout, which is the least useful failure a gate can produce: it says
 * nothing about WHICH claim broke.
 *
 * So a stalled evaluation resolves to a sentinel and the assertion that needed
 * it fails by name.
 */
const withDeadline = (promise, ms, what) =>
  Promise.race([
    promise,
    sleep(ms).then(() => ({ __timeout: `no response within ${ms}ms — ${what}` })),
  ]);

const checks = [];
/**
 * A FAILURE MUST SAY WHY. `ev` reports a thrown or timed-out evaluation as
 * `{__error}`, and a caller doing `String(v)` renders that `[object Object]` —
 * which is what the first CI failure of this job printed, throwing away the one
 * fact that would have explained it. Details render through `describe`, so an
 * error arrives as its text wherever it is reported.
 */
const describe = (v) =>
  v && typeof v === 'object' && '__error' in v ? `ERROR: ${v.__error}` : String(v ?? '');

const check = (name, ok, detail = '') => {
  const shown = describe(detail);
  checks.push({ name, ok, detail: shown });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${shown ? `  — ${shown}` : ''}`);
};

/** Poll until `fn` is truthy or the deadline passes. No bare sleeps. */
async function until(fn, what, ms = 20000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(250);
  }
}

async function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = rej;
  });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  };
  return {
    send: (method, params = {}, sessionId) =>
      new Promise((res) => {
        const i = ++id;
        pending.set(i, res);
        ws.send(JSON.stringify({ id: i, method, params, ...(sessionId ? { sessionId } : {}) }));
      }),
    close: () => ws.close(),
  };
}

const state = JSON.parse(process.env.VAULT_STATE ?? '{}');
const profile = mkdtempSync(join(tmpdir(), 'ext-smoke-'));
let chrome;
try {
  chrome = spawn(
    CHROME,
    [
      `--user-data-dir=${profile}`,
      `--remote-debugging-port=${DEBUG_PORT}`,
      '--no-first-run',
      '--no-default-browser-check',
      // Chrome's NEW headless supports extensions; the old one did not, and
      // that history is why this is a switch rather than a constant. A CI run
      // under Xvfb sets CHROME_HEADLESS=0 if the runner's build ever disagrees,
      // without this file having to guess which platform it is on.
      ...(process.env.CHROME_HEADLESS === '0' ? [] : ['--headless=new']),
      // Sandboxing is off ONLY under an explicit opt-in, because CI containers
      // run as root where the sandbox cannot initialise. It is never the local
      // default: a browser this harness drives against a stand-in server is
      // still a browser, and turning its sandbox off by habit is how that stops
      // being a considered choice.
      ...(process.env.CHROME_NO_SANDBOX === '1' ? ['--no-sandbox'] : []),
      'about:blank',
    ],
    { stdio: 'ignore' },
  );

  const version = await until(async () => {
    try {
      return await (await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/version`)).json();
    } catch {
      return null;
    }
  }, 'chrome devtools endpoint');
  console.log(`\n  browser: ${version.Browser}\n`);

  const b = await cdp(version.webSocketDebuggerUrl);

  // 1. THE PACKED ARTIFACT LOADS. A manifest Chrome refuses fails here, which
  //    no jsdom test can observe.
  const loaded = await b.send('Extensions.loadUnpacked', { path: EXT_DIR });
  const extId = loaded.result?.id;
  check(
    'the packed extension loads in Chrome',
    Boolean(extId),
    extId ?? JSON.stringify(loaded.error),
  );
  if (!extId) throw new Error('extension did not load');

  // 2. THE SERVICE WORKER BOOTS. `background.js` is an entry file excluded from
  //    coverage and driven by nothing else.
  const swSession = await until(async () => {
    const { result } = await b.send('Target.getTargets');
    const sw = result.targetInfos.find((t) => t.type === 'service_worker' && t.url.includes(extId));
    if (!sw) return null;
    const at = await b.send('Target.attachToTarget', { targetId: sw.targetId, flatten: true });
    return at.result.sessionId;
  }, 'the extension service worker');
  const ev = async (expression, session = swSession) => {
    const r = await withDeadline(
      b.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, session),
      15000,
      expression.slice(0, 60).replace(/\s+/g, ' '),
    );
    if (r?.__timeout) return { __error: r.__timeout };
    if (r.result?.exceptionDetails) {
      // `text` is bare "Uncaught"; the message a reader needs is on the
      // exception object. Prefer it, and keep `text` as the fallback.
      const d = r.result.exceptionDetails;
      return { __error: d.exception?.description ?? d.text };
    }
    return r.result?.result?.value;
  };

  // ATTACHED IS NOT READY, and the difference cost this job its first red run.
  // `Target.attachToTarget` succeeds as soon as the target EXISTS, while the
  // worker's `chrome` bindings are installed a moment later — so the next
  // `Runtime.evaluate` can throw, and every check after it inherits that. CI
  // failed exactly there (`chrome.runtime.getManifest` 55ms after attach) while
  // passing on the run before and passing locally, which is the signature of a
  // race rather than a defect in what is being asserted.
  //
  // The readiness predicate is therefore the thing actually needed: the worker
  // EVALUATES. Polled to a deadline, never slept at — the rule this repo keeps
  // restating about flaky gates.
  const swReady = await until(
    async () => {
      const id = await ev(`chrome.runtime.id`);
      return typeof id === 'string' && id.length > 0 ? id : null;
    },
    'the service worker to evaluate',
    15000,
  );
  check('its service worker boots', Boolean(swSession) && Boolean(swReady), swReady);

  // 3. THE MANIFEST CHROME PARSED is the one that was built — the M8 PR5
  //    baked-value lesson, asserted against the platform rather than a file.
  const perms = await ev(`JSON.stringify(chrome.runtime.getManifest().host_permissions)`);
  check(
    'the origin Chrome sees is the one that was baked',
    typeof perms === 'string' && perms.includes(String(PORT)),
    perms,
  );

  // 4. Seed the paired session. Pairing itself is proven live at the edge
  //    (PR2a); what is under test here is everything AFTER it.
  await ev(
    `chrome.storage.local.set({'estate.session':{accessToken:'smoke-access',refreshToken:'smoke-refresh',userId:${JSON.stringify(state.userId)},sessionId:'smoke-session'}}).then(()=>'ok')`,
  );

  // 5. THE OFFSCREEN DOCUMENT — created from the service worker, which is the
  //    exact call PR2b listed as unexercised.
  const offscreen = await ev(`
    (async () => {
      const has = await chrome.offscreen.hasDocument?.();
      if (!has) {
        await chrome.offscreen.createDocument({
          url: 'offscreen.html',
          reasons: ['WORKERS'],
          justification: 'holds the vault key in a worker',
        });
      }
      return 'created';
    })()
  `);
  check(
    'chrome.offscreen.createDocument works from the worker',
    offscreen === 'created',
    String(offscreen?.__error ?? offscreen),
  );

  const offSession = await until(async () => {
    const { result } = await b.send('Target.getTargets');
    const doc = result.targetInfos.find((t) => t.url.includes(`${extId}/offscreen.html`));
    if (!doc) return null;
    const at = await b.send('Target.attachToTarget', { targetId: doc.targetId, flatten: true });
    return at.result.sessionId;
  }, 'the offscreen document');
  check('the offscreen document is live', Boolean(offSession));

  // 6. THE CRYPTO LOADS AT ITS ABSOLUTE PATH. `/lib/vault-crypto/index.js` is
  //    served by the extension itself; a packaging slip makes it a 404 and the
  //    vault simply never opens — the class of defect that shipped once already.
  const crypto = await ev(
    `import('/lib/vault-crypto/index.js').then(m => typeof m.prepareUnlock).catch(e => 'ERR ' + e.message)`,
    offSession,
  );
  check('vault-crypto loads at its absolute path', crypto === 'function', String(crypto));

  // 7. A REAL SRP-6a UNLOCK, driven the way the popup drives it: a message to
  //    the offscreen document, which sequences both legs and hands the key to
  //    the worker it owns.
  const unlocked = await ev(
    `chrome.runtime.sendMessage({
       target: 'offscreen', kind: 'unlock',
       userId: ${JSON.stringify(state.userId)},
       password: ${JSON.stringify(state.password)},
       secretKey: ${JSON.stringify(state.secretKey)},
       bearer: 'smoke-access',
     }).then(r => JSON.stringify(r))`,
  );
  check('a REAL SRP-6a unlock succeeds', String(unlocked).includes('"unlocked"'), String(unlocked));

  // 8. AND THE ITEM DECRYPTS — the master key really was unwrapped, in a worker,
  //    in a browser.
  const listed = await ev(
    `chrome.runtime.sendMessage({target:'offscreen',kind:'list',bearer:'smoke-access'}).then(r=>JSON.stringify(r))`,
  );
  check(
    'an item decrypts to its title',
    String(listed).includes(state.itemTitle),
    String(listed).slice(0, 160),
  );

  // 9. A WRONG SECRET KEY IS REFUSED BY THE SERVER, not by a fixture.
  await ev(`chrome.runtime.sendMessage({target:'offscreen',kind:'lock',bearer:'smoke-access'})`);
  const wrong = await ev(
    `chrome.runtime.sendMessage({
       target:'offscreen', kind:'unlock',
       userId: ${JSON.stringify(state.userId)},
       password: ${JSON.stringify(state.password)},
       secretKey: 'ES1-AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD',
       bearer: 'smoke-access',
     }).then(r => JSON.stringify(r))`,
  );
  check(
    'a wrong Secret Key is refused',
    !String(wrong).includes('"unlocked"'),
    String(wrong).slice(0, 120),
  );

  // 10. THE CENTRAL CLAIM, over bytes that crossed a real socket.
  const requests = await (await fetch(`http://127.0.0.1:${PORT}/__requests`)).json();
  const wire = JSON.stringify(requests);
  const leaked = [
    ['the vault password', state.password],
    ['the Secret Key', state.secretKey],
    ['the Secret Key, ungrouped', String(state.secretKey).replace(/-/g, '')],
    ['the item secret', state.itemSecret],
  ].filter(([, needle]) => needle && wire.includes(needle));
  check(
    'nothing key-derived reached the wire',
    leaked.length === 0,
    leaked.length
      ? `LEAKED: ${leaked.map(([n]) => n).join(', ')}`
      : `${requests.length} requests inspected`,
  );

  // Anti-vacuity: a run that inspected nothing would pass the line above.
  check(
    'the run actually exercised the transport',
    requests.length >= 4,
    `${requests.length} requests`,
  );

  b.close();
} finally {
  chrome?.kill();
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n  ${checks.length - failed.length}/${checks.length} checks passed\n`);
if (failed.length) {
  console.error(`::error::browser smoke failed: ${failed.map((f) => f.name).join('; ')}`);
  process.exit(1);
}
