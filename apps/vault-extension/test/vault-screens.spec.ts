/**
 * The vault half of the popup.
 *
 * What is worth pinning is which SCREEN a given outcome produces — the step-up
 * is an expected step rather than an error, a wrong password must not read as a
 * lost pairing, and the Secret Key is remembered only after one has actually
 * opened the vault.
 */
import 'fake-indexeddb/auto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { messages } from '../src/copy';
import { rememberedSecretKey, rememberSecretKey } from '../src/secret-key-store';
import type { ApiResult } from '../src/api';
import { mountVaultScreens } from '../src/vault-screens';
import { TEST_ORIGIN } from './chrome-double';

const USER = '11111111-2222-4333-8444-555555555555';
const BEARER = 'extension-access-token';
/** What a popup held past fifteen minutes still has in hand. */
const STALE_BEARER = 'extension-access-token-expired';
/** What a refresh hands back in its place. */
const FRESH_BEARER = 'extension-access-token-rotated';

interface Wired {
  injected: unknown[];
  sent: unknown[];
  fetched: { url: string; body: string }[];
  /** Move the active tab after the screen has rendered. */
  navigate: (url: string | null) => void;
  /** Make the active tab a DIFFERENT tab than the one that was rendered. */
  moveToAnotherTab: () => void;
  /** Make `executeScript` fail the way a lapsed activeTab grant does. */
  refuseInjection: () => void;
}

/**
 * A chrome double whose `sendMessage` is scripted per message kind, plus a
 * `fetch` for the one call this module makes directly (the step-up).
 */
function wire(
  reply: (message: { kind?: string; bearer?: string }) => unknown,
  fetchStatus: { status: number; body?: unknown } = { status: 200 },
  // `null` means "no active tab we may see". NOT `undefined`, because passing
  // `undefined` explicitly SELECTS a default parameter — which silently gave
  // the no-tab case the default URL and made it pass for the wrong reason.
  pageUrl: string | null = 'https://example.com/login',
): Wired {
  const sent: unknown[] = [];
  const fetched: { url: string; body: string }[] = [];
  const injected: unknown[] = [];
  // MUTABLE, so a case can move the tab BETWEEN the render and the gesture —
  // which is the whole of what the fill-time re-read defends against and what
  // a fixed URL could never express.
  const tab = { id: 1, url: pageUrl };
  let injectionThrows = false;
  (globalThis as { chrome?: unknown }).chrome = {
    tabs: {
      query: () => Promise.resolve(tab.url === null ? [] : [{ id: tab.id, url: tab.url }]),
    },
    scripting: {
      executeScript: (injection: unknown) => {
        injected.push(injection);
        if (injectionThrows) {
          // What the platform does when the grant has lapsed or the tab is gone.
          return Promise.reject(new Error('Cannot access contents of the page'));
        }
        return Promise.resolve([
          { frameId: 0, result: { filledUsername: true, filledSecret: true } },
        ]);
      },
    },
    runtime: {
      getManifest: () => ({ host_permissions: [`${TEST_ORIGIN}/*`] }),
      getURL: (p: string) => p,
      sendMessage: (message: unknown) => {
        sent.push(message);
        return Promise.resolve(reply(message as { kind?: string }));
      },
      onMessage: { addListener: () => undefined },
    },
  };
  (globalThis as { fetch?: unknown }).fetch = (url: unknown, init: RequestInit) => {
    fetched.push({ url: String(url), body: typeof init.body === 'string' ? init.body : '' });
    return Promise.resolve({
      ok: fetchStatus.status >= 200 && fetchStatus.status < 300,
      status: fetchStatus.status,
      text: () => Promise.resolve(JSON.stringify(fetchStatus.body ?? {})),
    } as unknown as Response);
  };
  return {
    sent,
    fetched,
    injected,
    navigate: (url: string | null) => {
      tab.url = url;
    },
    moveToAnotherTab: () => {
      tab.id = 99;
    },
    refuseInjection: () => {
      injectionThrows = true;
    },
  };
}

/**
 * The `call` capability the popup supplies, as a test double.
 *
 * PASSTHROUGH BY DEFAULT, and that is a deliberate choice about what the other
 * thirty-two cases in this file are for. They assert screens, copy and
 * gestures; routing every one of them through a real `withSession` would couple
 * an assertion about a fill button to token-rotation mechanics, so the diff
 * that changed one would break the other. The refresh BEHAVIOUR is exercised by
 * the cases that opt into `expiringOnce()`, which is where it belongs.
 *
 * It still carries the load-bearing property: `vault-screens` receives no
 * bearer and can obtain one only by asking.
 */
function passthrough(bearer: string = BEARER): {
  call: <T>(fn: (b: string) => Promise<ApiResult<T>>) => Promise<ApiResult<T>>;
  presented: string[];
} {
  const presented: string[] = [];
  return {
    call: <T>(fn: (b: string) => Promise<ApiResult<T>>): Promise<ApiResult<T>> => {
      presented.push(bearer);
      return fn(bearer);
    },
    presented,
  };
}

/**
 * A `call` that behaves as `withSession` does across an access-token expiry:
 * the first attempt of every call answers `UNAUTHENTICATED`, then the SAME call
 * is retried on a fresh bearer and its real answer returned.
 *
 * This reproduces the popup's contract rather than importing `withSession`. The
 * unit under test is `vault-screens`, and what it has to prove is that each of
 * its actions goes THROUGH the capability instead of around it. Whether
 * `withSession` itself refreshes correctly is `session.spec.ts`'s question and
 * is answered there — stating which layer proves what, because a guard that
 * exists at two layers needs each test to say which one it covers.
 */
function expiringOnce(): {
  call: <T>(fn: (b: string) => Promise<ApiResult<T>>) => Promise<ApiResult<T>>;
  presented: string[];
} {
  const presented: string[] = [];
  // ROTATION IS MODELLED, because the popup's really is: `callOnLiveSession`
  // writes the refreshed session back with `rotateSession`, so the SECOND call
  // starts on the fresh credential. A double that re-presented the expired one
  // every time would make "refreshed once" and "refreshes on every call"
  // indistinguishable — and the second is what a stale capture looks like.
  let current = STALE_BEARER;
  return {
    call: async <T>(fn: (b: string) => Promise<ApiResult<T>>): Promise<ApiResult<T>> => {
      presented.push(current);
      const first = await fn(current);
      if (first.ok || first.code !== 'UNAUTHENTICATED') return first;
      current = FRESH_BEARER;
      presented.push(current);
      return fn(current);
    },
    presented,
  };
}

function host(): HTMLElement {
  document.body.replaceChildren();
  const node = document.createElement('div');
  document.body.append(node);
  return node;
}

/**
 * WAIT FOR THE CONDITION, DO NOT RACE IT.
 *
 * A fixed tick was enough until the unlock path grew an IndexedDB write between
 * the reply and the redraw, and then it was intermittently one macrotask short
 * — the same shape as the `StepUpPrompt` flake earlier in this milestone, where
 * a test assumed a teardown had happened instead of waiting for it. Polling to
 * a deadline states the precondition rather than assuming it.
 */
async function until(predicate: () => boolean, what: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(`timed out waiting for ${what}; screen was: ${text()}`);
}

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));
const text = (): string => document.body.textContent ?? '';
const button = (name: RegExp): HTMLButtonElement => {
  const found = [...document.querySelectorAll('button')].find((b) =>
    name.test(b.textContent ?? ''),
  );
  if (!found) throw new Error(`no button matching ${String(name)} in: ${text()}`);
  return found;
};

const LOCKED = { ok: true, state: { status: 'locked' } };

/* ------------------------------------------------------------------------- *
 * WHAT `POST /v1/auth/stepup` CAN ACTUALLY ANSWER, WALKED OUT OF IDENTITY.
 *
 * Derived rather than listed, because the list is what was wrong. The corpus is
 * the guards the controller decorates the handler with, plus the transitive
 * closure of private methods `stepUp` calls — so a refusal added to either
 * arrives here red instead of unnoticed.
 *
 * CROSS-PACKAGE BY DESIGN, and declared: `apps/vault-extension/turbo.json`
 * already widens this package's `test` inputs to the repo, which is what stops
 * a change to identity's vocabulary replaying a cached green here.
 * ------------------------------------------------------------------------- */

const IDENTITY_SRC = join(__dirname, '..', '..', 'services', 'identity', 'src');

/** Comments out, so a derivation never reads documentation as code. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
}

const NEST_STATUS: ReadonlyMap<string, number> = new Map([
  ['BadRequestException', 400],
  ['UnauthorizedException', 401],
  ['ForbiddenException', 403],
  ['NotFoundException', 404],
]);
const EXPLICIT_STATUS: ReadonlyMap<string, number> = new Map([
  ['HttpStatus.TOO_MANY_REQUESTS', 429],
]);

interface Refusal {
  readonly status: number;
  readonly token: string;
}

function throwsIn(src: string): Refusal[] {
  const out: Refusal[] = [];
  const pattern = /throw new (\w+)\(\{\s*error:\s*'([a-z_]+)'\s*\}(?:\s*,\s*(HttpStatus\.\w+))?/g;
  for (const m of src.matchAll(pattern)) {
    const explicit = m[3];
    const status =
      explicit === undefined ? NEST_STATUS.get(m[1] as string) : EXPLICIT_STATUS.get(explicit);
    if (status !== undefined) out.push({ status, token: m[2] as string });
  }
  return out;
}

/** Every `export class X` in identity, so a guard name resolves to its file. */
function classFiles(): ReadonlyMap<string, string> {
  const found = new Map<string, string>();
  for (const file of readdirSync(IDENTITY_SRC).filter((f) => f.endsWith('.ts'))) {
    const src = readFileSync(join(IDENTITY_SRC, file), 'utf8');
    for (const m of src.matchAll(/export class (\w+)/g)) found.set(m[1] as string, file);
  }
  return found;
}

/** The guard classes decorating the `stepup` handler. */
function stepUpGuards(controller: string): string[] {
  const at = controller.indexOf("@Post('stepup')");
  expect(at).toBeGreaterThanOrEqual(0);
  const end = controller.indexOf('async ', at);
  expect(end).toBeGreaterThan(at);
  return [...controller.slice(at, end).matchAll(/@UseGuards\(([^)]*)\)/g)]
    .flatMap((m) => (m[1] as string).split(','))
    .map((name) => name.trim())
    .filter((name) => name.length > 0);
}

/** A method's body, by name, from a stripped service source. */
function methodBody(service: string, name: string): string | null {
  // NOT `async`-only. A private helper that throws needs no `await` to do it,
  // and a walk that could only see async methods would step over one silently.
  const found = new RegExp(`\\n  (?:private )?(?:async )?${name}\\(`).exec(service);
  if (!found) return null;
  const end = service.indexOf('\n  }\n', found.index);
  return end < 0 ? service.slice(found.index) : service.slice(found.index, end);
}

/**
 * `this.X(` targets that are NOT methods of this class, with the reason. A call
 * the walk cannot resolve is otherwise indistinguishable from a method with no
 * throws in it — the walk would step over a whole subtree and report a shorter,
 * perfectly plausible answer.
 */
const NOT_A_METHOD: ReadonlyMap<string, string> = new Map([
  ['clock', 'An injected `() => Date` on the class, not a method. It cannot throw a refusal.'],
]);

/**
 * Throw forms this walk can READ. Anything else in a reachable body is a
 * refusal the corpus cannot see.
 *
 * The idiom that forces this is in the very file being walked:
 * `throw invalidCredentials()` appears seven times in `auth.service.ts`, where
 * the helper builds the exception elsewhere. None of those sites is reachable
 * from `stepUp` today — but "not today" is exactly the claim that rots, and a
 * corpus narrower than its stated guarantee goes green for the same reason it
 * is wrong. So an unreadable throw in a reachable body turns this fence RED
 * rather than quietly shrinking it, on the same principle as the residual
 * fence's marker list.
 */
const READABLE_THROW = /throw new \w+\(\{\s*error:/;

/** `stepUp` plus everything it calls on `this`, to a fixed point. */
function reachableFromStepUp(service: string): {
  methods: string[];
  refusals: Refusal[];
  unresolved: string[];
  unreadableThrows: string[];
} {
  const seen = new Set<string>();
  const stack = ['stepUp'];
  const refusals: Refusal[] = [];
  const unresolved: string[] = [];
  const unreadableThrows: string[] = [];
  while (stack.length > 0) {
    const name = stack.pop() as string;
    if (seen.has(name)) continue;
    seen.add(name);
    const body = methodBody(service, name);
    if (body === null) {
      if (!NOT_A_METHOD.has(name)) unresolved.push(name);
      continue;
    }
    refusals.push(...throwsIn(body));
    for (const line of body.matchAll(/^\s*throw .*/gm)) {
      const text = line[0].trim();
      if (!READABLE_THROW.test(text)) unreadableThrows.push(`${name}: ${text}`);
    }
    for (const m of body.matchAll(/this\.(\w+)\(/g)) {
      if (!seen.has(m[1] as string)) stack.push(m[1] as string);
    }
  }
  return { methods: [...seen].sort(), refusals, unresolved, unreadableThrows };
}

function stepUpRefusals(): { refusals: Refusal[]; guards: string[]; methods: string[] } {
  const files = classFiles();
  const controller = stripComments(readFileSync(join(IDENTITY_SRC, 'auth.controller.ts'), 'utf8'));
  const guards = stepUpGuards(controller);
  const all: Refusal[] = [];
  for (const guard of guards) {
    const file = files.get(guard);
    expect(file).toBeDefined();
    all.push(...throwsIn(stripComments(readFileSync(join(IDENTITY_SRC, file as string), 'utf8'))));
  }
  const service = stripComments(readFileSync(join(IDENTITY_SRC, 'auth.service.ts'), 'utf8'));
  const walked = reachableFromStepUp(service);
  all.push(...walked.refusals);
  // THE WALK'S OWN BLIND SPOTS, surfaced rather than absorbed. A call that
  // resolved to nothing and a throw this parser cannot read are both ways for
  // the corpus to be narrower than the guarantee stated above it.
  expect(walked.unresolved).toEqual([]);
  expect(walked.unreadableThrows).toEqual([]);
  const staleNotMethod = [...NOT_A_METHOD.keys()].filter((n) => !walked.methods.includes(n));
  expect(staleNotMethod).toEqual([]);
  const unique = new Map<string, Refusal>();
  for (const r of all) unique.set(`${r.status} ${r.token}`, r);
  return {
    refusals: [...unique.values()].sort((a, b) =>
      a.status === b.status ? a.token.localeCompare(b.token) : a.status - b.status,
    ),
    guards,
    methods: walked.methods,
  };
}

describe('the vault half holds no credential of its own', () => {
  const SCREENS = join(__dirname, '..', 'src', 'vault-screens.ts');
  const CLIENT = join(__dirname, '..', 'src', 'vault-client.ts');

  /** Comments out, so a fence never reads its own documentation. */
  function strip(src: string): string {
    return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
  }

  /**
   * The `vault-client` exports that TAKE A BEARER, from their own signatures.
   *
   * Derived rather than listed, and the distinction earns its keep immediately:
   * `vaultState()` takes none and so must NOT be required to sit inside a
   * wrapper. A hand-written exclusion list would have said the same thing today
   * and rotted the first time a function gained or lost the parameter.
   */
  function credentialTaking(): string[] {
    const src = strip(readFileSync(CLIENT, 'utf8'));
    const found: string[] = [];
    for (const m of src.matchAll(/export async function (\w+)\(([\s\S]*?)\)\s*:/g)) {
      if (/\bbearer\b/.test(m[2] as string)) found.push(m[1] as string);
    }
    return found.sort();
  }

  /**
   * The source ranges covered by a `call(...)` wrapper, by matching parens.
   *
   * Not a line-based check: two of these wrappers span a dozen lines, and a
   * regex that stopped at the newline would call them absent and go red for a
   * reason that has nothing to do with the property.
   */
  function wrapperRanges(src: string): [number, number][] {
    const ranges: [number, number][] = [];
    for (const m of src.matchAll(/\bcall\(/g)) {
      let depth = 0;
      const open = m.index + m[0].length - 1;
      for (let i = open; i < src.length; i += 1) {
        if (src[i] === '(') depth += 1;
        else if (src[i] === ')') {
          depth -= 1;
          if (depth === 0) {
            ranges.push([m.index, i]);
            break;
          }
        }
      }
    }
    return ranges;
  }

  const inside = (ranges: [number, number][], at: number): boolean =>
    ranges.some(([from, to]) => at >= from && at <= to);

  it('takes a CAPABILITY, never a bearer — the deps interface says so', () => {
    const src = strip(readFileSync(SCREENS, 'utf8'));
    const start = src.indexOf('export interface VaultScreensDeps');
    expect(start).toBeGreaterThanOrEqual(0);
    const end = src.indexOf('}', start);
    expect(end).toBeGreaterThan(start);
    const body = src.slice(start, end);
    // THE WHOLE DEFECT, in one assertion. A `readonly bearer: string` here is a
    // credential captured at mount and spent for the life of the popup, which
    // is what made a fifteen-minute-old token read as an un-paired device.
    // MEMBERS, not mentions: the surviving `bearer` in this block is the name of
    // a PARAMETER inside `call`'s type, which binds nothing and is erased at
    // build. Renaming it would make the assertion below simpler and prove less.
    expect(body).not.toMatch(/readonly\s+bearer\b/);
    expect(body).not.toMatch(/^\s*bearer\s*[?:]/m);
    expect(body).toMatch(/readonly call:/);
  });

  it('obtains a bearer ONLY from the capability, at every site that needs one', () => {
    const src = strip(readFileSync(SCREENS, 'utf8'));
    const ranges = wrapperRanges(src);
    const takers = credentialTaking();

    // ANTI-VACUITY, at BOTH levels. An empty derivation would satisfy every
    // "nothing outside" assertion below, and so would a source that made no
    // calls at all. Both floors, plus a member that must be there.
    expect(takers.length).toBeGreaterThanOrEqual(6);
    expect(takers).toContain('listItems');
    expect(takers).not.toContain('vaultState');
    expect(ranges.length).toBeGreaterThanOrEqual(8);

    // Every credential-taking client call sits inside a wrapper...
    const strayCalls: string[] = [];
    for (const name of [...takers, 'request']) {
      for (const m of src.matchAll(new RegExp(`\\b${name}\\(`, 'g'))) {
        if (!inside(ranges, m.index)) strayCalls.push(`${name} @${String(m.index)}`);
      }
    }
    expect(strayCalls).toEqual([]);

    // ...and so does every RUNTIME mention of a bearer, so there is no way to
    // hold one that this fence cannot see. Anchored on the identifier the
    // runtime reads, not on a call shape a later edit could rename around.
    //
    // THE DEPS INTERFACE IS CUT OUT OF THE CORPUS, with its reason and its own
    // assertion above rather than as a silent exemption: it is a TYPE, erased
    // at build, and the one `bearer` in it names a parameter of `call`'s
    // signature. Stating the corpus is the point — a fence whose input is
    // narrower than its claim goes green for the same reason it is wrong.
    const iface = src.indexOf('export interface VaultScreensDeps');
    const ifaceEnd = src.indexOf('}', iface);
    expect(ifaceEnd).toBeGreaterThan(iface);
    const runtime = [...src.matchAll(/\bbearer\b/g)].filter(
      (m) => m.index < iface || m.index > ifaceEnd,
    );
    // ANTI-VACUITY: cutting the interface must not cut everything.
    expect(runtime.length).toBeGreaterThanOrEqual(8);
    const stray = runtime.filter((m) => !inside(ranges, m.index)).map((m) => `@${String(m.index)}`);
    expect(stray).toEqual([]);
  });
});

describe('a popup held past the access token’s fifteen minutes', () => {
  afterEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  /**
   * WHAT THIS IS ABOUT. The access token lives fifteen minutes; the session
   * lives thirty days. Until M44 PR2 `vault-screens` was handed one bearer at
   * mount and spent it forever, so a popup left open across that boundary
   * answered every action `UNAUTHENTICATED` and told the user "This device is
   * no longer connected to your account … Connect it again to continue" about
   * a pairing that was perfectly alive — naming re-pairing, which costs a
   * step-up on the app origin, as the remedy for a token that had merely aged.
   *
   * The three cases below are a DISCRIMINATION SET, not three coverage points.
   * A screen that simply always retried would pass the first two and fail the
   * third; a screen that never retried would pass the first and third. Only
   * all three together say the two conditions are told apart.
   */

  const ITEM = { id: 'i-1', itemType: 'password', title: 'Bank login' };

  /** Unlocked, listing one item — but only for a bearer the server accepts. */
  function acceptingOnly(live: string) {
    return (message: { kind?: string; bearer?: string }): unknown => {
      if (message.kind === 'state') return { ok: true, state: { status: 'unlocked' } };
      if (message.bearer !== undefined && message.bearer !== live) {
        return { ok: false, code: 'UNAUTHENTICATED' };
      }
      if (message.kind === 'list') return { ok: true, items: [ITEM] };
      return { ok: true, state: { status: 'unlocked' } };
    };
  }

  it('CONTROL: with a live bearer the list renders, so the fixture reaches the branch', async () => {
    wire(acceptingOnly(BEARER));
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Bank login'), 'the list to render');
    expect(text()).not.toContain('no longer connected');
  });

  it('refreshes and shows the vault, instead of claiming the device was disconnected', async () => {
    wire(acceptingOnly(FRESH_BEARER));
    const capability = expiringOnce();
    await mountVaultScreens({ host: host(), userId: USER, call: capability.call });

    await until(() => text().includes('Bank login'), 'the list to render after a refresh');
    // The defect, named as an assertion rather than implied by the absence of
    // one: this is the sentence a live pairing must never be given.
    expect(text()).not.toContain('no longer connected');
    // It really did take two credentials to get there — otherwise this passes
    // for want of an expiry rather than because a refresh happened. And the
    // expired one is presented EXACTLY ONCE: the screen makes several calls,
    // and every one of them re-presenting a dead token is precisely what the
    // snapshot defect looked like.
    expect(capability.presented[0]).toBe(STALE_BEARER);
    expect(capability.presented.filter((b) => b === STALE_BEARER)).toHaveLength(1);
    expect(capability.presented.filter((b) => b === FRESH_BEARER).length).toBeGreaterThan(1);
  });

  it('still reports a REVOKED pairing as disconnected — a refresh that fails is not an expiry', async () => {
    // Nothing this double accepts: the refresh happened and the session is
    // genuinely gone, which is the case the copy is TRUE about.
    wire(acceptingOnly('a-credential-the-server-will-never-accept'));
    await mountVaultScreens({ host: host(), userId: USER, call: expiringOnce().call });
    await until(() => text().includes('no longer connected'), 'the disconnected copy');
    expect(text()).not.toContain('Bank login');
  });

  it('routes the STEP-UP call through the capability too, not around it', async () => {
    // The one call in this module that does not go through `vault-client` — it
    // is a direct `request()` to the identity proxy, and it was the eighth
    // raw-bearer site. A fix applied to seven of eight is a rule half-applied.
    const { fetched } = wire(
      (message) =>
        message.kind === 'unlock'
          ? { ok: false, code: 'STEPUP_REQUIRED' }
          : { ok: true, state: { status: 'locked' } },
      { status: 200 },
    );
    const capability = expiringOnce();
    await mountVaultScreens({ host: host(), userId: USER, call: capability.call });

    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    button(/Open vault/).click();
    await until(() => document.querySelector('#stepup-code') !== null, 'the code field');

    (document.querySelector('#stepup-code') as HTMLInputElement).value = '123456';
    button(/Confirm$/).click();
    await until(() => fetched.length > 0, 'the step-up request');
    expect(capability.presented.length).toBeGreaterThan(0);
  });
});

describe('the vault screens', () => {
  afterEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  it('offers an unlock form when the vault is locked', async () => {
    wire(() => LOCKED);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });

    expect(text()).toContain('Vault locked');
    expect(document.querySelector('#vault-password')).not.toBeNull();
    expect(document.querySelector('#secret-key')).not.toBeNull();
    // The cost of remembering is stated next to the choice, not implied.
    expect(text()).toContain('can read a remembered Secret Key');
  });

  it('opens, lists what is inside, and remembers the Secret Key only after it worked', async () => {
    wire((message) =>
      message.kind === 'unlock'
        ? { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } }
        : message.kind === 'list'
          ? { ok: true, items: [{ id: 'i-1', itemType: 'password', title: 'Bank login' }] }
          : LOCKED,
    );
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });

    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    (document.querySelector('#remember') as HTMLInputElement).checked = true;
    button(/Open vault/).click();
    await until(() => text().includes('Vault open'), 'the vault to open');

    expect(text()).toContain('Bank login');
    expect(await rememberedSecretKey(USER)).toBe('ES1-GOOD');
  });

  it('does NOT remember a Secret Key that failed to open the vault', async () => {
    // A typo persisted as the device's key would break every later unlock and
    // look like a corrupted device rather than a mistake.
    await rememberSecretKey(USER, 'ES1-PREVIOUS');
    wire((message) => (message.kind === 'unlock' ? { ok: false, code: 'SRP_FAILED' } : LOCKED));
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });

    (document.querySelector('#vault-password') as HTMLInputElement).value = 'wrong';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-TYPO';
    button(/Open vault/).click();
    await until(() => text().includes(messages.SRP_FAILED), 'the refusal');

    expect(await rememberedSecretKey(USER)).toBe('ES1-PREVIOUS');
  });

  it('treats a required step-up as a STEP, not a failure', async () => {
    // Both SRP legs are step-up gated, so this is the expected path — and it is
    // answered in place rather than by sending the user back to Estate, which
    // would mean re-pairing.
    const { fetched } = wire(
      (message) => (message.kind === 'unlock' ? { ok: false, code: 'STEPUP_REQUIRED' } : LOCKED),
      { status: 200 },
    );
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    button(/Open vault/).click();
    await settle();

    expect(text()).toContain('Confirm it’s you');
    (document.querySelector('#stepup-code') as HTMLInputElement).value = '123456';
    button(/Confirm/).click();
    await settle();

    expect(fetched[0]?.url).toBe(`${TEST_ORIGIN}/api/auth/stepup`);
    expect(JSON.parse(fetched[0]?.body ?? '{}')).toEqual({ code: '123456' });
    // Back to the unlock form, ready to retry.
    expect(text()).toContain('Vault locked');
  });

  it('refuses a malformed code before spending an attempt', async () => {
    const { fetched } = wire((message) =>
      message.kind === 'unlock' ? { ok: false, code: 'STEPUP_REQUIRED' } : LOCKED,
    );
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    button(/Open vault/).click();
    await settle();

    (document.querySelector('#stepup-code') as HTMLInputElement).value = '12ab';
    button(/Confirm/).click();
    await settle();

    expect(text()).toContain('Enter the six digits.');
    expect(fetched).toHaveLength(0);
  });

  /*
   * THE STEP-UP REFUSALS, DERIVED RATHER THAN IMAGINED (M27 PR6).
   *
   * What stood here was one test called "names the CODE when a step-up is
   * refused, never a password", answering `401 unauthorized`. That IS a real
   * token — `SessionGuard` throws it — but it is what a DEAD PAIRING looks
   * like, not a rejected code. So a test named for one property exercised the
   * boundary of another, and stayed green while the screen answered a mistyped
   * authenticator digit with PAIRING copy: "create a new one in Estate under
   * Security", about a number that is read rather than created.
   *
   * The arm was keyed on `UNAUTHENTICATED`, lifted from
   * `apps/vault-web/src/client/stepup.ts` where that WAS the right code because
   * that origin then mapped every 401 to it. M44 PR1 split `invalid_code` out
   * there as well — the same defect, mirrored — so the premise this sentence
   * describes is now historical. What did not depend on it: this client splits
   * 401 three ways, so the copied expression named a different failure here and
   * the two sentences came out swapped. identity had already anticipated exactly this: the 429 helper's
   * comment says the cap gets its own token and never `invalid_code`, "the M12
   * lesson about one token changing meaning with the surface".
   */
  async function refusalText(status: number, token: string): Promise<string> {
    const { fetched } = wire(
      (message) => (message.kind === 'unlock' ? { ok: false, code: 'STEPUP_REQUIRED' } : LOCKED),
      { status, body: { error: token } },
    );
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    (document.querySelector('#vault-password') as HTMLInputElement).value = 'pw';
    (document.querySelector('#secret-key') as HTMLInputElement).value = 'ES1-GOOD';
    button(/Open vault/).click();
    await until(() => document.querySelector('#stepup-code') !== null, 'the step-up form');
    (document.querySelector('#stepup-code') as HTMLInputElement).value = '123456';
    button(/Confirm/).click();
    // STAGED ON THE ERROR NODE, not on a tick: the call and the redraw are two
    // hops, and this file's own `until` exists because a fixed tick flaked here.
    await until(() => document.querySelector('p.error') !== null, `the refusal for ${token}`);
    expect(fetched).toHaveLength(1);
    return document.querySelector('p.error')?.textContent ?? '';
  }

  /**
   * REFUSALS THIS SCREEN ANSWERS GENERICALLY ON PURPOSE, each with its reason.
   * A refusal is here or it has a sentence of its own; there is no third state,
   * which is the whole point of the unclassified check below.
   */
  const GENERIC: ReadonlyMap<string, string> = new Map([
    [
      '400 invalid_request',
      'Not a user condition here. It comes from `requireAuth`, whose own comment calls it unreachable behind SessionGuard, and from the body schema — which CODE_PATTERN refuses before the network. Either is a bug in THIS extension, and UNKNOWN is the honest sentence for one.',
    ],
  ]);

  it('derives what the step-up route can refuse, out of identity itself', () => {
    const { refusals, guards, methods } = stepUpRefusals();
    // ANTI-VACUITY AT EVERY LEVEL, not just the total. A walk that resolved no
    // guards and a walk that entered no methods both yield a short list that
    // would agree with a hand-written expectation.
    expect(guards).toContain('SessionGuard');
    expect(methods).toContain('stepUp');
    expect(methods).toContain('refuseStepUpForRate');
    expect(methods.length).toBeGreaterThanOrEqual(4);
    // SETS, not counts: a mis-attribution preserves a count.
    //
    // Pinned exactly, so a refusal ADDED to identity arrives red here instead
    // of unnoticed. Measured: inserting one throw into `stepUp` reddens this
    // and names the new token in the diff. Disabling the closure walk reddens
    // it too, which is why the method assertions above are not decoration.
    expect(refusals.map((r) => `${r.status} ${r.token}`)).toEqual([
      '400 invalid_request',
      '401 invalid_code',
      '401 unauthorized',
      '429 too_many_attempts',
    ]);
  });

  it('answers a rejected code about the AUTHENTICATOR, never about pairing', async () => {
    const shown = await refusalText(401, 'invalid_code');
    expect(shown).toContain('Codes last about 30 seconds');
    // THE DEFECT, NAMED. `invalid_code` is also identity's answer for a refused
    // PAIRING code; reading it as pairing everywhere sent someone who mistyped
    // six digits to Estate's Security screen to create a replacement.
    expect(shown).not.toBe(messages.INVALID_CODE);
    expect(shown).not.toContain('Estate under Security');
  });

  it('answers a revoked pairing about the DEVICE, never about the code', async () => {
    const shown = await refusalText(401, 'unauthorized');
    expect(shown).toBe(messages.UNAUTHENTICATED);
    // The arm the replaced test actually exercised while claiming the other.
    expect(shown).not.toContain('30 seconds');
  });

  it('answers the guessing cap as a limit, never as an outage', async () => {
    const shown = await refusalText(429, 'too_many_attempts');
    expect(shown).toBe(messages.TOO_MANY_ATTEMPTS);
    expect(shown).not.toBe(messages.UNKNOWN);
    // It must neither blame the code nor invite the retry the cap is refusing.
    expect(shown).not.toContain('30 seconds');
    expect(shown).not.toContain('try again in a moment');
  });

  it('gives every refusal on this route a sentence of its OWN', async () => {
    /*
     * DISCRIMINATION, NOT COVERAGE. "Every refusal renders a sentence" is
     * satisfied by a screen rendering ONE sentence for all of them — which is
     * the shape of the defect this replaced. Only the pairwise comparison
     * closes it, and an equivalence assertion is half a specification.
     *
     * WHAT THIS TEST DOES NOT CATCH, measured rather than assumed. Reverting
     * the discriminator in `vault-screens.ts` leaves this test GREEN: a SWAP
     * preserves distinctness, so three wrong sentences are still three
     * different ones. The two named tests above are what catch a permutation;
     * this one catches a COLLAPSE.
     *
     * ITS POSITIVE CONTROL is collapsing the cap's sentence onto the
     * DEVICE-DISCONNECTED one (`messages.UNAUTHENTICATED`), which reddens this
     * test and nothing else.
     *
     * NOT onto the PAIRING sentence, and the difference is kept here because an
     * earlier draft of this comment named that mutation — which leaves all 37
     * tests green. `messages.INVALID_CODE` is unreachable FROM THIS SCREEN: a
     * rejected code renders the inline sentence above, so collapsing onto the
     * pairing copy collides with nothing and proves nothing. A positive control
     * has to name a mutation somebody actually ran, or it is the same
     * unverified claim about the tree this whole file exists to refuse.
     */
    const { refusals } = stepUpRefusals();
    // A reason recorded for a refusal that no longer exists is a claim about the
    // tree nobody checks — this repo's most repeated defect, in miniature.
    const stale = [...GENERIC.keys()].filter(
      (key) => !refusals.some((r) => `${r.status} ${r.token}` === key),
    );
    expect(stale).toEqual([]);

    const shown = new Map<string, string>();
    for (const r of refusals) {
      const key = `${r.status} ${r.token}`;
      if (GENERIC.has(key)) continue;
      shown.set(key, await refusalText(r.status, r.token));
    }
    /*
     * A refusal not declared GENERIC must have a sentence of its OWN, which
     * means it must not be the generic sentence either.
     *
     * The first draft of this check only inspected refusals at status 400 while
     * the test claimed every refusal on the route — a fence whose input was
     * narrower than its claim, which is the exact defect this file exists to
     * catch, committed inside it. A new refusal falling through to UNKNOWN
     * would have been DISTINCT from the other three and passed the pairwise
     * comparison below while saying nothing at all to the user.
     */
    const spokenGenerically = [...shown.entries()]
      .filter(([, sentence]) => sentence === messages.UNKNOWN)
      .map(([key]) => key);
    expect(spokenGenerically).toEqual([]);
    // ANTI-VACUITY: a loop that drove nothing also produces no clashes below.
    expect(shown.size).toBe(3);
    const bySentence = new Map<string, string[]>();
    for (const [key, sentence] of shown) {
      bySentence.set(sentence, [...(bySentence.get(sentence) ?? []), key]);
    }
    expect([...bySentence.values()].filter((keys) => keys.length > 1)).toEqual([]);
  });

  it('locks on request, and comes back to the unlock form', async () => {
    wire((message) =>
      message.kind === 'list'
        ? { ok: true, items: [] }
        : message.kind === 'lock'
          ? LOCKED
          : { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } },
    );
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    expect(text()).toContain('Vault open');
    expect(text()).toContain('No items in this vault yet.');

    button(/Lock/).click();
    await settle();
    expect(text()).toContain('Vault locked');
  });

  it('shows an unreadable item as present rather than hiding it', async () => {
    wire((message) =>
      message.kind === 'list'
        ? { ok: true, items: [{ id: 'i', itemType: 'password', title: '', unreadable: true }] }
        : { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } },
    );
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    expect(text()).toContain('could not be read');
  });

  it('renders an item title as TEXT, whatever it contains', async () => {
    wire((message) =>
      message.kind === 'list'
        ? { ok: true, items: [{ id: 'i', itemType: 'password', title: '<img src=x onerror=1>' }] }
        : { ok: true, state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' } },
    );
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    expect(document.querySelector('img')).toBeNull();
    expect(text()).toContain('<img src=x onerror=1>');
  });

  it('an unreachable offscreen document offers the unlock form, with the reason', async () => {
    // Not a dead end: the only thing this screen can offer is an unlock, so it
    // shows the form and attaches why the state read failed.
    wire(() => undefined);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    expect(text()).toContain('Vault locked');
    expect(text()).toContain(messages.UNAVAILABLE);
  });
});

describe('what is saved for the page you are on', () => {
  afterEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  const unlocked = {
    ok: true,
    state: { status: 'unlocked', expiresAt: '2099-01-01T00:00:00.000Z' },
  };

  function openWith(
    matched: unknown,
    pageUrl: string | null = 'https://example.com/login',
    fill: unknown = { ok: true, credential: { username: 'someone', secret: 's3cret' } },
  ): Wired {
    return wire(
      (message) =>
        message.kind === 'list'
          ? { ok: true, items: [] }
          : message.kind === 'matches'
            ? { ok: true, matched }
            : message.kind === 'fill'
              ? fill
              : unlocked,
      { status: 200 },
      pageUrl,
    );
  }

  it('names the site and lists what matches it', async () => {
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'match', domain: 'example.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('For example.com'), 'the per-page section');
    expect(text()).toContain('Bank login — saved for this site');
  });

  it('SHOWS a confusable refusal rather than hiding it', async () => {
    // §4 TB9 refuses rather than warns — but a refusal the user cannot see is
    // indistinguishable from having nothing saved, which is the moment worth
    // telling them about.
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'confusable', savedDomain: 'example.com', pageDomain: 'exarnple.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('only looks like the saved one'), 'the refusal');
    expect(text()).not.toContain('saved for this site');
  });

  it('says why a downgrade is refused', async () => {
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'scheme-downgrade', domain: 'example.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('this page is not secure'), 'the downgrade refusal');
  });

  it('says plainly that nothing is saved here', async () => {
    openWith([]);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Nothing saved for this site'), 'the empty state');
  });

  it('offers a fill button on a MATCH, and on nothing else', async () => {
    /*
     * REWRITTEN IN PR3b, not deleted. This case was named "offers no fill button
     * anywhere — that is PR3b", and PR3b makes that false; deleting it would
     * leave the one screen that decides what is offered with no test of what it
     * offers. What it asserts now is the property that replaced the absence:
     * `isFillable` is the only predicate, so a refusal gets no control at all —
     * not even a disabled one, because a greyed-out button invites "how do I
     * enable it" and the answer is "you cannot, on purpose".
     */
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'match', domain: 'example.com' },
      },
      {
        id: 'j',
        itemType: 'password',
        title: 'Lookalike',
        verdict: { kind: 'confusable', savedDomain: 'example.com', pageDomain: 'exarnple.com' },
      },
      {
        id: 'k',
        itemType: 'password',
        title: 'Insecure',
        verdict: { kind: 'scheme-downgrade', domain: 'example.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('For example.com'), 'the per-page section');

    const fills = [...document.querySelectorAll('button')].filter((b) =>
      /^fill$/i.test(b.textContent ?? ''),
    );
    // Exactly one, for exactly the matching row.
    expect(fills).toHaveLength(1);
    expect(fills[0]?.closest('li')?.textContent).toContain('Bank login');
    // And no disabled control smuggled onto the refusals.
    expect([...document.querySelectorAll('button')].some((b) => b.hasAttribute('disabled'))).toBe(
      false,
    );
  });

  it('says on screen that filling does not make a site genuine', async () => {
    // docs/04 records this as a residual "*on screen*". This is the screen, and
    // the sentence is asserted rather than left to whoever writes the copy next.
    openWith([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank login',
        verdict: { kind: 'match', domain: 'example.com' },
      },
    ]);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('For example.com'), 'the per-page section');
    expect(text()).toContain('gives this page the password');
    expect(text()).toContain('cannot tell whether the site itself is genuine');
  });

  const MATCH = [
    {
      id: 'i',
      itemType: 'password',
      title: 'Bank login',
      verdict: { kind: 'match', domain: 'example.com' },
    },
  ];

  const pressFill = async (): Promise<void> => {
    await until(() => text().includes('For example.com'), 'the per-page section');
    const button = [...document.querySelectorAll('button')].find((b) =>
      /^fill$/i.test(b.textContent ?? ''),
    );
    if (!button) throw new Error(`no Fill button. Saw: ${text()}`);
    button.click();
  };

  it('fills, and says what Estate did rather than what the page will do', async () => {
    const wired = openWith(MATCH);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await pressFill();
    await until(() => text().includes('Filled'), 'the outcome');

    // The credential reached the page exactly once, as an argument.
    expect(wired.injected).toHaveLength(1);
    expect(JSON.stringify(wired.injected[0])).toContain('s3cret');
    // The copy used to assert "Nothing was submitted", which the extension
    // cannot know: the fill dispatches `input` and `change` and a page is free
    // to submit on either (measured). It says what IT did now, and points the
    // user at the one thing they can still check.
    expect(text()).toContain('Estate didn’t submit anything');
    expect(text()).not.toContain('Nothing was submitted');
  });

  /**
   * THE FILL-TIME RE-READ (M16 review).
   *
   * `vault-worker-core.ts` claimed the holder re-decides "because the page can
   * navigate between the two calls", and it could not: both calls got the same
   * captured string, so the second decision was f(x) === f(x) over the page URL.
   * These two cases are the ones that could not have passed before.
   */
  it('REFUSES to fill when the tab has navigated since the screen was drawn', async () => {
    const wired = openWith(MATCH);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('For example.com'), 'the per-page section');

    wired.navigate('https://evil.test/harvest');
    const button = [...document.querySelectorAll('button')].find((b) =>
      /^fill$/i.test(b.textContent ?? ''),
    );
    button?.click();

    await until(() => text().includes('This tab changed'), 'the refusal');
    // Nothing was decrypted and nothing was injected.
    expect(wired.injected).toHaveLength(0);
    expect(wired.sent.filter((m) => (m as { kind?: string }).kind === 'fill')).toHaveLength(0);
  });

  it('REFUSES when the active tab is no longer the tab that was rendered', async () => {
    const wired = openWith(MATCH);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('For example.com'), 'the per-page section');

    wired.moveToAnotherTab();
    const button = [...document.querySelectorAll('button')].find((b) =>
      /^fill$/i.test(b.textContent ?? ''),
    );
    button?.click();

    await until(() => text().includes('This tab changed'), 'the refusal');
    expect(wired.injected).toHaveLength(0);
  });

  it('a REFUSED injection is not reported as a page with no password field', async () => {
    // `ok: false` means the platform refused — navigated, closed, grant lapsed.
    // It used to render as a fact about the page's markup, which is a control
    // reading as an absence; `inject.spec.ts` keeps them apart and this caller
    // did not.
    const wired = openWith(MATCH);
    wired.refuseInjection();
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await pressFill();
    await until(() => text().includes('couldn’t reach that page'), 'the refusal');
    expect(text()).not.toContain('No password field was found');
  });

  it('warns ONCE about an internationalised page, and does not claim anything about the items', async () => {
    // The replacement for the per-item punycode verdict that returned the whole
    // vault on any IDN page. One sentence about the page; the items are
    // unaffected.
    openWith([], 'https://xn--80ak6aa92e.com/login');
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('internationalised domain name'), 'the page notice');
    expect(text()).toContain('Nothing saved for this site');
    expect(text()).not.toContain('only looks like the saved one');
  });

  it('shows a page URL it cannot parse verbatim, and claims nothing about it', async () => {
    // One parse serves both the heading and the internationalised-domain
    // notice, so one failure path covers both. A tab URL that will not parse is
    // displayed as-is rather than becoming an empty heading, and — the part
    // that matters — it is NOT reported as internationalised, because nothing
    // was established about it.
    openWith([], 'not a url at all');
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('For not a url at all'), 'the verbatim heading');
    expect(text()).not.toContain('internationalised domain name');
  });

  it('asks for a FILL, naming the item and the page, never for a secret', async () => {
    const wired = openWith(MATCH);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await pressFill();
    await until(() => text().includes('Filled'), 'the outcome');

    const ask = wired.sent.find((m) => (m as { kind?: string }).kind === 'fill');
    expect(ask).toEqual({
      target: 'offscreen',
      kind: 'fill',
      bearer: BEARER,
      itemId: 'i',
      pageUrl: 'https://example.com/login',
    });
  });

  it('says the holder declined WITHOUT calling it an error, and injects nothing', async () => {
    // `credential: null` is the key holder refusing — the item does not belong
    // to this page, or could not be opened. The user did nothing wrong and there
    // is nothing to retry, so it must not read as a failure (the M9 rule).
    const wired = openWith(MATCH, 'https://example.com/login', { ok: true, credential: null });
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await pressFill();
    await until(() => text().includes('not offered for this page'), 'the refusal');

    expect(wired.injected).toEqual([]);
    expect(document.querySelector('.error')).toBeNull();
  });

  it('shows a locked vault as an ERROR, because that one is worth retrying', async () => {
    const wired = openWith(MATCH, 'https://example.com/login', {
      ok: false,
      code: 'VAULT_LOCKED',
    });
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await pressFill();
    await until(() => document.querySelector('.error') !== null, 'the error');
    expect(wired.injected).toEqual([]);
  });

  it('renders the whole vault normally when the page cannot be seen', async () => {
    // A chrome:// tab, or a window with nothing active. Not a failure of the
    // vault, so the list is still there and the per-page section simply is not.
    openWith([], null);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Vault open'), 'the unlocked view');
    expect(text()).not.toContain('For ');
    expect(text()).not.toContain('Nothing saved for this site');
  });
});

describe('authoring an item in the popup (M16 PR4a)', () => {
  const ITEM = {
    id: 'i-1',
    itemType: 'password',
    title: 'Bank login',
    blobVersion: 4,
    // DELIBERATELY UNEQUAL to blobVersion. Since M27 PR1a these are two
    // different jobs — the blob version binds the AAD, the revision is the
    // concurrency token — and a fixture where they agree cannot catch a call
    // site that reads the wrong one.
    revision: 41,
  };

  function composing(reply: (m: { kind?: string }) => unknown): Wired {
    return wire(
      (message) =>
        message.kind === 'list'
          ? { ok: true, items: [ITEM] }
          : message.kind === 'matches'
            ? { ok: true, matched: [] }
            : (reply(message) ?? { ok: true, state: { status: 'unlocked', expiresAt: 'x' } }),
      { status: 200 },
      null,
    );
  }

  const typeInto = (id: string, value: string): void => {
    const input = document.getElementById(id) as HTMLInputElement | null;
    if (!input) throw new Error(`no field ${id}. Saw: ${text()}`);
    input.value = value;
  };
  const press = (label: string): void => {
    const button = [...document.querySelectorAll('button')].find(
      (b) => (b.textContent ?? '') === label,
    );
    if (!button) throw new Error(`no button ${label}. Saw: ${text()}`);
    button.click();
  };

  it('creates from what was typed, and says the address decides where it fills', async () => {
    const wired = composing((m) => (m.kind === 'create' ? { ok: true, item: ITEM } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Vault open'), 'the vault');

    press('New item');
    await until(() => text().includes('New item'), 'the form');
    // The one sentence the form owes: the url is what governs the fill.
    expect(text()).toContain('decides where this can be filled');

    typeInto('item-title', 'Typed here');
    typeInto('item-secret', 's3cret');
    press('Add to vault');
    await until(() => wired.sent.some((m) => (m as { kind?: string }).kind === 'create'), 'create');

    const sent = wired.sent.find((m) => (m as { kind?: string }).kind === 'create');
    expect(sent).toMatchObject({
      kind: 'create',
      itemType: 'password',
      content: { title: 'Typed here', secret: 's3cret', username: '', url: '' },
    });
  });

  it('refuses a create with no title rather than saving an unfindable item', async () => {
    composing(() => undefined);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Vault open'), 'the vault');
    press('New item');
    await until(() => text().includes('New item'), 'the form');
    press('Add to vault');
    await until(() => text().includes('Give it a title'), 'the refusal');
  });

  it('EDIT SENDS ONLY WHAT CHANGED, so a blank field cannot erase what it cannot see', async () => {
    const wired = composing((m) => (m.kind === 'update' ? { ok: true, item: ITEM } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Bank login'), 'the list');

    press('Edit');
    await until(() => text().includes('Edit item'), 'the form');
    expect(text()).toContain('Leave a field empty to keep what is already saved');

    // Only the password is typed. Title is pre-filled and unchanged; username
    // and url are left blank — and must NOT be sent as empty strings, or the
    // holder would merge them and wipe values the user never saw.
    typeInto('item-secret', 'a-new-password');
    press('Save changes');
    await until(() => wired.sent.some((m) => (m as { kind?: string }).kind === 'update'), 'update');

    const sent = wired.sent.find((m) => (m as { kind?: string }).kind === 'update') as {
      changes: Record<string, unknown>;
      blobVersion: number;
    };
    expect(sent.changes).toEqual({ secret: 'a-new-password' });
    expect(Object.keys(sent.changes)).not.toContain('username');
    expect(Object.keys(sent.changes)).not.toContain('url');
    // And the version the popup READ travels, which is what makes If-Match mean
    // anything.
    expect(sent.blobVersion).toBe(4);
  });

  it('sends the REVISION as the concurrency token, never the blob version', async () => {
    // The popup BUILDS the update message; no service-side test can see this
    // hop, and a test that hands `updateItem` a hand-written object proves only
    // that the host forwards what it was given. This drives the real chain:
    // a listed item -> the edit form -> vault-client -> the message on the wire.
    const wired = composing((m) => (m.kind === 'update' ? { ok: true, item: ITEM } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Bank login'), 'the list');

    press('Edit');
    await until(() => text().includes('Edit item'), 'the form');
    typeInto('item-secret', 'a-new-password');
    press('Save changes');
    await until(() => wired.sent.some((m) => (m as { kind?: string }).kind === 'update'), 'update');

    const sent = wired.sent.find((m) => (m as { kind?: string }).kind === 'update') as {
      blobVersion: number;
      revision: number;
    };
    // The number that becomes If-Match.
    expect(sent.revision).toBe(41);
    // POSITIVE CONTROL: the blob version still travels, under its own name,
    // because it is what the content AAD binds. Losing it is a different bug.
    expect(sent.blobVersion).toBe(4);
  });

  it('keeps the typed form on screen when a create is refused', async () => {
    // Losing what someone just typed because the server said no is the worst
    // possible answer on a form holding a password.
    composing((m) => (m.kind === 'create' ? { ok: false, code: 'VAULT_LOCKED' } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Vault open'), 'the vault');
    press('New item');
    await until(() => text().includes('New item'), 'the form');
    typeInto('item-title', 'Typed here');
    press('Add to vault');
    await until(() => text().includes('Your vault is locked'), 'the refusal');
    // Still the form, not the list.
    expect(text()).toContain('New item');
  });

  it('explains a version conflict in its own words, and offers no overwrite', async () => {
    composing((m) => (m.kind === 'update' ? { ok: false, code: 'VERSION_CONFLICT' } : undefined));
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Bank login'), 'the list');
    press('Edit');
    await until(() => text().includes('Edit item'), 'the form');
    typeInto('item-secret', 'x');
    press('Save changes');
    await until(() => text().includes('changed somewhere else'), 'the conflict');
    // Deliberately NO "overwrite anyway": seeing the newer value first is the
    // whole point of If-Match.
    expect(text().toLowerCase()).not.toContain('overwrite');
  });

  it('sends nothing at all when an edit changed nothing', async () => {
    const wired = composing(() => undefined);
    await mountVaultScreens({ host: host(), userId: USER, call: passthrough().call });
    await until(() => text().includes('Bank login'), 'the list');
    press('Edit');
    await until(() => text().includes('Edit item'), 'the form');
    press('Save changes');
    await until(() => text().includes('Vault open'), 'back to the list');
    expect(wired.sent.some((m) => (m as { kind?: string }).kind === 'update')).toBe(false);
  });
});
