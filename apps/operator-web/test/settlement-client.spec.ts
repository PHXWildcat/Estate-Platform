/**
 * @jest-environment jsdom
 */

/**
 * THE SETTLEMENT CLIENT: the shape it expects, and the shape it is sent.
 *
 * Two things are checked here that no screen test can see. First that the
 * client's REQUIRED FIELDS really exist on the service's own DTOs — read out of
 * the settlement service's source, the compose-parity mechanism, because a
 * browser client cannot import a NestJS package. That drift is silent in the
 * worst possible direction: this client refuses a row it cannot fully read (a
 * short worklist of death reports is indistinguishable from a quiet week), so a
 * field renamed at the service would empty the review queue rather than break
 * it. Second, that every path this client asks for is a path the operator edge
 * will actually forward — an unallowlisted path is a 404 from our own edge,
 * indistinguishable on screen from a case that does not exist.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as settlement from '../src/client/settlement';
import { REJECTION_REASONS } from '../src/client/settlement';

const ROOT = join(__dirname, '..', '..', '..');
const SERVICE = join(ROOT, 'apps', 'services', 'settlement', 'src');
const EDGE = readFileSync(join(__dirname, '..', 'src', 'server.ts'), 'utf8');

/** Comments stripped: a scan of source is a scan of CODE. */
function code(path: string): string {
  return readFileSync(path, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

const client = readFileSync(join(__dirname, '..', 'src', 'client', 'settlement.ts'), 'utf8');

function interfaceFields(source: string, name: string): Set<string> {
  const start = source.indexOf(`export interface ${name} {`);
  expect(start).toBeGreaterThanOrEqual(0);
  const end = source.indexOf('\n}', start);
  expect(end).toBeGreaterThan(start);
  const body = source.slice(start, end);
  const fields = new Set<string>();
  for (const match of body.matchAll(/^\s{2}(?:readonly\s+)?([A-Za-z_$][\w$]*)\??:/gm)) {
    fields.add(match[1] as string);
  }
  return fields;
}

/**
 * The fields a UNION OF OBJECT LITERALS declares, across every arm.
 *
 * `interfaceFields` cannot read `EvidenceEntry`: it is a `type`, its arms are
 * indented one level deeper than an interface's members, and one of them is
 * written on a single line. Scanned to the next top-level declaration rather
 * than to the next `;`, because the arms contain semicolons of their own
 * (`type: 'document';`) and the first one ends nothing.
 */
function unionFields(source: string, name: string): Set<string> {
  const start = source.indexOf(`export type ${name} =`);
  expect(start).toBeGreaterThanOrEqual(0);
  const next = source.indexOf('\nexport ', start + 1);
  const body = source.slice(start, next === -1 ? source.length : next);
  const fields = new Set<string>();
  for (const match of body.matchAll(/([A-Za-z_$][\w$]*)\s*\??:/g)) fields.add(match[1] as string);
  return fields;
}

/** The keys this client insists on finding, read from its own parsers. */
function requiredKeys(parser: string): Set<string> {
  const start = client.indexOf(`function ${parser}(`);
  expect(start).toBeGreaterThanOrEqual(0);
  const end = client.indexOf('\n}', start);
  const body = client.slice(start, end);
  const keys = new Set<string>();
  for (const match of body.matchAll(/raw\['([^']+)'\]/g)) keys.add(match[1] as string);
  return keys;
}

describe('the wire shapes this client reads really exist at settlement', () => {
  const dtos =
    code(join(SERVICE, 'settlement.service.ts')) + code(join(SERVICE, 'admin.service.ts'));

  it.each([
    ['parseCase', 'CaseDto'],
    ['parseStage', 'StageDto'],
    ['parseDistribution', 'DistributionDto'],
    ['parseTimeline', 'TimelineEntry'],
  ])('%s reads only fields %s declares', (parser, dto) => {
    const declared = interfaceFields(dtos, dto);
    const wanted = requiredKeys(parser);
    // Anti-vacuity on both sides: two empty sets agree perfectly.
    expect(declared.size).toBeGreaterThan(2);
    expect(wanted.size).toBeGreaterThan(2);
    expect([...wanted].filter((key) => !declared.has(key))).toEqual([]);
  });

  /**
   * EVIDENCE IS PINNED IN BOTH DIRECTIONS (M22 PR4b), and it is the only shape
   * here that is.
   *
   * The other four are subset checks: a client may legitimately ignore a DTO
   * field it has no use for. Evidence is the field this console exists to put
   * in front of a human, and "ignored it" is how it got here — settlement has
   * returned `evidence` on every `CaseDto` since M7 and `parseCase` dropped it
   * for five milestones, silently, because no assertion ran in that direction.
   * A new arm with a new reference is a reviewer looking at an entry whose
   * substance is not on screen, so the sets must be EQUAL and a widening is
   * somebody's decision rather than a default.
   */
  it('parseEvidence reads EXACTLY the fields EvidenceEntry declares, both ways', () => {
    const declared = unionFields(code(join(SERVICE, 'cases.repo.ts')), 'EvidenceEntry');
    const wanted = requiredKeys('parseEvidence');
    // Anti-vacuity: two empty sets agree perfectly, and both arms together
    // carry six fields.
    expect(declared.size).toBeGreaterThan(4);
    expect([...declared].sort()).toEqual([...wanted].sort());
  });
});

describe('every path this client asks for is a path the edge forwards', () => {
  /**
   * Derived from BOTH files rather than compared to a list, because a list is a
   * third copy and the drift being caught is between the two that exist. The
   * edge's allowlist is exact-match per method, so a client template the table
   * does not carry is a 404 from our own edge — which on screen is
   * indistinguishable from a case that is not there.
   */
  function edgePaths(): Set<string> {
    const paths = new Set<string>();
    for (const block of EDGE.matchAll(/\{[^{}]*\}/g)) {
      const path = /\bpath:\s*'([^']+)'/.exec(block[0])?.[1];
      if (path?.startsWith('/api/settlement/')) paths.add(path);
    }
    return paths;
  }

  /** `${CASES}/${encodeURIComponent(id)}/timeline` → `/api/settlement/cases/:p/timeline`. */
  function clientPaths(): Set<string> {
    const cases = /const CASES = '([^']+)'/.exec(client)?.[1];
    expect(cases).toBe('/api/settlement/cases');
    const paths = new Set<string>();
    for (const match of client.matchAll(/request<unknown>\(\s*[`']([^`']+)[`']/g)) {
      const template = (match[1] as string).replace('${CASES}', cases as string);
      paths.add(template.replace(/\$\{[^}]*\}/g, ':p'));
    }
    return paths;
  }

  it('asks for exactly the settlement paths the edge allowlists', () => {
    const edge = [...edgePaths()].map((p) => p.replace(/:[A-Za-z]+/g, ':p')).sort();
    const asked = [...clientPaths()].sort();
    expect(edge.length).toBe(13);
    expect(asked).toEqual(edge);
  });
});

interface Reply {
  status: number;
  body: unknown;
}

let calls: Array<{ path: string; method: string; body: unknown }>;

function transport(reply: Reply): void {
  calls = [];
  (globalThis as { fetch?: unknown }).fetch = (path: string, init?: RequestInit) => {
    calls.push({
      path,
      method: init?.method ?? 'GET',
      body: init?.body === undefined ? undefined : JSON.parse(init.body as string),
    });
    return Promise.resolve({
      ok: reply.status >= 200 && reply.status < 300,
      status: reply.status,
      text: () => Promise.resolve(JSON.stringify(reply.body)),
    });
  };
}

describe('the review decision', () => {
  it('sends the reason with a rejection, and no reason with an approval', async () => {
    transport({ status: 200, body: {} });
    await settlement.decideReview('c-1', 'reject', 'fraud_suspected');
    expect(calls[0]?.body).toEqual({ decision: 'reject', reason: 'fraud_suspected' });

    transport({ status: 200, body: {} });
    await settlement.decideReview('c-1', 'approve');
    expect(calls[0]?.body).toEqual({ decision: 'approve' });
  });

  it('offers a CLOSED reason vocabulary, matching the service schema', () => {
    const schema = code(join(SERVICE, 'schemas.ts'));
    const block = /ReviewDecisionSchema[\s\S]{0,600}?reason:[\s\S]{0,300}?\]\)/.exec(schema);
    expect(block).not.toBeNull();
    const tokens = [...(block as RegExpExecArray)[0].matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
    for (const reason of REJECTION_REASONS) {
      expect(tokens).toContain(reason);
    }
  });
});

describe('a list refuses rather than shortens', () => {
  it('fails the whole list when one row will not parse', async () => {
    transport({ status: 200, body: [{ nonsense: true }] });
    const result = await settlement.reviewQueue();
    expect(result).toEqual({ ok: false, code: 'UNKNOWN' });
  });

  it('refuses a body that is not an array at all', async () => {
    transport({ status: 200, body: { caseId: 'c-1' } });
    expect(await settlement.reviewQueue()).toEqual({ ok: false, code: 'UNKNOWN' });
  });

  it('passes a REFUSAL through untouched, so a 403 stays a 403', async () => {
    transport({ status: 403, body: { error: 'forbidden' } });
    expect(await settlement.reviewQueue()).toEqual({ ok: false, code: 'FORBIDDEN' });
  });
});

describe('a timeline detail is scalars only', () => {
  it('says so rather than stringifying a shape it does not understand', async () => {
    // `String({})` is '[object Object]', which on an audit surface is a sentence
    // that looks like a value and is not one.
    transport({
      status: 200,
      body: [{ at: '2026-08-01T00:00:00.000Z', kind: 'case.opened', detail: { nested: { a: 1 } } }],
    });
    const result = await settlement.timeline('c-1');
    expect(result.ok).toBe(true);
    const detail = result.ok ? result.data[0]?.detail : {};
    expect(detail?.['nested']).toMatch(/does not understand/);
    expect(detail?.['nested']).not.toContain('[object Object]');
  });
});
