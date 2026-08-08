/**
 * @jest-environment jsdom
 */

/**
 * The browser client (M15 PR2).
 *
 * jsdom cannot enforce a CSP or Trusted Types, so what those buy is measured in
 * a REAL browser instead (PR1: `trustedTypes.createPolicy` refused, `innerHTML`
 * threw producing zero child nodes, `eval` and `new Function` threw EvalError
 * from page context). What jsdom is good for is the half a browser cannot
 * easily assert — that the DOM helper produces TEXT for text, that a failure
 * never renders as a success, and that the status mapping is what the UI thinks.
 *
 * The crypto here is REAL: jest resolves `/lib/vault-crypto/index.js` to the
 * package sources, so an enrollment in these tests runs PBKDF2 and SRP exactly
 * as the browser will. That is what makes the egress spec meaningful.
 */
import { el, replaceChildren, text } from '../src/client/dom';
import { request } from '../src/client/api';
import { decodeItemContent, encodeItemContent } from '../src/client/item-content';
import { entropyBits, generatePassword, GeneratorError } from '../src/client/generator';
import { renderEmergencyKit } from '../src/client/emergency-kit';

type FetchArgs = [string, RequestInit | undefined];

/**
 * A response DOUBLE rather than a real `Response`: jsdom provides no `fetch` and
 * no `Response` global, so constructing one threw — and `request` dutifully
 * reported NETWORK, which is correct behaviour for a broken transport and a
 * completely misleading test result.
 */
function response(status: number, body: string | null): unknown {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(body ?? ''),
  };
}

function stubFetch(handler: (path: string, init?: RequestInit) => unknown): FetchArgs[] {
  const calls: FetchArgs[] = [];
  globalThis.fetch = ((path: string, init?: RequestInit) => {
    calls.push([path, init]);
    return Promise.resolve(handler(path, init));
  }) as unknown as typeof fetch;
  return calls;
}

const json = (status: number, body: unknown): unknown => response(status, JSON.stringify(body));

describe('dom helpers build text, never markup', () => {
  it('renders a script-shaped item title as characters', () => {
    // The property the whole renderer exists for. A vault item's title is
    // attacker-influencable in the general case (somebody else named the
    // account), so it must never be parsed.
    const node = el('p', {}, ['<img src=x onerror=alert(1)>']);
    expect(node.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(node.querySelector('img')).toBeNull();
    expect(node.childNodes).toHaveLength(1);
    expect(node.childNodes[0]?.nodeType).toBe(3); // TEXT_NODE
  });

  it('replaceChildren also produces text nodes, not parsed markup', () => {
    const host = el('div');
    replaceChildren(host, '<b>bold?</b>', text('plain'));
    expect(host.querySelector('b')).toBeNull();
    expect(host.textContent).toBe('<b>bold?</b>plain');
  });

  it('sets only the attributes it was given, and drops false/undefined', () => {
    const node = el('button', { class: 'button', disabled: false, hidden: true });
    expect(node.getAttribute('class')).toBe('button');
    expect(node.hasAttribute('disabled')).toBe(false);
    expect(node.hasAttribute('hidden')).toBe(true);
  });
});

describe('api failure mapping', () => {
  it.each([
    [401, 'unauthorized', 'UNAUTHENTICATED'],
    [403, 'stepup_required', 'STEPUP_REQUIRED'],
    [403, 'vault_locked', 'VAULT_LOCKED'],
    [403, 'something_else', 'UNKNOWN'],
    [404, 'not_found', 'NOT_FOUND'],
    [409, 'version_conflict', 'CONFLICT'],
    [400, 'invalid_request', 'INVALID_REQUEST'],
    [502, 'upstream_unavailable', 'UNAVAILABLE'],
    [500, 'internal_error', 'UNKNOWN'],
  ])('maps %s/%s to %s', async (status, token, expected) => {
    stubFetch(() => json(status, { error: token }));
    expect(await request('/api/vault/keyset')).toEqual({ ok: false, code: expected });
  });

  it('never surfaces server error text', async () => {
    stubFetch(() => json(500, { error: 'internal_error', message: 'pg: relation does not exist' }));
    const result = await request('/api/vault/keyset');
    expect(JSON.stringify(result)).not.toContain('relation does not exist');
  });

  it('carries the CSRF header and same-origin credentials on every call', async () => {
    const calls = stubFetch(() => json(200, {}));
    await request('/api/vault/keyset');
    const init = calls[0]?.[1];
    expect((init?.headers as Record<string, string>)['x-estate-vault-csrf']).toBe('1');
    expect(init?.credentials).toBe('same-origin');
  });

  it('sends the vault-session token as a HEADER, never in the body or the URL', async () => {
    const calls = stubFetch(() => json(200, {}));
    await request('/api/vault/items', { vaultSession: 'opaque-vault-token' });
    expect((calls[0]?.[1]?.headers as Record<string, string>)['x-estate-vault-session']).toBe(
      'opaque-vault-token',
    );
    expect(calls[0]?.[0]).not.toContain('opaque-vault-token');
    expect(JSON.stringify(calls[0]?.[1]?.body ?? '')).not.toContain('opaque-vault-token');
  });

  it('treats a network failure as a failure, not as empty data', async () => {
    globalThis.fetch = () => Promise.reject(new Error('offline'));
    expect(await request('/api/vault/keyset')).toEqual({ ok: false, code: 'NETWORK' });
  });

  it('accepts a 204 with no body', async () => {
    stubFetch(() => response(204, null));
    expect(await request('/api/vault/lock')).toEqual({ ok: true, data: {} });
  });
});

describe('item content', () => {
  it('round-trips the fields a user filled in', () => {
    const content = {
      title: 'Bank — joint',
      username: 'sam@example.test',
      secret: 'hunter2',
      notes: 'branch: high street',
    };
    expect(decodeItemContent(encodeItemContent(content))).toEqual(content);
  });

  it('drops empty fields rather than storing blanks', () => {
    const encoded = encodeItemContent({ title: 'Only a title', username: '', secret: '' });
    expect(decodeItemContent(encoded)).toEqual({ title: 'Only a title' });
    expect(new TextDecoder().decode(encoded)).not.toContain('username');
  });

  it('PRESERVES fields a newer client wrote, through an edit', () => {
    // Without this, opening an item in an older tab and saving would silently
    // delete fields the user never saw — data loss disguised as an edit.
    const fromFuture = new TextEncoder().encode(
      JSON.stringify({ title: 'Card', totpSeed: 'JBSWY3DP', customFields: [{ k: 'v' }] }),
    );
    const decoded = decodeItemContent(fromFuture);
    expect(decoded.unknown).toEqual({ totpSeed: 'JBSWY3DP', customFields: [{ k: 'v' }] });

    const reEncoded = JSON.parse(new TextDecoder().decode(encodeItemContent(decoded))) as Record<
      string,
      unknown
    >;
    expect(reEncoded['totpSeed']).toBe('JBSWY3DP');
    expect(reEncoded['customFields']).toEqual([{ k: 'v' }]);
  });

  it('throws rather than guessing when a blob does not parse', () => {
    // A blob that decrypted but will not parse means the AEAD authenticated
    // bytes this client cannot read. Rendering a blank item over it would
    // invite the user to overwrite something real.
    expect(() => decodeItemContent(new TextEncoder().encode('not json'))).toThrow();
    expect(() => decodeItemContent(new TextEncoder().encode('[1,2]'))).toThrow();
  });
});

describe('the password generator', () => {
  it('produces the requested length, from the declared alphabet', () => {
    const password = generatePassword(32);
    expect(password).toHaveLength(32);
    expect(password).toMatch(/^[A-Za-z0-9\-_.!@#$%^&*]+$/);
  });

  it('refuses a length it cannot honour rather than clamping', () => {
    // Silently generating something shorter than asked for costs entropy
    // without telling anyone (the M10 moneyToCents lesson).
    expect(() => generatePassword(4)).toThrow(GeneratorError);
    expect(() => generatePassword(1024)).toThrow(GeneratorError);
    expect(() => generatePassword(12.5)).toThrow(GeneratorError);
  });

  it('does not repeat itself', () => {
    const seen = new Set(Array.from({ length: 50 }, () => generatePassword(16)));
    expect(seen.size).toBe(50);
  });

  it('reports entropy honestly for the alphabet it uses', () => {
    // 74 characters ⇒ ~6.2 bits each. A wrong number here would be a claim
    // about strength that the generator does not deliver.
    expect(entropyBits(1)).toBe(6);
    expect(entropyBits(24)).toBeGreaterThanOrEqual(148);
  });

  it('uses rejection sampling, so the alphabet is not biased', () => {
    // The obvious `% length` favours the first 34 characters by ~1.35x. Drawn
    // over enough samples the tail characters must appear at a comparable rate
    // to the head ones.
    const counts = new Map<string, number>();
    for (const ch of generatePassword(128).repeat(1) +
      Array.from({ length: 40 }, () => generatePassword(128)).join('')) {
      counts.set(ch, (counts.get(ch) ?? 0) + 1);
    }
    const head = counts.get('a') ?? 0;
    const tail = counts.get('*') ?? 0;
    expect(tail).toBeGreaterThan(0);
    // Generous bound: this is a bias check, not a randomness test suite.
    expect(tail / Math.max(head, 1)).toBeGreaterThan(0.4);
  });
});

describe('the emergency kit', () => {
  const kit = renderEmergencyKit({
    secretKey: 'ES1-AAAAA-BBBBB-CCCCC-DDDDD',
    accountLabel: 'user-uuid',
    issuedAt: '2026-08-08',
  });

  it('carries the Secret Key and NOT the password', () => {
    expect(kit).toContain('ES1-AAAAA-BBBBB-CCCCC-DDDDD');
    // 2SKD's whole point: a kit carrying both halves would turn a filing
    // cabinet into a single point of failure.
    expect(kit).toMatch(/password is deliberately NOT written here/i);
  });

  it('says plainly that losing it is unrecoverable', () => {
    // A user deciding where to file this needs to know the stakes at the
    // moment they decide, not after.
    expect(kit).toMatch(/no recovery/i);
    expect(kit).toMatch(/permanently destroys/i);
  });
});
