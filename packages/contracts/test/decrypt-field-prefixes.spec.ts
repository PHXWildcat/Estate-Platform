/**
 * Fence for the decrypt-attribution registry (M18 PR1).
 *
 * DECRYPT_FIELD_PREFIXES claims that the first dotted token of every field
 * name a service passes into FieldCrypto is (a) registered, and (b) disjoint
 * per service — the M18 detector attributes `crypto.field.decrypted` events
 * to services on exactly that claim, because the audit envelope carries no
 * producing-service field. Until this fence that was prose; this makes it a
 * scan that fails the build (the credential-graph precedent).
 *
 * Mechanism: for every service under apps/services, every src file whose
 * NON-COMMENT code touches field crypto (FieldCrypto / FieldCipher /
 * ContentCipher / encryptField / decryptField) is tokenized with a real
 * string-aware scanner (not a regex strip — the strings ARE the data here),
 * and every string literal or template-literal head shaped like a field
 * prefix (`token.` with a lowercase snake token) becomes a candidate.
 * Rules, each in both directions:
 *   1. a candidate whose token is registered must be registered to THE
 *      SCANNED SERVICE (cross-service emission is the defect the registry
 *      exists to make impossible — this is the disjointness claim, checked
 *      against source rather than asserted);
 *   2. every registered prefix is OBSERVED in its own service's source —
 *      dead registry data is a lie the detector would trust;
 *   3. vault has no field-crypto files at all (Zone A has no server decrypt
 *      path), and audit — whose M18 detector legitimately names the registry
 *      helpers and the decrypt action — contributes ZERO candidates: it
 *      consumes the stream and must never emit a field into it (the PR2
 *      revision the PR1 version of this rule promised);
 *   4. anti-vacuity floors per service, because a scan that stops matching
 *      goes green (the 2026-08-07 lesson).
 *
 * What this fence deliberately does NOT police: a literal whose first token
 * is REGISTERED NOWHERE. The first run proved that rule unworkable at this
 * layer — the crypto-touching files legitimately carry ~170 dotted literals
 * from other vocabularies (identity's auth_events ledger kinds alone are
 * 122: 'user.registered', 'login.failed', …), and an exclusion list that
 * size is the permanently-red gate people learn to ignore. The division of
 * labor is: this fence keeps the REGISTRY true (attribution can never be
 * wrong for a prefix the registry knows), and the detector keeps the
 * UNKNOWN loud (an unregistered prefix classifies as its own reportable
 * class with a deliberately low bound, and PR2's stack e2e asserts zero
 * anomaly events after the dev journey — so a new unregistered prefix that
 * ships goes red there, before merge, rather than here).
 *
 * Residual, stated rather than hidden: the tokenizer does not disambiguate
 * regex literals from division, so a regex containing an odd number of quote
 * characters could desync literal extraction for the rest of that file. The
 * floors are the tripwire for gross undercounting; no such regex exists in
 * the scanned files today.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  AUDIT_ACTIONS,
  DECRYPT_FIELD_PREFIXES,
  decryptFieldPrefix,
  decryptFieldServiceFor,
  TOPICS,
} from '../src';

const REPO_ROOT = join(__dirname, '..', '..', '..');
const SERVICES_DIR = join(REPO_ROOT, 'apps', 'services');

/** A src file is in scope iff its non-comment code mentions one of these. */
const CRYPTO_TOKEN = /FieldCrypto|FieldCipher|ContentCipher|encryptField|decryptField/;

/**
 * Services that must have NO field-crypto files at all. Vault is structural:
 * Zone A's server never holds a decryptable field.
 */
const NO_FIELD_CRYPTO_SERVICES = ['vault'] as const;

/**
 * Services whose files may NAME the crypto vocabulary without emitting into
 * it: audit's M18 detector imports the registry helpers and queries the
 * decrypt action, so its files match the crypto-token scan — but a prefix
 * CANDIDATE appearing there would be the consumer growing an emitter's
 * vocabulary, which is exactly the confusion the registry exists to prevent.
 */
const STREAM_CONSUMER_SERVICES = ['audit'] as const;

/**
 * Exact literals that look like field prefixes but are catalog members from
 * other vocabularies. Derived catalogs first (AUDIT_ACTIONS, TOPICS) so they
 * cannot drift; anything hand-listed here carries its reason.
 */
const EXCLUDED_LITERALS = new Map<string, string>([
  ...AUDIT_ACTIONS.map((a): [string, string] => [a, 'audit action catalog']),
  ...Object.values(TOPICS).map((t): [string, string] => [t, 'Kafka topic registry']),
]);

/**
 * Anti-vacuity floors, measured 2026-08-13 (M18 PR1): `files` counts the
 * service's field-crypto source files, `registered` its candidates whose
 * token the registry knows (the set rules 1 and 2 actually consume). Floors
 * sit AT the measured values: a drop means either a real removal (lower it
 * in review) or the scan rotting (fix the scan) — the fence cannot tell, so
 * it refuses either way.
 */
const SCAN_FLOORS: Record<string, { files: number; registered: number }> = {
  identity: { files: 3, registered: 3 },
  profile: { files: 5, registered: 30 },
  assets: { files: 4, registered: 2 },
  documents: { files: 3, registered: 2 },
  plaid: { files: 3, registered: 6 },
  'ai-assistant': { files: 4, registered: 2 },
  notifications: { files: 3, registered: 1 },
  settlement: { files: 2, registered: 1 },
};

const PREFIX_SHAPE = /^[a-z][a-z0-9_]*$/;
const CANDIDATE_SHAPE = /^([a-z][a-z0-9_]*)\./;

/**
 * String-aware scan of TypeScript source. Returns every string literal and
 * every template-literal head (text before the first `${`, or the whole
 * template if it has none), plus the non-comment code for token matching.
 * Comments never contribute literals; nested templates inside `${}` are
 * scanned recursively via the frame stack.
 */
function scanSource(source: string): { literals: string[]; code: string } {
  const literals: string[] = [];
  let code = '';
  /** Open template frames; braceDepth 0 ⇒ inside the template's literal text. */
  const frames: { braceDepth: number; buf: string; headDone: boolean }[] = [];
  let mode: 'code' | 'line' | 'block' | 'single' | 'double' = 'code';
  let strBuf = '';
  let i = 0;
  while (i < source.length) {
    const c = source[i] as string;
    const next = source[i + 1];
    if (mode === 'line') {
      if (c === '\n') {
        mode = 'code';
        code += c;
      }
      i += 1;
      continue;
    }
    if (mode === 'block') {
      if (c === '*' && next === '/') {
        mode = 'code';
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }
    if (mode === 'single' || mode === 'double') {
      const quote = mode === 'single' ? "'" : '"';
      if (c === '\\') {
        strBuf += c + (next ?? '');
        i += 2;
        continue;
      }
      if (c === quote) {
        literals.push(strBuf);
        code += strBuf;
        strBuf = '';
        mode = 'code';
        i += 1;
        continue;
      }
      strBuf += c;
      i += 1;
      continue;
    }
    // mode === 'code'
    const top = frames[frames.length - 1];
    if (top && top.braceDepth === 0) {
      // Inside a template's literal text.
      if (c === '\\') {
        top.buf += c + (next ?? '');
        i += 2;
        continue;
      }
      if (c === '`') {
        if (!top.headDone) {
          literals.push(top.buf);
          code += top.buf;
        }
        frames.pop();
        i += 1;
        continue;
      }
      if (c === '$' && next === '{') {
        if (!top.headDone) {
          literals.push(top.buf);
          code += top.buf;
          top.headDone = true;
        }
        top.braceDepth = 1;
        i += 2;
        continue;
      }
      top.buf += c;
      i += 1;
      continue;
    }
    // Plain code, or inside a template's ${ } expression.
    if (c === '/' && next === '/') {
      mode = 'line';
      i += 2;
      continue;
    }
    if (c === '/' && next === '*') {
      mode = 'block';
      i += 2;
      continue;
    }
    if (c === "'") {
      mode = 'single';
      strBuf = '';
      i += 1;
      continue;
    }
    if (c === '"') {
      mode = 'double';
      strBuf = '';
      i += 1;
      continue;
    }
    if (c === '`') {
      frames.push({ braceDepth: 0, buf: '', headDone: false });
      i += 1;
      continue;
    }
    if (top && top.braceDepth > 0) {
      if (c === '{') {
        top.braceDepth += 1;
      } else if (c === '}') {
        top.braceDepth -= 1;
      }
    }
    code += c;
    i += 1;
    continue;
  }
  return { literals, code };
}

function walk(dir: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  return entries.flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      return walk(path);
    }
    return path.endsWith('.ts') ? [path] : [];
  });
}

interface Candidate {
  file: string;
  value: string;
  token: string;
}

interface ServiceScan {
  service: string;
  cryptoFiles: string[];
  candidates: Candidate[];
}

const SERVICES = readdirSync(SERVICES_DIR).filter((entry) =>
  statSync(join(SERVICES_DIR, entry)).isDirectory(),
);

const SCANS: ServiceScan[] = SERVICES.map((service) => {
  const cryptoFiles: string[] = [];
  const candidates: Candidate[] = [];
  for (const file of walk(join(SERVICES_DIR, service, 'src'))) {
    const { literals, code } = scanSource(readFileSync(file, 'utf8'));
    if (!CRYPTO_TOKEN.test(code)) {
      continue;
    }
    const rel = file.slice(REPO_ROOT.length + 1);
    cryptoFiles.push(rel);
    for (const value of literals) {
      const match = CANDIDATE_SHAPE.exec(value);
      if (!match || EXCLUDED_LITERALS.has(value)) {
        continue;
      }
      candidates.push({ file: rel, value, token: match[1] as string });
    }
  }
  return { service, cryptoFiles, candidates };
});

const scanOf = (service: string): ServiceScan =>
  SCANS.find((s) => s.service === service) as ServiceScan;

describe('DECRYPT_FIELD_PREFIXES registry shape', () => {
  it('maps only to services that exist on disk', () => {
    // A hand-maintained service name makes a renamed service invisible — the
    // SERVICE_NAMES lesson. Every value must be a directory under
    // apps/services.
    for (const service of Object.values(DECRYPT_FIELD_PREFIXES)) {
      expect(SERVICES).toContain(service);
    }
  });

  it('keys are dot-free lowercase tokens (first-token grammar)', () => {
    for (const prefix of Object.keys(DECRYPT_FIELD_PREFIXES)) {
      expect(prefix).toMatch(PREFIX_SHAPE);
    }
  });

  it('never registers a prefix to a service declared field-crypto-free', () => {
    for (const service of Object.values(DECRYPT_FIELD_PREFIXES)) {
      expect(NO_FIELD_CRYPTO_SERVICES).not.toContain(service);
    }
  });
});

describe('decryptFieldPrefix / decryptFieldServiceFor', () => {
  it('extracts the first dotted token', () => {
    expect(decryptFieldPrefix('contact.name')).toBe('contact');
    expect(decryptFieldPrefix('doc.9f0.v2.abc')).toBe('doc');
    expect(decryptFieldPrefix('plaid_item.access_token.42')).toBe('plaid_item');
    expect(decryptFieldPrefix('nodots')).toBe('nodots');
  });

  it('resolves every registered prefix to its service', () => {
    for (const [prefix, service] of Object.entries(DECRYPT_FIELD_PREFIXES)) {
      expect(decryptFieldServiceFor(`${prefix}.anything.else`)).toBe(service);
    }
  });

  it('answers null for unregistered prefixes — the reportable class', () => {
    expect(decryptFieldServiceFor('trust.name')).toBeNull();
    expect(decryptFieldServiceFor('nodots')).toBeNull();
  });

  it('never resolves through the object prototype', () => {
    // Field names are attacker-adjacent strings; `constructor.x` must be
    // unknown, not a function.
    expect(decryptFieldServiceFor('constructor.x')).toBeNull();
    expect(decryptFieldServiceFor('toString.x')).toBeNull();
    expect(decryptFieldServiceFor('__proto__.x')).toBeNull();
  });
});

describe('per-service source scan', () => {
  it('scanned at least one emitting service (vacuity guard)', () => {
    expect(SCANS.some((s) => s.candidates.length > 0)).toBe(true);
  });

  it.each(SERVICES.map((s) => [s] as [string]))(
    '%s: every registered-token candidate belongs to this service (disjointness)',
    (service) => {
      const violations = scanOf(service).candidates.filter((c) => {
        const owner = decryptFieldServiceFor(c.value);
        return owner !== null && owner !== service;
      });
      expect(violations).toEqual([]);
    },
  );

  it.each(Object.entries(DECRYPT_FIELD_PREFIXES))(
    'prefix %s is observed in %s source (no dead registry data)',
    (prefix, service) => {
      const observed = scanOf(service).candidates.some((c) => c.token === prefix);
      expect(observed).toBe(true);
    },
  );

  it.each(NO_FIELD_CRYPTO_SERVICES.map((s) => [s] as [string]))(
    '%s has no field-crypto files at all',
    (service) => {
      expect(scanOf(service).cryptoFiles).toEqual([]);
    },
  );

  it.each(STREAM_CONSUMER_SERVICES.map((s) => [s] as [string]))(
    '%s consumes the stream and contributes zero prefix candidates',
    (service) => {
      const scan = scanOf(service);
      // Anti-vacuity: the detector really is in scope of the scan — an audit
      // tree with no crypto-token files would make the candidates assertion
      // vacuously true (and would mean the detector was deleted).
      expect(scan.cryptoFiles.length).toBeGreaterThanOrEqual(1);
      expect(scan.candidates).toEqual([]);
    },
  );

  it.each(Object.entries(SCAN_FLOORS))('%s scan meets its anti-vacuity floor', (service, floor) => {
    const scan = scanOf(service);
    const registered = scan.candidates.filter((c) => decryptFieldServiceFor(c.value) !== null);
    expect(scan.cryptoFiles.length).toBeGreaterThanOrEqual(floor.files);
    expect(registered.length).toBeGreaterThanOrEqual(floor.registered);
  });

  it('floors cover exactly the emitting services', () => {
    const emitting = [...new Set(Object.values(DECRYPT_FIELD_PREFIXES))].sort();
    expect(Object.keys(SCAN_FLOORS).sort()).toEqual(emitting);
  });
});
