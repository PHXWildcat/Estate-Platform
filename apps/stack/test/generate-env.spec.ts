import {
  credentialEnvVarsFor,
  SERVICE_CREDENTIAL_GRAPH,
  type ServiceName,
} from '@estate/auth-guard';
import {
  assignCredentials,
  generateEnv,
  renderEnvFile,
  writeStackEnv,
  type EnvFileIo,
} from '../src/generate-env';
import { SERVICES } from '../src/topology';

/** In-memory filesystem so the overwrite guard is tested without disk. */
function fakeIo(present: string[] = []): EnvFileIo & { written: Map<string, string> } {
  const written = new Map<string, string>();
  return {
    written,
    exists: (path) => present.includes(path) || written.has(path),
    write: (path, contents) => {
      written.set(path, contents);
    },
  };
}

describe('writeStackEnv', () => {
  it('writes when there is nothing to lose', () => {
    const io = fakeIo();
    const outcome = writeStackEnv({ mode: 'development', target: '.env.stack', force: false }, io);
    expect(outcome).toEqual({ status: 'written', path: '.env.stack' });
    expect(io.written.get('.env.stack')).toContain('KAFKA_BROKERS=redpanda:29092');
  });

  it('REFUSES to clobber an existing env, because that orphans ciphertext', () => {
    // Regenerating mints new KMS master keys and blind-index keys, so every
    // ciphertext already in the stack's volumes becomes unreadable — and the
    // symptom appears later, as decrypt failures in a stack that looks new.
    const io = fakeIo(['.env.stack']);
    const outcome = writeStackEnv({ mode: 'development', target: '.env.stack', force: false }, io);
    expect(outcome.status).toBe('refused');
    expect(io.written.size).toBe(0);
    if (outcome.status === 'refused') {
      expect(outcome.message).toContain('down -v');
    }
  });

  it('overwrites under --force', () => {
    const io = fakeIo(['.env.stack']);
    expect(
      writeStackEnv({ mode: 'production', target: '.env.stack', force: true }, io).status,
    ).toBe('written');
    expect(io.written.get('.env.stack')).toContain('PLAID_MODE=live');
  });
});

/** Distinct, predictable secrets so equality assertions mean something. */
function countingMint(): () => string {
  let n = 0;
  return () => `secret-${++n}`;
}

describe('credential assignment (derived from the graph)', () => {
  it('gives the callee and EVERY holder the identical value', () => {
    // The residual the graph module records as unenforced: "nothing verifies
    // that vault's SETTLEMENT_INTERNAL_TOKEN really is settlement's inbound
    // value". Deriving both from one minted secret makes the agreement
    // structural — there is no second place to type it differently.
    const assigned = assignCredentials(countingMint());
    for (const edge of SERVICE_CREDENTIAL_GRAPH) {
      const expected = assigned.get(edge.callee)?.get(edge.envVar);
      if (edge.holders.length === 0) {
        // A zero-holder edge is deliberately unprovisioned: minting an inbound
        // value nobody can present would be an aspirational grant.
        expect(expected).toBeUndefined();
        continue;
      }
      expect(expected).toBeDefined();
      for (const holder of edge.holders) {
        expect(assigned.get(holder)?.get(edge.envVar)).toBe(expected);
      }
    }
  });

  it('never gives two edges the same value', () => {
    // Independently random, so settlement's two credentials cannot collide —
    // the M7 collapse — without anyone having to remember to check.
    const assigned = assignCredentials();
    const values = [...assigned.values()].flatMap((m) => [...m.values()]);
    expect(new Set(values).size).toBe(new Set(values).size);
    const perEdge = SERVICE_CREDENTIAL_GRAPH.filter((e) => e.holders.length > 0).map((e) =>
      assigned.get(e.callee)?.get(e.envVar),
    );
    expect(new Set(perEdge).size).toBe(perEdge.length);
  });

  it('grants each service EXACTLY what the graph entitles it to', () => {
    // Equality in both directions: extra is an over-grant, missing is a gate
    // silently unwired. Mirrors each service's own config.spec.ts assertion —
    // with one deliberate subtraction: an inbound edge with ZERO holders is
    // never minted. The service's config can absorb the variable, but nothing
    // in the repo can present it, so provisioning a value would be exactly the
    // aspirational grant the graph records the edge as not having.
    const assigned = assignCredentials();
    const zeroHolderVars = new Set(
      SERVICE_CREDENTIAL_GRAPH.filter((e) => e.holders.length === 0).map((e) => e.envVar),
    );
    for (const service of SERVICES) {
      const held = [...(assigned.get(service.name) ?? new Map()).keys()].sort();
      const entitled = credentialEnvVarsFor(service.name as ServiceName).filter(
        (envVar) =>
          !(
            zeroHolderVars.has(envVar) &&
            SERVICE_CREDENTIAL_GRAPH.some((e) => e.envVar === envVar && e.callee === service.name)
          ),
      );
      expect(held).toEqual(entitled);
    }
  });

  it('gives vault settlement’s gate key and NOT identity’s lock key', () => {
    // Stated concretely because this exact over-grant is what the M7 review
    // found: vault holding a credential identity would accept turns the most
    // exposed service in the product into one that can entomb a living user.
    const assigned = assignCredentials();
    const vault = assigned.get('vault');
    expect(vault?.has('SETTLEMENT_INTERNAL_TOKEN')).toBe(true);
    expect(vault?.has('IDENTITY_INTERNAL_TOKEN')).toBe(false);
  });

  it('leaves the documents legal-hold credential with no holder', () => {
    // holders: [] in the graph, because no in-repo client calls that route.
    // Generating one anyway would be an unenforced grant — exactly the
    // prose-vs-reality gap the graph module exists to close.
    const assigned = assignCredentials();
    for (const service of SERVICES) {
      if (service.name === 'documents') continue;
      expect(assigned.get(service.name)?.has('DOCUMENTS_INTERNAL_TOKEN')).not.toBe(true);
    }
  });
});

describe('generateEnv', () => {
  it('selects the REAL adapters for every dependency the stack provides', () => {
    const entries = new Map(generateEnv({ mode: 'development' }).entries);
    expect(entries.get('DOCUMENTS_OBJECT_STORE_MODE')).toBe('s3');
    expect(entries.get('DOCUMENTS_SCANNER_MODE')).toBe('clamd');
    expect(entries.get('DOCUMENTS_OCR_MODE')).toBe('tesseract');
    expect(entries.get('KAFKA_BROKERS')).toBe('redpanda:29092');
    // The whole point of PR1's KMS_MODE: the AWS adapter runs in dev too.
    expect(entries.get('IDENTITY_KMS_MODE')).toBe('aws');
    expect(entries.get('DOCUMENTS_KMS_MODE')).toBe('aws');
  });

  it('gives every key-holding service its OWN KEK, never a shared one', () => {
    const entries = new Map(generateEnv({ mode: 'development' }).entries);
    const keyIds = SERVICES.filter((s) => s.kekAlias !== null).map((s) =>
      entries.get(`${s.name.toUpperCase()}_AWS_KMS_KEY_ID`),
    );
    expect(keyIds).toHaveLength(6);
    expect(new Set(keyIds).size).toBe(6);
  });

  it('gives Zone A and audit no key material at all', () => {
    const entries = new Map(generateEnv({ mode: 'development' }).entries);
    for (const name of ['VAULT', 'AUDIT']) {
      expect(entries.has(`${name}_AWS_KMS_KEY_ID`)).toBe(false);
      expect(entries.has(`${name}_KMS_MASTER_KEY_HEX`)).toBe(false);
    }
  });

  it('keeps the two blind-index keys independent', () => {
    // identity keys users.email_bidx in auth; profile keys contacts.email_bidx
    // in core. Nothing compares them, so a shared value would only create a
    // cross-cluster correlation the schema never intended.
    const entries = new Map(generateEnv({ mode: 'development' }).entries);
    expect(entries.get('IDENTITY_EMAIL_INDEX_KEY_HEX')).not.toBe(
      entries.get('PROFILE_EMAIL_INDEX_KEY_HEX'),
    );
  });

  it('mints 32-byte hex for every key material variable', () => {
    const entries = generateEnv({ mode: 'development' }).entries;
    for (const [key, value] of entries) {
      if (key.endsWith('_KEY_HEX')) {
        expect(value).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it('uses dummy AWS credentials and the LocalStack endpoint', () => {
    const entries = new Map(generateEnv({ mode: 'development' }).entries);
    expect(entries.get('AWS_ACCESS_KEY_ID')).toBe('test');
    expect(entries.get('AWS_ENDPOINT_URL')).toBe('http://localstack:4566');
  });

  it('production mode demands live Plaid; development stays stubbed', () => {
    expect(new Map(generateEnv({ mode: 'production' }).entries).get('PLAID_MODE')).toBe('live');
    expect(new Map(generateEnv({ mode: 'development' }).entries).get('PLAID_MODE')).toBe('stub');
  });

  it('points every service at its own cluster, in-network', () => {
    const entries = new Map(generateEnv({ mode: 'development' }).entries);
    expect(entries.get('IDENTITY_DATABASE_URL')).toContain('@pg-auth:5432/auth');
    // Co-tenants share a cluster, and must agree on it.
    expect(entries.get('PROFILE_DATABASE_URL')).toBe(entries.get('SETTLEMENT_DATABASE_URL'));
    expect(entries.get('ASSETS_DATABASE_URL')).toBe(entries.get('PLAID_DATABASE_URL'));
    // Host ports are for host tooling only; nothing in-network uses them.
    for (const [key, value] of entries) {
      if (key.endsWith('_DATABASE_URL')) {
        expect(value).not.toMatch(/:543[3-8]\//);
      }
    }
  });

  it('renders a file that parses back to the same entries', () => {
    const generated = generateEnv({ mode: 'development' });
    const rendered = renderEnvFile(generated, { mode: 'development' });
    const parsed = new Map(
      rendered
        .split('\n')
        .filter((l) => l.length > 0 && !l.startsWith('#'))
        .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)] as const),
    );
    expect(parsed).toEqual(new Map(generated.entries));
  });

  it('says in the file which mode it is, and what that means', () => {
    const rendered = renderEnvFile(generateEnv({ mode: 'production' }), { mode: 'production' });
    expect(rendered).toContain('do not commit');
    expect(rendered).toContain('503');
  });
});
