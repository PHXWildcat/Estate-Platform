import { credentialsLookReal, diagnose, parseEnvFile, summarize } from '../src/doctor';
import { generateEnv, renderEnvFile } from '../src/generate-env';

/** The file the generator actually writes, as the doctor will read it. */
function generatedEnv(
  mode: 'development' | 'production' = 'development',
  addressing: 'compose' | 'host' = 'compose',
): Map<string, string> {
  return parseEnvFile(renderEnvFile(generateEnv({ mode, addressing }), { mode }));
}

const codesOf = (env: Map<string, string>): string[] =>
  diagnose(env)
    .filter((f) => f.severity === 'error')
    .map((f) => f.code);

describe('doctor on a generated environment', () => {
  it('passes cleanly — the generator and the doctor agree', () => {
    expect(diagnose(generatedEnv())).toEqual([]);
    expect(diagnose(generatedEnv('production'))).toEqual([]);
  });
});

describe('addressing must match its consumer', () => {
  // The M8 security review found the CI workflow handing the HOST-addressed
  // file to containerised bootstrap jobs, where 'localhost' is each
  // container's own loopback. Every migration failed, the blocking gate died
  // before the stack test ran, and the production rehearsal never executed
  // while the docs credited it as proven. run-services-cli already refused the
  // opposite direction; the asymmetry was the hole.
  it('refuses a host-addressed file about to be handed to compose', () => {
    const findings = diagnose(generatedEnv('development', 'host'), { consumedBy: 'compose' });
    expect(findings.map((f) => f.code)).toEqual(['addressing_mismatch']);
    expect(findings[0]?.severity).toBe('error');
  });

  it('refuses a compose-addressed file about to be run on the host', () => {
    const findings = diagnose(generatedEnv(), { consumedBy: 'host' });
    expect(findings.map((f) => f.code)).toEqual(['addressing_mismatch']);
  });

  it('accepts each file for the consumer it was generated for', () => {
    expect(diagnose(generatedEnv(), { consumedBy: 'compose' })).toEqual([]);
    expect(diagnose(generatedEnv('development', 'host'), { consumedBy: 'host' })).toEqual([]);
    expect(diagnose(generatedEnv('production', 'host'), { consumedBy: 'host' })).toEqual([]);
  });

  it('says nothing when no consumer is named — the check is opt-in', () => {
    expect(diagnose(generatedEnv('development', 'host'))).toEqual([]);
  });

  it('treats a file with no STACK_ADDRESSING as compose-addressed', () => {
    // Hand-written files predate the marker; compose is the default the
    // generator has always written, so assuming it cannot invent a failure.
    const env = generatedEnv();
    env.delete('STACK_ADDRESSING');
    expect(diagnose(env, { consumedBy: 'compose' })).toEqual([]);
    expect(diagnose(env, { consumedBy: 'host' }).map((f) => f.code)).toEqual([
      'addressing_mismatch',
    ]);
  });
});

describe('the real-AWS footgun', () => {
  it('refuses when a service uses AWS KMS with no endpoint override', () => {
    // Before an AWS account existed this path merely failed for lack of
    // credentials. Now it succeeds against a real account, which is worse.
    const env = generatedEnv();
    env.delete('AWS_ENDPOINT_URL');
    expect(codesOf(env)).toContain('aws_endpoint_missing');
  });

  it('refuses a PER-SERVICE endpoint override, which outranks the one it just checked', () => {
    // @smithy/core resolves AWS_ENDPOINT_URL_KMS before AWS_ENDPOINT_URL, and
    // the services' https-in-production guard only ever reads the plain name.
    const env = generatedEnv();
    env.set('AWS_ENDPOINT_URL_KMS', 'http://kms.somewhere.else:4566');
    expect(codesOf(env)).toContain('aws_endpoint_service_override');
  });

  it('is not fooled by a local-looking USERINFO', () => {
    // `https://localhost:anything@aws.example.com/` begins with the string
    // `https://localhost:` while addressing a host on the internet. The old
    // check was a prefix match, and this check is the thing standing between a
    // misconfigured stack and real AWS calls on a real account.
    const env = generatedEnv();
    env.set('AWS_ENDPOINT_URL', 'https://localhost:4566@kms.us-east-1.amazonaws.com/');
    expect(codesOf(env)).toContain('aws_endpoint_not_local');
  });

  it('refuses an endpoint it cannot parse rather than assuming it is local', () => {
    const env = generatedEnv();
    env.set('AWS_ENDPOINT_URL', 'localstack:4566');
    expect(codesOf(env)).toContain('aws_endpoint_not_local');
  });

  it('refuses an endpoint that is not the local stack', () => {
    const env = generatedEnv();
    env.set('AWS_ENDPOINT_URL', 'https://kms.us-east-1.amazonaws.com');
    expect(codesOf(env)).toContain('aws_endpoint_not_local');
  });

  it('accepts the loopback spellings a host-run probe would use', () => {
    for (const endpoint of ['http://localhost:4566', 'http://127.0.0.1:4566']) {
      const env = generatedEnv();
      env.set('AWS_ENDPOINT_URL', endpoint);
      expect(codesOf(env)).not.toContain('aws_endpoint_not_local');
    }
  });

  it('refuses credentials shaped like real AWS keys', () => {
    const env = generatedEnv();
    env.set('AWS_ACCESS_KEY_ID', 'AKIAIOSFODNN7EXAMPLE');
    env.set('AWS_SECRET_ACCESS_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    expect(codesOf(env)).toContain('aws_credentials_look_real');
  });

  it('classifies key shapes correctly', () => {
    expect(credentialsLookReal('test', 'test')).toBe(false);
    expect(credentialsLookReal('AKIAIOSFODNN7EXAMPLE', 'x')).toBe(true);
    expect(credentialsLookReal('ASIAIOSFODNN7EXAMPLE', 'x')).toBe(true);
    // A 40-char secret is AWS's shape and nothing a local stack needs.
    expect(credentialsLookReal('someuser', 'a'.repeat(40))).toBe(true);
  });
});

describe('the credential graph, restated against the file', () => {
  it('catches a holder whose copy does not match the callee', () => {
    // The exact drift the graph module records as unenforced.
    const env = generatedEnv();
    env.set('VAULT_SETTLEMENT_INTERNAL_TOKEN', 'pasted-the-wrong-secret');
    expect(codesOf(env)).toContain('credential_mismatch');
  });

  it('catches a gate credential left unset', () => {
    const env = generatedEnv();
    env.set('SETTLEMENT_SETTLEMENT_INTERNAL_TOKEN', '');
    expect(codesOf(env)).toContain('credential_missing');
  });

  it('catches the M7 collapse: one value in both of settlement’s slots', () => {
    // Settlement's own config refuses this — but only in production, and the
    // stack's default mode is development.
    const env = generatedEnv();
    const shared = env.get('SETTLEMENT_SETTLEMENT_INTERNAL_TOKEN')!;
    env.set('SETTLEMENT_IDENTITY_INTERNAL_TOKEN', shared);
    env.set('VAULT_SETTLEMENT_INTERNAL_TOKEN', shared);
    env.set('IDENTITY_IDENTITY_INTERNAL_TOKEN', shared);
    expect(codesOf(env)).toContain('credential_aliased');
  });

  it('catches one value shared by two different CALLEES (M9 review)', () => {
    // The gap the M9 security review found: check 4 compares a service's
    // inbound value against its own outbounds, so a collision between two
    // callees — the shape an operator produces by reusing one secrets-store
    // entry — was invisible, while docs/04 and the compose file both claimed
    // the doctor enforced a full pairwise loop. Here identity and vault would
    // end up holding a working key to documents' legal-hold route.
    const env = generatedEnv();
    const shared = env.get('NOTIFICATIONS_NOTIFICATIONS_INTERNAL_TOKEN')!;
    env.set('DOCUMENTS_DOCUMENTS_INTERNAL_TOKEN', shared);
    env.set('SETTLEMENT_DOCUMENTS_INTERNAL_TOKEN', shared);
    // Every holder copy still matches its callee, so check 3 is satisfied and
    // the ONLY thing that can catch this is the cross-callee comparison.
    expect(codesOf(env)).not.toContain('credential_mismatch');
    expect(codesOf(env)).toContain('credential_aliased');
  });
});

describe('dependencies the stack must really provide', () => {
  it('refuses a missing database url', () => {
    const env = generatedEnv();
    env.delete('DOCUMENTS_DATABASE_URL');
    expect(codesOf(env)).toContain('database_url_missing');
  });

  it('refuses missing brokers, which would silently select the in-memory producer', () => {
    const env = generatedEnv();
    env.set('KAFKA_BROKERS', '');
    expect(codesOf(env)).toContain('kafka_brokers_missing');
  });

  it('warns when an adapter has fallen back to a stub', () => {
    const env = generatedEnv();
    env.set('DOCUMENTS_SCANNER_MODE', 'stub');
    const findings = diagnose(env);
    expect(findings.map((f) => f.code)).toContain('adapter_stubbed');
    // A warning, not an error: the stack still runs and still proves the rest.
    expect(findings.find((f) => f.code === 'adapter_stubbed')?.severity).toBe('warning');
  });
});

describe('parseEnvFile', () => {
  it('ignores comments and blank lines, and keeps values containing =', () => {
    const env = parseEnvFile('# c\n\nA=1\nB=post=gres://x\n  C = 3 \n');
    expect(env.get('A')).toBe('1');
    expect(env.get('B')).toBe('post=gres://x');
    expect(env.get('C')).toBe('3');
    expect(env.has('#')).toBe(false);
  });

  it('skips malformed lines rather than inventing keys', () => {
    expect(parseEnvFile('novalue\n=novalue\n').size).toBe(0);
  });
});

describe('summarize', () => {
  it('counts only errors, and renders every finding', () => {
    const env = generatedEnv();
    env.set('DOCUMENTS_SCANNER_MODE', 'stub');
    env.delete('AWS_ENDPOINT_URL');
    const summary = summarize(diagnose(env));
    expect(summary.errorCount).toBe(1);
    expect(summary.lines).toHaveLength(2);
    expect(summary.lines.some((l) => l.startsWith('warning:'))).toBe(true);
  });

  it('is empty for a clean environment', () => {
    expect(summarize(diagnose(generatedEnv()))).toEqual({ errorCount: 0, lines: [] });
  });
});
