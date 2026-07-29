import {
  inboundCredentialFor,
  outboundCredentialsFor,
  SERVICE_CREDENTIAL_GRAPH,
  SERVICE_NAMES,
} from '@estate/auth-guard';
import { DUMMY_AWS_ACCESS_KEY_ID, DUMMY_AWS_SECRET_ACCESS_KEY } from './generate-env';
import { NETWORK, SERVICES } from './topology';

/**
 * Preflight for a generated stack environment.
 *
 * The generator gets provisioning right by construction; the doctor exists
 * because `.env.stack` is a plain file that a human can edit, and because the
 * two failures it looks for are both SILENT — a stack with either one boots
 * cleanly and looks healthy.
 */

export interface Finding {
  readonly severity: 'error' | 'warning';
  readonly code: string;
  readonly message: string;
}

/** Findings reduced to what a caller prints and exits with. */
export function summarize(findings: readonly Finding[]): {
  errorCount: number;
  lines: string[];
} {
  return {
    errorCount: findings.filter((f) => f.severity === 'error').length,
    lines: findings.map((f) => `${f.severity}: [${f.code}] ${f.message}`),
  };
}

/** Parse a dotenv file. Deliberately minimal: no interpolation, no exports. */
export function parseEnvFile(contents: string): Map<string, string> {
  const env = new Map<string, string>();
  for (const raw of contents.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    env.set(line.slice(0, eq).trim(), line.slice(eq + 1).trim());
  }
  return env;
}

/**
 * Does this look like a real AWS credential rather than LocalStack's?
 *
 * Real access key ids are 20 uppercase alphanumerics beginning with a
 * recognised prefix (AKIA long-term, ASIA temporary, and the others AWS has
 * used). The check is deliberately about SHAPE, not a match against any
 * particular account: the point is to notice that something which could
 * authenticate somewhere real has been placed where only a stub belongs.
 */
export function credentialsLookReal(accessKeyId: string, secretAccessKey: string): boolean {
  if (/^(AKIA|ASIA|ABIA|ACCA|AIDA|AROA|AIPA|ANPA|ANVA|APKA|AGPA)[A-Z0-9]{12,}$/.test(accessKeyId)) {
    return true;
  }
  // A 40-character secret is AWS's shape and nothing a local stack needs.
  return accessKeyId !== DUMMY_AWS_ACCESS_KEY_ID && secretAccessKey.length >= 40;
}

/**
 * Check a generated environment before the stack starts.
 *
 * Ordered by what actually goes wrong, not by section.
 */
export function diagnose(env: ReadonlyMap<string, string>): Finding[] {
  const findings: Finding[] = [];
  const get = (key: string): string => env.get(key) ?? '';

  // 1. THE REAL-AWS FOOTGUN. PR1 gave every AWS client an endpoint override,
  //    and the SDK honours AWS_ENDPOINT_URL ambiently besides. So a stack with
  //    KMS_MODE=aws and no endpoint does not fail — it talks to real AWS,
  //    minting real DEKs and real charges on whatever profile is in scope.
  //    Before an AWS account existed that path merely failed; now it succeeds.
  const endpoint = get('AWS_ENDPOINT_URL');
  const usesAws = SERVICES.some((s) => get(`${s.name.toUpperCase()}_KMS_MODE`) === 'aws');
  if (usesAws && endpoint.length === 0) {
    findings.push({
      severity: 'error',
      code: 'aws_endpoint_missing',
      message:
        'A service is set to KMS_MODE=aws but AWS_ENDPOINT_URL is unset. The AWS SDK would reach REAL AWS: real keys, real objects, real charges. Set it to ' +
        NETWORK.awsEndpoint,
    });
  } else if (
    endpoint.length > 0 &&
    // 'aws-tls' is the production profile's TLS terminator in front of
    // LocalStack — still entirely local, just not plaintext.
    !/^https?:\/\/(localstack|aws-tls|127\.0\.0\.1|localhost)(:|\/|$)/.test(endpoint)
  ) {
    findings.push({
      severity: 'error',
      code: 'aws_endpoint_not_local',
      message: `AWS_ENDPOINT_URL points at ${endpoint}, which is not the local stack. Expected ${NETWORK.awsEndpoint} (or the TLS proxy in production mode).`,
    });
  }

  // 1b. Production reaches AWS over TLS, so it must also be told which CA to
  //     trust. Without this the first KMS call fails on an unknown issuer —
  //     and the tempting "fix" is NODE_TLS_REJECT_UNAUTHORIZED, which would
  //     turn the production TLS requirement into decoration.
  if (get('STACK_MODE') === 'production') {
    if (!endpoint.startsWith('https://')) {
      findings.push({
        severity: 'error',
        code: 'production_endpoint_not_tls',
        message:
          'Production mode requires an https AWS endpoint (the stack runs one in front of LocalStack). Every service refuses to boot otherwise, by design.',
      });
    }
    if (get('NODE_EXTRA_CA_CERTS').length === 0) {
      findings.push({
        severity: 'error',
        code: 'tls_ca_not_trusted',
        message:
          'Production mode uses a generated CA for the AWS endpoint but NODE_EXTRA_CA_CERTS is unset, so TLS verification would fail. Do NOT set NODE_TLS_REJECT_UNAUTHORIZED — trust the CA instead.',
      });
    }
  }

  // 2. REAL CREDENTIALS IN A LOCAL FILE. The dummy values are the second layer
  //    of the same guard: with them, a wrong endpoint fails loudly instead of
  //    succeeding quietly.
  const accessKeyId = get('AWS_ACCESS_KEY_ID');
  const secretAccessKey = get('AWS_SECRET_ACCESS_KEY');
  if (credentialsLookReal(accessKeyId, secretAccessKey)) {
    findings.push({
      severity: 'error',
      code: 'aws_credentials_look_real',
      message:
        'AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY look like real AWS credentials. The stack needs credentials LocalStack accepts and AWS refuses — that is what makes a misconfigured endpoint fail loudly. Use ' +
        `${DUMMY_AWS_ACCESS_KEY_ID}/${DUMMY_AWS_SECRET_ACCESS_KEY}.`,
    });
  }

  // 3. THE CREDENTIAL GRAPH, RESTATED AGAINST THE FILE. The generator cannot
  //    be wrong here; a hand edit can. This is the check the graph module says
  //    nothing performs.
  for (const edge of SERVICE_CREDENTIAL_GRAPH) {
    const calleeVar = `${edge.callee.toUpperCase()}_${edge.envVar}`;
    const expected = get(calleeVar);
    if (edge.holders.length === 0) {
      continue;
    }
    if (expected.length === 0) {
      findings.push({
        severity: 'error',
        code: 'credential_missing',
        message: `${calleeVar} is unset, so ${edge.callee}'s internal routes refuse every caller and ${edge.holders.join('/')} cannot reach them.`,
      });
      continue;
    }
    for (const holder of edge.holders) {
      const holderVar = `${holder.toUpperCase()}_${edge.envVar}`;
      const held = get(holderVar);
      if (held !== expected) {
        findings.push({
          severity: 'error',
          code: 'credential_mismatch',
          message: `${holderVar} does not equal ${calleeVar}. ${holder} would be refused by ${edge.callee} on every call.`,
        });
      }
    }
  }

  // 4. THE M7 COLLAPSE, DIRECTLY — the graph's rule 2, checked as values:
  //    a service NEVER reuses its own inbound credential as an outbound one.
  //    Settlement's config refuses this in production, but only in production,
  //    and development is the mode the stack runs by default. Derived from the
  //    graph for every service rather than hardcoding settlement's two names —
  //    both because the rule is general and because the credential-graph fence
  //    (rightly) refuses token-shaped identifiers it has not declared.
  for (const service of SERVICE_NAMES) {
    const inbound = inboundCredentialFor(service);
    if (!inbound) {
      continue;
    }
    const inboundValue = get(`${service.toUpperCase()}_${inbound.envVar}`);
    if (inboundValue.length === 0) {
      continue;
    }
    for (const outbound of outboundCredentialsFor(service)) {
      if (get(`${service.toUpperCase()}_${outbound.envVar}`) === inboundValue) {
        findings.push({
          severity: 'error',
          code: 'credential_aliased',
          message: `${service}'s inbound credential equals its outbound ${outbound.envVar}. That is the M7 collapse: one value in both directions transitively hands every gate caller a key it must never hold.`,
        });
      }
    }
  }

  // 5. Each service needs its cluster. A missing URL is a service that starts
  //    and 500s per request rather than failing at boot.
  for (const service of SERVICES) {
    if (get(`${service.name.toUpperCase()}_DATABASE_URL`).length === 0) {
      findings.push({
        severity: 'error',
        code: 'database_url_missing',
        message: `${service.name.toUpperCase()}_DATABASE_URL is unset.`,
      });
    }
  }

  // 6. Kafka. Absent brokers do not fail in development — they select the
  //    in-memory producer, so the audit chain silently never leaves the
  //    process and the stack proves nothing about the broker hop.
  if (get('KAFKA_BROKERS').length === 0) {
    findings.push({
      severity: 'error',
      code: 'kafka_brokers_missing',
      message:
        'KAFKA_BROKERS is unset. In development that silently selects the in-memory audit producer, so nothing crosses a real broker and the stack proves less than it appears to.',
    });
  }

  // 7. Adapters. Any stub here means the stack is not testing what it claims.
  const stubbed: Array<[string, string, string]> = [
    ['DOCUMENTS_OBJECT_STORE_MODE', 's3', 'the filesystem object store'],
    ['DOCUMENTS_SCANNER_MODE', 'clamd', 'the stub malware scanner'],
    ['DOCUMENTS_OCR_MODE', 'tesseract', 'the stub OCR engine'],
  ];
  for (const [key, expected, what] of stubbed) {
    const actual = get(key);
    if (actual !== expected) {
      findings.push({
        severity: 'warning',
        code: 'adapter_stubbed',
        message: `${key} is "${actual || '(unset)'}", not "${expected}" — the stack would run ${what} instead of the real dependency.`,
      });
    }
  }

  // 8. TLS verification must never be switched off to make the stack run.
  //    It is the shortest path from "production mode won't connect" to a
  //    green stack that proves nothing about transport security.
  if (env.get('NODE_TLS_REJECT_UNAUTHORIZED') === '0') {
    findings.push({
      severity: 'error',
      code: 'tls_verification_disabled',
      message:
        'NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verification process-wide, which makes the production https requirement decoration. Trust the stack CA via NODE_EXTRA_CA_CERTS instead.',
    });
  }

  return findings;
}
