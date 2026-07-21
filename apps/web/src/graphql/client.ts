/**
 * Minimal typed GraphQL client for the BFF.
 *
 * Security posture:
 * - Auth lives in httpOnly cookies set by the BFF; this module never reads,
 *   stores, or forwards any token.
 * - `x-estate-csrf` is a custom header the BFF requires so simple-form CSRF
 *   cannot reach the endpoint.
 * - Requests are persisted-query calls (hash from the checked-in manifest);
 *   the full document is included only outside production.
 * - Server error text is never surfaced: failures narrow to a closed code set
 *   and the UI maps codes to its own copy.
 */
import manifest from '../../persisted-manifest.json';
import { operations, type OperationName } from './operations';

export const GQL_ERROR_CODES = [
  'UNAUTHENTICATED',
  'STEPUP_REQUIRED',
  'INVALID_REQUEST',
  'INVALID_CREDENTIALS',
] as const;

/** Error codes the BFF contract defines. */
export type GqlErrorCode = (typeof GQL_ERROR_CODES)[number];

/** Every way a request can fail, as seen by the UI. */
export type GqlFailureCode = GqlErrorCode | 'NETWORK' | 'UNKNOWN';

export type GqlResult<T> = { ok: true; data: T } | { ok: false; code: GqlFailureCode };

export type MfaLevel = 'none' | 'mfa' | 'stepup';

export interface SessionInfo {
  userId: string;
  mfaLevel: MfaLevel;
  stepUpFresh: boolean;
}

type EmptyVariables = Record<string, never>;

interface OperationSignatures {
  Register: {
    variables: { email: string; password: string };
    data: { register: { ok: boolean } };
  };
  Login: {
    variables: { email: string; password: string };
    data: { login: { ok: boolean } };
  };
  Refresh: { variables: EmptyVariables; data: { refresh: { ok: boolean } } };
  TotpEnroll: { variables: EmptyVariables; data: { totpEnroll: { otpauthUri: string } } };
  TotpVerify: { variables: { code: string }; data: { totpVerify: { ok: boolean } } };
  StepUp: { variables: { code: string }; data: { stepUp: { ok: boolean } } };
  ExportDemo: { variables: EmptyVariables; data: { exportDemo: { ok: boolean } } };
  Session: { variables: EmptyVariables; data: { session: SessionInfo } };
}

const hashByDocument: ReadonlyMap<string, string> = new Map(
  Object.entries(manifest as Record<string, string>).map(([hash, document]) => [document, hash]),
);

function isGqlErrorCode(value: unknown): value is GqlErrorCode {
  return typeof value === 'string' && (GQL_ERROR_CODES as readonly string[]).includes(value);
}

/** Extracts errors[0].extensions.code from an untrusted payload, if present. */
function extractErrorCode(payload: unknown): GqlFailureCode | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const errors = (payload as { errors?: unknown }).errors;
  if (!Array.isArray(errors) || errors.length === 0) return null;
  const first: unknown = errors[0];
  if (typeof first !== 'object' || first === null) return 'UNKNOWN';
  const extensions = (first as { extensions?: unknown }).extensions;
  if (typeof extensions !== 'object' || extensions === null) return 'UNKNOWN';
  const code = (extensions as { code?: unknown }).code;
  return isGqlErrorCode(code) ? code : 'UNKNOWN';
}

/**
 * Sends one persisted GraphQL operation to the same-origin `/graphql` endpoint.
 * Resolves to a discriminated result; never throws on server or network
 * failure and never exposes server-provided message text.
 */
export async function gqlRequest<Name extends OperationName>(
  operation: Name,
  variables: OperationSignatures[Name]['variables'],
): Promise<GqlResult<OperationSignatures[Name]['data']>> {
  const document = operations[operation];
  const sha256Hash = hashByDocument.get(document);
  if (sha256Hash === undefined) {
    // Build-time misconfiguration, not a runtime condition: the checked-in
    // manifest is out of sync with operations.ts.
    throw new Error(
      `No persisted hash for operation "${operation}". Run: node scripts/build-persisted-manifest.mjs`,
    );
  }

  const body: Record<string, unknown> = {
    variables,
    extensions: { persistedQuery: { sha256Hash } },
  };
  if (process.env.NODE_ENV !== 'production') {
    body.query = document;
  }

  let response: Response;
  try {
    response = await fetch('/graphql', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-estate-csrf': '1',
      },
      credentials: 'include',
      body: JSON.stringify(body),
    });
  } catch {
    return { ok: false, code: 'NETWORK' };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return { ok: false, code: 'NETWORK' };
  }

  const errorCode = extractErrorCode(payload);
  if (errorCode !== null) return { ok: false, code: errorCode };

  const data =
    typeof payload === 'object' && payload !== null
      ? (payload as { data?: unknown }).data
      : undefined;
  if (!response.ok || data === undefined || data === null) {
    return { ok: false, code: 'UNKNOWN' };
  }
  return { ok: true, data: data as OperationSignatures[Name]['data'] };
}
