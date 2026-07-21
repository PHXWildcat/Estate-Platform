/**
 * Single source of truth for every GraphQL operation this app sends.
 *
 * Format contract (relied on by scripts/build-persisted-manifest.mjs, which
 * extracts these documents with a line-anchored pattern, and guarded by the
 * manifest sync test): each document is declared as
 * `export const <NAME>_(MUTATION|QUERY) = \`...\`;` with no interpolation and
 * no backticks inside the document. Edit a document -> regenerate the
 * manifest: `node scripts/build-persisted-manifest.mjs`.
 */

export const REGISTER_MUTATION = `mutation Register($email: String!, $password: String!) {
  register(email: $email, password: $password) {
    ok
  }
}`;

export const LOGIN_MUTATION = `mutation Login($email: String!, $password: String!) {
  login(email: $email, password: $password) {
    ok
  }
}`;

export const REFRESH_MUTATION = `mutation Refresh {
  refresh {
    ok
  }
}`;

export const TOTP_ENROLL_MUTATION = `mutation TotpEnroll {
  totpEnroll {
    otpauthUri
  }
}`;

export const TOTP_VERIFY_MUTATION = `mutation TotpVerify($code: String!) {
  totpVerify(code: $code) {
    ok
  }
}`;

export const STEP_UP_MUTATION = `mutation StepUp($code: String!) {
  stepUp(code: $code) {
    ok
  }
}`;

export const EXPORT_DEMO_MUTATION = `mutation ExportDemo {
  exportDemo {
    ok
  }
}`;

export const SESSION_QUERY = `query Session {
  session {
    userId
    mfaLevel
    stepUpFresh
  }
}`;

export const operations = {
  Register: REGISTER_MUTATION,
  Login: LOGIN_MUTATION,
  Refresh: REFRESH_MUTATION,
  TotpEnroll: TOTP_ENROLL_MUTATION,
  TotpVerify: TOTP_VERIFY_MUTATION,
  StepUp: STEP_UP_MUTATION,
  ExportDemo: EXPORT_DEMO_MUTATION,
  Session: SESSION_QUERY,
} as const;

export type OperationName = keyof typeof operations;
