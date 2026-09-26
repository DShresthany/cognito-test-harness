/**
 * Named CI / local test suites, report allowlist, and required npm scripts.
 * Pure contract — scripts and vitest projects must stay aligned with these names.
 * Gate order lives in scripts/ci-gate.sh.
 */

export const NAMED_SUITES = ["unit", "http", "live-cognito"] as const;
export type NamedSuite = (typeof NAMED_SUITES)[number];

/** Default `npm test` — no cloud credentials required. */
export const DEFAULT_TEST_SUITES = ["unit", "http"] as const;

/**
 * Allowlisted top-level keys for scenario / CI report objects.
 * Values must never be usernames, tokens, secrets, sessions, or codes.
 */
export const REPORT_ALLOWLIST_FIELDS = [
  "operation",
  "outcomeKind",
  "challengeType",
  "rejectionReason",
  "category",
  "providerCode",
  "requestId",
  "requestIds",
  "retryable",
  "profileId",
  "cleanupStatus",
  "enrollmentVerified",
  "preferredMfaSet",
  "mfaAuthenticated",
  "accessVerified",
  "idVerified",
  "wrongCodeRejected",
  "wrongCodeReason",
  "recovered",
  "reuseRejected",
  "refreshTokenIssued",
  "temporaryPasswordRejected",
  "newPasswordAuthenticates",
  "requiredAttributes",
  "policyViolationReason",
  "accessVerifiesOnAccess",
  "idVerifiesOnId",
  "accessRejectedAsId",
  "idRejectedAsAccess",
  "tamperedAccessRejected",
  "tamperedIdRejected",
  "crossProfileAccessRejected",
  "crossProfileIdRejected",
] as const;

export function assertReportKeysAllowlisted(
  evidence: Record<string, unknown>,
): void {
  const allowed = new Set<string>(REPORT_ALLOWLIST_FIELDS);
  for (const key of Object.keys(evidence)) {
    if (!allowed.has(key)) {
      throw new Error(`report field not allowlisted: ${key}`);
    }
  }
}

/** npm script names that must exist for the named suites. */
export const REQUIRED_NPM_SCRIPTS = {
  test: "default unit+http",
  "test:unit": "unit suite",
  "test:http": "http suite",
  "test:live:cognito": "serial live Cognito (includes TOTP)",
  typecheck: "root TypeScript check",
  preflight: "manifest validate + live Describe preflight",
  "ci:gate": "ordered PR gate",
} as const;
