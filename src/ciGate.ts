/**
 * Named CI / local test suites and the ordered PR gate phases.
 * Pure contract — scripts and vitest projects must stay aligned with these names.
 */

export const NAMED_SUITES = ["unit", "http", "live-cognito"] as const;
export type NamedSuite = (typeof NAMED_SUITES)[number];

/** Default `npm test` — no cloud credentials required. */
export const DEFAULT_TEST_SUITES = ["unit", "http"] as const;

export type CiGatePhase =
  | "typecheck"
  | "unit"
  | "http"
  | "infra-typecheck-and-assertions"
  | "synth"
  | "validate-manifest-and-preflight"
  | "live-cognito"
  | "cleanup-secret-files";

/** Ordered PR gate. Live Cognito runs only after all prior phases succeed. */
export const CI_GATE_PHASES: readonly CiGatePhase[] = [
  "typecheck",
  "unit",
  "http",
  "infra-typecheck-and-assertions",
  "synth",
  "validate-manifest-and-preflight",
  "live-cognito",
  "cleanup-secret-files",
];

export type BuildFailureCategory =
  | "static"
  | "infrastructure"
  | "profile-drift"
  | "semantic-scenario"
  | "operational-aws"
  | "timeout"
  | "cleanup"
  | "finalization"
  | "deployment";

const PHASE_CATEGORY: Record<CiGatePhase, BuildFailureCategory> = {
  typecheck: "static",
  unit: "static",
  http: "static",
  "infra-typecheck-and-assertions": "infrastructure",
  synth: "infrastructure",
  "validate-manifest-and-preflight": "profile-drift",
  "live-cognito": "semantic-scenario",
  "cleanup-secret-files": "cleanup",
};

/** Phases that must not create Cognito personas. */
export const PHASES_BEFORE_LIVE: readonly CiGatePhase[] = CI_GATE_PHASES.filter(
  (phase) => phase !== "live-cognito" && phase !== "cleanup-secret-files",
);

export function classifyFailedPhase(phase: CiGatePhase): BuildFailureCategory {
  return PHASE_CATEGORY[phase];
}

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
