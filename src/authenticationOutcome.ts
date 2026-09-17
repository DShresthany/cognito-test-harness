export type AuthenticationOperation =
  | "admin-initiate-auth"
  | "initiate-auth"
  | "respond-to-auth-challenge"
  | "verify-software-token"
  | "associate-software-token"
  | "refresh-token"
  | "verify-access-token";

export type CognitoTokenSet = {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresInSeconds?: number;
  tokenType?: string;
};

export type OpaqueChallengeSession = string & {
  readonly __brand: "OpaqueChallengeSession";
};

export type CanonicalUsername = string & {
  readonly __brand: "CanonicalUsername";
};

export type AuthenticationProfileId = string & {
  readonly __brand: "AuthenticationProfileId";
};

export type ChallengeContinuation = {
  session: OpaqueChallengeSession;
  username: CanonicalUsername;
  profileId: AuthenticationProfileId;
};

export type MfaMethod = "software-token-mfa" | "sms-mfa";

export type AuthenticationChallenge =
  | {
      type: "new-password-required";
      continuation: ChallengeContinuation;
      requiredAttributes: string[];
    }
  | {
      type: "mfa-setup";
      continuation: ChallengeContinuation;
      availableMethods: MfaMethod[];
    }
  | {
      type: "software-token-mfa";
      continuation: ChallengeContinuation;
    }
  | {
      type: "select-mfa-type";
      continuation: ChallengeContinuation;
      availableMfaMethods: MfaMethod[];
    };

export type AuthenticationRejectionReason =
  | "invalid-credentials"
  | "user-not-confirmed"
  | "password-reset-required"
  | "invalid-code"
  | "expired-code"
  | "invalid-refresh-token"
  | "invalid-access-token"
  | "invalid-challenge-session"
  | "recovery-unavailable"
  | "password-policy-violation"
  | "too-many-failed-attempts";

export type ProviderDiagnostic = {
  providerCode?: string;
  operation: AuthenticationOperation;
  requestId?: string;
  requestIds?: string[];
  reasonCode?: string;
};

export type AuthenticationRejection = {
  reason: AuthenticationRejectionReason;
  diagnostic: ProviderDiagnostic;
};

export type AuthenticationOutcome =
  | { kind: "authenticated"; tokens: CognitoTokenSet }
  | { kind: "challenged"; challenge: AuthenticationChallenge }
  | { kind: "rejected"; rejection: AuthenticationRejection };

export type OperationalCategory =
  | "configuration"
  | "iam-authorization"
  | "request-blocked"
  | "throttled"
  | "service"
  | "network"
  | "delivery"
  | "unsupported-response";

export type CognitoAuthResponse = {
  AuthenticationResult?: {
    AccessToken?: string;
    IdToken?: string;
    RefreshToken?: string;
    ExpiresIn?: number;
    TokenType?: string;
  };
  ChallengeName?: string;
  ChallengeParameters?: Record<string, string>;
  Session?: string;
  Status?: string;
};

export type MapAuthenticationOutcomeInput = {
  operation: AuthenticationOperation;
  response?: CognitoAuthResponse;
  error?: unknown;
  continuation?: {
    username?: string;
    profileId: string;
  };
};

export class OperationalAuthenticationFailure extends Error {
  readonly category: OperationalCategory;
  readonly operation: AuthenticationOperation;
  readonly retryable: boolean;
  readonly diagnostic: ProviderDiagnostic;

  constructor(args: {
    category: OperationalCategory;
    operation: AuthenticationOperation;
    retryable: boolean;
    diagnostic?: Omit<ProviderDiagnostic, "operation">;
    message?: string;
    cause?: unknown;
  }) {
    super(args.message ?? `operational authentication failure: ${args.category}`, {
      cause: args.cause,
    });
    this.name = "OperationalAuthenticationFailure";
    this.category = args.category;
    this.operation = args.operation;
    this.retryable = args.retryable;
    this.diagnostic = {
      operation: args.operation,
      ...args.diagnostic,
    };
  }
}

export type SafeDiagnostic = {
  operation: AuthenticationOperation;
  outcomeKind: "authenticated" | "challenged" | "rejected" | "operational-failure";
  challengeType?: AuthenticationChallenge["type"];
  rejectionReason?: AuthenticationRejectionReason;
  providerCode?: string;
  requestId?: string;
  requestIds?: string[];
  retryable?: boolean;
  category?: OperationalCategory;
  profileId?: string;
};

function assertNever(_value: never): never {
  throw new Error("unhandled authentication variant");
}

function asOpaqueSession(session: string): OpaqueChallengeSession {
  return session as OpaqueChallengeSession;
}

function asCanonicalUsername(username: string): CanonicalUsername {
  return username as CanonicalUsername;
}

function asProfileId(profileId: string): AuthenticationProfileId {
  return profileId as AuthenticationProfileId;
}

export function mapAuthenticationOutcome(
  input: MapAuthenticationOutcomeInput,
): AuthenticationOutcome {
  if (input.error !== undefined) {
    return mapError(input.operation, input.error);
  }

  return mapResponse(input);
}

function mapResponse(input: MapAuthenticationOutcomeInput): AuthenticationOutcome {
  const response = input.response;
  if (!response) {
    throw new OperationalAuthenticationFailure({
      category: "unsupported-response",
      operation: input.operation,
      retryable: false,
    });
  }

  if (input.operation === "verify-software-token") {
    return mapVerifySoftwareToken(input.operation, response);
  }

  const tokens = response.AuthenticationResult;
  if (tokens?.AccessToken && tokens.IdToken) {
    return {
      kind: "authenticated",
      tokens: {
        accessToken: tokens.AccessToken,
        idToken: tokens.IdToken,
        ...(tokens.RefreshToken ? { refreshToken: tokens.RefreshToken } : {}),
        ...(tokens.ExpiresIn !== undefined
          ? { expiresInSeconds: tokens.ExpiresIn }
          : {}),
        ...(tokens.TokenType ? { tokenType: tokens.TokenType } : {}),
      },
    };
  }

  if (response.ChallengeName) {
    return mapChallenge(input, response);
  }

  throw new OperationalAuthenticationFailure({
    category: "unsupported-response",
    operation: input.operation,
    retryable: false,
  });
}

function mapVerifySoftwareToken(
  operation: AuthenticationOperation,
  response: CognitoAuthResponse,
): AuthenticationOutcome {
  switch (response.Status) {
    case "ERROR":
      return {
        kind: "rejected",
        rejection: {
          reason: "invalid-code",
          diagnostic: { operation },
        },
      };
    case "SUCCESS":
      // Enrollment/verification succeeded; that is not an authentication outcome.
      // Drivers handle SUCCESS before asking the mapper for an outcome.
      throw new OperationalAuthenticationFailure({
        category: "unsupported-response",
        operation,
        retryable: false,
        diagnostic: { providerCode: "SUCCESS" },
      });
    default:
      throw new OperationalAuthenticationFailure({
        category: "unsupported-response",
        operation,
        retryable: false,
        diagnostic: { providerCode: response.Status },
      });
  }
}

function mapChallenge(
  input: MapAuthenticationOutcomeInput,
  response: CognitoAuthResponse,
): AuthenticationOutcome {
  const session = response.Session;
  const username =
    response.ChallengeParameters?.USERNAME ?? input.continuation?.username;
  const profileId = input.continuation?.profileId;

  if (!session || !username || !profileId) {
    throw new OperationalAuthenticationFailure({
      category: "unsupported-response",
      operation: input.operation,
      retryable: false,
    });
  }

  const continuation: ChallengeContinuation = {
    session: asOpaqueSession(session),
    username: asCanonicalUsername(username),
    profileId: asProfileId(profileId),
  };

  const challengeName = response.ChallengeName;
  switch (challengeName) {
    case "NEW_PASSWORD_REQUIRED":
      return {
        kind: "challenged",
        challenge: {
          type: "new-password-required",
          continuation,
          requiredAttributes: parseRequiredAttributes(
            response.ChallengeParameters?.requiredAttributes,
          ),
        },
      };
    case "MFA_SETUP":
      return {
        kind: "challenged",
        challenge: {
          type: "mfa-setup",
          continuation,
          availableMethods: parseMfaMethods(
            input.operation,
            response.ChallengeParameters?.MFAS_CAN_SETUP,
          ),
        },
      };
    case "SOFTWARE_TOKEN_MFA":
      return {
        kind: "challenged",
        challenge: {
          type: "software-token-mfa",
          continuation,
        },
      };
    case "SELECT_MFA_TYPE":
      return {
        kind: "challenged",
        challenge: {
          type: "select-mfa-type",
          continuation,
          availableMfaMethods: parseMfaMethods(
            input.operation,
            response.ChallengeParameters?.MFAS_CAN_CHOOSE,
          ),
        },
      };
    default:
      throw new OperationalAuthenticationFailure({
        category: "unsupported-response",
        operation: input.operation,
        retryable: false,
        diagnostic: { providerCode: challengeName },
      });
  }
}

function parseRequiredAttributes(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.flatMap((value) => {
      if (typeof value !== "string") {
        return [];
      }
      return [value.replace(/^userAttributes\./, "")];
    });
  } catch {
    return raw
      .split(",")
      .map((part) => part.trim().replace(/^userAttributes\./, ""))
      .filter(Boolean);
  }
}

function parseMfaMethods(
  operation: AuthenticationOperation,
  raw: string | undefined,
): MfaMethod[] {
  if (!raw) {
    return [];
  }

  return parseMfaMethodNames(raw).flatMap((name) => {
    switch (name) {
      case "SOFTWARE_TOKEN_MFA":
        return ["software-token-mfa" as const];
      case "SMS_MFA":
        return ["sms-mfa" as const];
      default:
        throw new OperationalAuthenticationFailure({
          category: "unsupported-response",
          operation,
          retryable: false,
          diagnostic: { providerCode: name },
        });
    }
  });
}

function parseMfaMethodNames(raw: string): string[] {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.flatMap((value) =>
      typeof value === "string" ? [value] : [],
    );
  } catch {
    return raw
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
  }
}

function mapError(
  operation: AuthenticationOperation,
  error: unknown,
): AuthenticationOutcome {
  const name = errorName(error);
  const requestId = requestIdOf(error);
  const reasonCode = reasonCodeOf(error);
  const diagnostic: ProviderDiagnostic = {
    operation,
    ...(name ? { providerCode: name } : {}),
    ...(requestId ? { requestId, requestIds: [requestId] } : {}),
    ...(reasonCode ? { reasonCode } : {}),
  };

  switch (name) {
    case "NotAuthorizedException":
      return {
        kind: "rejected",
        rejection: {
          reason: notAuthorizedReason(operation),
          diagnostic,
        },
      };
    case "UserNotFoundException":
      return {
        kind: "rejected",
        rejection: {
          reason: "invalid-credentials",
          diagnostic,
        },
      };
    case "UserNotConfirmedException":
      return {
        kind: "rejected",
        rejection: {
          reason: "user-not-confirmed",
          diagnostic,
        },
      };
    case "PasswordResetRequiredException":
      return {
        kind: "rejected",
        rejection: {
          reason: "password-reset-required",
          diagnostic,
        },
      };
    case "CodeMismatchException":
    case "EnableSoftwareTokenMFAException":
      return {
        kind: "rejected",
        rejection: {
          reason: "invalid-code",
          diagnostic,
        },
      };
    case "ExpiredCodeException":
      return {
        kind: "rejected",
        rejection: {
          reason: "expired-code",
          diagnostic,
        },
      };
    case "InvalidPasswordException":
    case "PasswordHistoryPolicyViolationException":
      return {
        kind: "rejected",
        rejection: {
          reason: "password-policy-violation",
          diagnostic,
        },
      };
    case "TooManyFailedAttemptsException":
      return {
        kind: "rejected",
        rejection: {
          reason: "too-many-failed-attempts",
          diagnostic,
        },
      };
    case "RefreshTokenReuseException":
      return {
        kind: "rejected",
        rejection: {
          reason: "invalid-refresh-token",
          diagnostic,
        },
      };
    case "UnauthorizedException":
    case "UnsupportedTokenTypeException":
      return {
        kind: "rejected",
        rejection: {
          reason: "invalid-access-token",
          diagnostic,
        },
      };
    case "TooManyRequestsException":
      throw new OperationalAuthenticationFailure({
        category: "throttled",
        operation,
        retryable: true,
        diagnostic,
        cause: error,
      });
    case "ForbiddenException":
      throw new OperationalAuthenticationFailure({
        category: "request-blocked",
        operation,
        retryable: false,
        diagnostic,
        cause: error,
      });
    case "AccessDeniedException":
      throw new OperationalAuthenticationFailure({
        category: "iam-authorization",
        operation,
        retryable: false,
        diagnostic,
        cause: error,
      });
    case "InternalErrorException":
    case "InternalServerException":
    case "InvalidLambdaResponseException":
    case "UnexpectedLambdaException":
      throw new OperationalAuthenticationFailure({
        category: "service",
        operation,
        retryable: true,
        diagnostic,
        cause: error,
      });
    case "UserLambdaValidationException":
      throw new OperationalAuthenticationFailure({
        category: "service",
        operation,
        retryable: false,
        diagnostic,
        cause: error,
      });
    case "CodeDeliveryFailureException":
      throw new OperationalAuthenticationFailure({
        category: "delivery",
        operation,
        retryable: false,
        diagnostic,
        cause: error,
      });
    case "InvalidParameterException":
      return mapInvalidParameter(operation, diagnostic, error);
    case "InvalidUserPoolConfigurationException":
    case "ResourceNotFoundException":
    case "SoftwareTokenMFANotFoundException":
    case "InvalidSmsRoleAccessPolicyException":
    case "InvalidSmsRoleTrustRelationshipException":
    case "InvalidEmailRoleAccessPolicyException":
    case "OperationNotEnabledException":
      throw new OperationalAuthenticationFailure({
        category: "configuration",
        operation,
        retryable: false,
        diagnostic,
        cause: error,
      });
    default:
      if (isNetworkError(error)) {
        throw new OperationalAuthenticationFailure({
          category: "network",
          operation,
          retryable: true,
          diagnostic,
          cause: error,
        });
      }
      throw new OperationalAuthenticationFailure({
        category: "unsupported-response",
        operation,
        retryable: false,
        diagnostic,
        cause: error,
      });
  }
}

function mapInvalidParameter(
  operation: AuthenticationOperation,
  diagnostic: ProviderDiagnostic,
  error: unknown,
): AuthenticationOutcome {
  if (operation === "respond-to-auth-challenge") {
    return {
      kind: "rejected",
      rejection: {
        reason: "invalid-challenge-session",
        diagnostic,
      },
    };
  }

  if (operation === "refresh-token") {
    return {
      kind: "rejected",
      rejection: {
        reason: "invalid-refresh-token",
        diagnostic,
      },
    };
  }

  throw new OperationalAuthenticationFailure({
    category: "configuration",
    operation,
    retryable: false,
    diagnostic,
    cause: error,
  });
}

function notAuthorizedReason(
  operation: AuthenticationOperation,
): AuthenticationRejectionReason {
  switch (operation) {
    case "refresh-token":
      return "invalid-refresh-token";
    case "respond-to-auth-challenge":
      return "invalid-challenge-session";
    case "associate-software-token":
    case "verify-software-token":
    case "verify-access-token":
      return "invalid-access-token";
    case "admin-initiate-auth":
    case "initiate-auth":
      return "invalid-credentials";
    default: {
      const exhaustive: never = operation;
      return assertNever(exhaustive);
    }
  }
}

function errorName(error: unknown): string | undefined {
  if (typeof error === "object" && error !== null && "name" in error) {
    const name = (error as { name?: unknown }).name;
    if (typeof name === "string") {
      return name;
    }
  }
  return undefined;
}

function requestIdOf(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("$metadata" in error)) {
    return undefined;
  }
  const metadata = (error as { $metadata?: { requestId?: unknown } }).$metadata;
  return typeof metadata?.requestId === "string" ? metadata.requestId : undefined;
}

function reasonCodeOf(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("reasonCode" in error)) {
    return undefined;
  }
  const reasonCode = (error as { reasonCode?: unknown }).reasonCode;
  return typeof reasonCode === "string" ? reasonCode : undefined;
}

function isNetworkError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) {
    return false;
  }

  const candidate = error as { name?: unknown; code?: unknown };
  const name = typeof candidate.name === "string" ? candidate.name : "";
  const code = typeof candidate.code === "string" ? candidate.code : "";

  return (
    name === "TimeoutError" ||
    name === "NetworkingError" ||
    code === "ECONNRESET" ||
    code === "ETIMEDOUT" ||
    code === "ENOTFOUND" ||
    code === "ECONNREFUSED"
  );
}

function challengeTypeOf(
  challenge: AuthenticationChallenge,
): AuthenticationChallenge["type"] {
  switch (challenge.type) {
    case "new-password-required":
    case "mfa-setup":
    case "software-token-mfa":
    case "select-mfa-type":
      return challenge.type;
    default:
      return assertNever(challenge);
  }
}

function rejectionReasonOf(
  reason: AuthenticationRejectionReason,
): AuthenticationRejectionReason {
  switch (reason) {
    case "invalid-credentials":
    case "user-not-confirmed":
    case "password-reset-required":
    case "invalid-code":
    case "expired-code":
    case "invalid-refresh-token":
    case "invalid-access-token":
    case "invalid-challenge-session":
    case "recovery-unavailable":
    case "password-policy-violation":
    case "too-many-failed-attempts":
      return reason;
    default:
      return assertNever(reason);
  }
}

function operationalCategoryOf(
  category: OperationalCategory,
): OperationalCategory {
  switch (category) {
    case "configuration":
    case "iam-authorization":
    case "request-blocked":
    case "throttled":
    case "service":
    case "network":
    case "delivery":
    case "unsupported-response":
      return category;
    default:
      return assertNever(category);
  }
}

export function requireAuthenticated(
  outcome: AuthenticationOutcome,
): CognitoTokenSet {
  switch (outcome.kind) {
    case "authenticated":
      return outcome.tokens;
    case "challenged":
      throw new Error("expected authenticated outcome, received challenged");
    case "rejected":
      throw new Error("expected authenticated outcome, received rejected");
    default: {
      const exhaustive: never = outcome;
      return assertNever(exhaustive);
    }
  }
}

export function toSafeDiagnostic(
  value: AuthenticationOutcome | OperationalAuthenticationFailure,
  context: { operation: AuthenticationOperation; profileId?: string },
): SafeDiagnostic {
  if (value instanceof OperationalAuthenticationFailure) {
    return {
      operation: value.operation,
      outcomeKind: "operational-failure",
      category: operationalCategoryOf(value.category),
      retryable: value.retryable,
      ...(value.diagnostic.providerCode
        ? { providerCode: value.diagnostic.providerCode }
        : {}),
      ...(value.diagnostic.requestId
        ? { requestId: value.diagnostic.requestId }
        : {}),
      ...(value.diagnostic.requestIds
        ? { requestIds: value.diagnostic.requestIds }
        : {}),
      ...(context.profileId ? { profileId: context.profileId } : {}),
    };
  }

  switch (value.kind) {
    case "authenticated":
      return {
        operation: context.operation,
        outcomeKind: "authenticated",
        ...(context.profileId ? { profileId: context.profileId } : {}),
      };
    case "challenged":
      return {
        operation: context.operation,
        outcomeKind: "challenged",
        challengeType: challengeTypeOf(value.challenge),
        profileId: value.challenge.continuation.profileId,
      };
    case "rejected":
      return {
        operation: value.rejection.diagnostic.operation,
        outcomeKind: "rejected",
        rejectionReason: rejectionReasonOf(value.rejection.reason),
        ...(value.rejection.diagnostic.providerCode
          ? { providerCode: value.rejection.diagnostic.providerCode }
          : {}),
        ...(value.rejection.diagnostic.requestId
          ? { requestId: value.rejection.diagnostic.requestId }
          : {}),
        ...(context.profileId ? { profileId: context.profileId } : {}),
      };
    default:
      return assertNever(value);
  }
}

export type RetryAuthenticationDependencies = {
  maxAttempts?: number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
};

const DEFAULT_MAX_ATTEMPTS = 3;
const BASE_DELAY_MS = 100;
const MAX_DELAY_MS = 2000;

export async function retryAuthenticationOperation<T>(
  run: () => Promise<T>,
  deps: RetryAuthenticationDependencies = {},
): Promise<T> {
  const maxAttempts = deps.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const sleep = deps.sleep ?? defaultSleep;
  const random = deps.random ?? Math.random;
  const requestIds: string[] = [];
  let attempt = 0;

  while (true) {
    try {
      return await run();
    } catch (error) {
      if (!(error instanceof OperationalAuthenticationFailure) || !error.retryable) {
        throw error;
      }

      if (error.diagnostic.requestId) {
        requestIds.push(error.diagnostic.requestId);
      }

      attempt += 1;
      if (attempt >= maxAttempts) {
        throw new OperationalAuthenticationFailure({
          category: error.category,
          operation: error.operation,
          retryable: true,
          diagnostic: {
            ...error.diagnostic,
            requestIds: requestIds.length > 0 ? requestIds : error.diagnostic.requestIds,
            requestId: error.diagnostic.requestId,
          },
          cause: error,
        });
      }

      const cap = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** (attempt - 1));
      const delay = Math.floor(random() * cap);
      await sleep(delay);
    }
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
