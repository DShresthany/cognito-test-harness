import {
  AccessDeniedException,
  CodeDeliveryFailureException,
  CodeMismatchException,
  ExpiredCodeException,
  ForbiddenException,
  InternalErrorException,
  InvalidParameterException,
  InvalidPasswordException,
  InvalidUserPoolConfigurationException,
  NotAuthorizedException,
  PasswordResetRequiredException,
  TooManyFailedAttemptsException,
  TooManyRequestsException,
  UnexpectedLambdaException,
  UserLambdaValidationException,
  UserNotConfirmedException,
  UserNotFoundException,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import {
  mapAuthenticationOutcome,
  OperationalAuthenticationFailure,
  retryAuthenticationOperation,
  toSafeDiagnostic,
  type AuthenticationChallenge,
  type AuthenticationOperation,
  type AuthenticationOutcome,
  type AuthenticationRejectionReason,
  type OperationalCategory,
} from "../../src/authenticationOutcome.js";

const continuation = {
  username: "persona@example.com",
  profileId: "user-pool-public",
};

function cognitoException<T>(
  Ctor: new (args: { $metadata: { requestId?: string }; message: string }) => T,
  message: string,
  requestId = "req-1",
): T {
  return new Ctor({
    $metadata: { requestId },
    message,
  });
}

function expectRejected(
  outcome: AuthenticationOutcome,
  reason: AuthenticationRejectionReason,
  providerCode?: string,
): void {
  expect(outcome.kind).toBe("rejected");
  if (outcome.kind !== "rejected") {
    return;
  }
  expect(outcome.rejection.reason).toBe(reason);
  if (providerCode) {
    expect(outcome.rejection.diagnostic.providerCode).toBe(providerCode);
  }
}

function expectOperational(
  run: () => unknown,
  expected: {
    category: OperationalCategory;
    retryable: boolean;
    operation?: AuthenticationOperation;
    providerCode?: string;
  },
): OperationalAuthenticationFailure {
  try {
    run();
    throw new Error("expected operational authentication failure");
  } catch (error) {
    expect(error).toBeInstanceOf(OperationalAuthenticationFailure);
    const failure = error as OperationalAuthenticationFailure;
    expect(failure.category).toBe(expected.category);
    expect(failure.retryable).toBe(expected.retryable);
    if (expected.operation) {
      expect(failure.operation).toBe(expected.operation);
    }
    if (expected.providerCode) {
      expect(failure.diagnostic.providerCode).toBe(expected.providerCode);
    }
    return failure;
  }
}

describe("mapAuthenticationOutcome", () => {
  it("maps a token result to authenticated with access, ID, and optional refresh tokens", () => {
    const outcome = mapAuthenticationOutcome({
      operation: "admin-initiate-auth",
      response: {
        AuthenticationResult: {
          AccessToken: "access-token",
          IdToken: "id-token",
          RefreshToken: "refresh-token",
          ExpiresIn: 3600,
          TokenType: "Bearer",
        },
      },
    });

    expect(outcome).toEqual({
      kind: "authenticated",
      tokens: {
        accessToken: "access-token",
        idToken: "id-token",
        refreshToken: "refresh-token",
        expiresInSeconds: 3600,
        tokenType: "Bearer",
      },
    });
  });

  it("maps public initiate-auth tokens without a refresh token", () => {
    const outcome = mapAuthenticationOutcome({
      operation: "initiate-auth",
      response: {
        AuthenticationResult: {
          AccessToken: "access-token",
          IdToken: "id-token",
        },
      },
    });

    expect(outcome).toEqual({
      kind: "authenticated",
      tokens: {
        accessToken: "access-token",
        idToken: "id-token",
      },
    });
  });

  it("NP-5: maps NEW_PASSWORD_REQUIRED requiredAttributes without live pool mutation", () => {
    const session = "challenge-session-np5";
    const outcome = mapAuthenticationOutcome({
      operation: "initiate-auth",
      continuation,
      response: {
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        Session: session,
        ChallengeParameters: {
          USERNAME: "canonical-user",
          requiredAttributes: '["userAttributes.email","userAttributes.name"]',
        },
      },
    });

    expect(outcome).toEqual({
      kind: "challenged",
      challenge: {
        type: "new-password-required",
        requiredAttributes: ["email", "name"],
        continuation: {
          session,
          username: "canonical-user",
          profileId: "user-pool-public",
        },
      },
    });
  });

  it("maps MFA_SETUP, SOFTWARE_TOKEN_MFA, and SELECT_MFA_TYPE with typed parameters", () => {
    const cases: Array<{
      challengeName: string;
      parameters?: Record<string, string>;
      expected: AuthenticationChallenge["type"];
      extra?: Record<string, unknown>;
    }> = [
      {
        challengeName: "MFA_SETUP",
        parameters: {
          MFAS_CAN_SETUP: '["SOFTWARE_TOKEN_MFA","SMS_MFA"]',
        },
        expected: "mfa-setup",
        extra: { availableMethods: ["software-token-mfa", "sms-mfa"] },
      },
      {
        challengeName: "SOFTWARE_TOKEN_MFA",
        expected: "software-token-mfa",
      },
      {
        challengeName: "SELECT_MFA_TYPE",
        parameters: { MFAS_CAN_CHOOSE: '["SOFTWARE_TOKEN_MFA"]' },
        expected: "select-mfa-type",
        extra: { availableMfaMethods: ["software-token-mfa"] },
      },
    ];

    for (const testCase of cases) {
      const session = `session-for-${testCase.challengeName}`;
      const outcome = mapAuthenticationOutcome({
        operation: "respond-to-auth-challenge",
        continuation,
        response: {
          ChallengeName: testCase.challengeName,
          Session: session,
          ChallengeParameters: {
            USERNAME: continuation.username,
            ...testCase.parameters,
          },
        },
      });

      expect(outcome.kind).toBe("challenged");
      if (outcome.kind !== "challenged") {
        continue;
      }
      expect(outcome.challenge.type).toBe(testCase.expected);
      expect(outcome.challenge.continuation.session).toBe(session);
      expect(outcome.challenge.continuation.username).toBe(continuation.username);
      expect(outcome.challenge.continuation.profileId).toBe(continuation.profileId);
      if (testCase.extra) {
        expect(outcome.challenge).toMatchObject(testCase.extra);
      }
    }
  });

  it("maps NEW_PASSWORD_REQUIRED without required attributes to an empty list", () => {
    const outcome = mapAuthenticationOutcome({
      operation: "initiate-auth",
      continuation,
      response: {
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        Session: "session-empty-attrs",
        ChallengeParameters: { USERNAME: continuation.username },
      },
    });

    expect(outcome).toMatchObject({
      kind: "challenged",
      challenge: {
        type: "new-password-required",
        requiredAttributes: [],
      },
    });
  });

  it("maps a successful response with missing tokens and no challenge to unsupported-response", () => {
    expectOperational(
      () =>
        mapAuthenticationOutcome({
          operation: "initiate-auth",
          response: {
            AuthenticationResult: { AccessToken: "access-only" },
          },
        }),
      { category: "unsupported-response", retryable: false },
    );
  });

  it("maps an unknown challenge name to operational unsupported-response", () => {
    expectOperational(
      () =>
        mapAuthenticationOutcome({
          operation: "initiate-auth",
          continuation,
          response: {
            ChallengeName: "CUSTOM_CHALLENGE",
            Session: "session",
            ChallengeParameters: { USERNAME: continuation.username },
          },
        }),
      {
        category: "unsupported-response",
        retryable: false,
        providerCode: "CUSTOM_CHALLENGE",
      },
    );
  });

  it("maps VerifySoftwareToken status ERROR to rejection invalid-code", () => {
    const outcome = mapAuthenticationOutcome({
      operation: "verify-software-token",
      response: { Status: "ERROR" },
    });

    expectRejected(outcome, "invalid-code");
  });

  it("maps a missing VerifySoftwareToken status to operational unsupported-response", () => {
    expectOperational(
      () =>
        mapAuthenticationOutcome({
          operation: "verify-software-token",
          response: {},
        }),
      { category: "unsupported-response", retryable: false },
    );
  });

  it("maps Cognito exceptions by operation to first-release rejections and operational failures", () => {
    const rows: Array<{
      name: string;
      operation: AuthenticationOperation;
      challengeName?: string;
      error: unknown;
      expected:
        | {
            kind: "rejected";
            reason: AuthenticationRejectionReason;
            providerCode: string;
          }
        | {
            kind: "operational";
            category: OperationalCategory;
            retryable: boolean;
          };
    }> = [
      {
        name: "wrong password on admin auth",
        operation: "admin-initiate-auth",
        error: cognitoException(NotAuthorizedException, "Incorrect username or password."),
        expected: {
          kind: "rejected",
          reason: "invalid-credentials",
          providerCode: "NotAuthorizedException",
        },
      },
      {
        name: "missing user on public auth",
        operation: "initiate-auth",
        error: cognitoException(UserNotFoundException, "User does not exist."),
        expected: {
          kind: "rejected",
          reason: "invalid-credentials",
          providerCode: "UserNotFoundException",
        },
      },
      {
        name: "unconfirmed user",
        operation: "initiate-auth",
        error: cognitoException(UserNotConfirmedException, "User is not confirmed."),
        expected: {
          kind: "rejected",
          reason: "user-not-confirmed",
          providerCode: "UserNotConfirmedException",
        },
      },
      {
        name: "password reset required",
        operation: "initiate-auth",
        error: cognitoException(PasswordResetRequiredException, "Password reset required."),
        expected: {
          kind: "rejected",
          reason: "password-reset-required",
          providerCode: "PasswordResetRequiredException",
        },
      },
      {
        name: "wrong TOTP code",
        operation: "respond-to-auth-challenge",
        error: cognitoException(CodeMismatchException, "Code mismatch."),
        expected: {
          kind: "rejected",
          reason: "invalid-code",
          providerCode: "CodeMismatchException",
        },
      },
      {
        name: "invalid NEW_PASSWORD_REQUIRED session as CodeMismatch",
        operation: "respond-to-auth-challenge" as const,
        challengeName: "NEW_PASSWORD_REQUIRED",
        error: cognitoException(CodeMismatchException, "Invalid session."),
        expected: {
          kind: "rejected",
          reason: "invalid-challenge-session",
          providerCode: "CodeMismatchException",
        },
      },
      {
        name: "expired code",
        operation: "respond-to-auth-challenge",
        error: cognitoException(ExpiredCodeException, "Code expired."),
        expected: {
          kind: "rejected",
          reason: "expired-code",
          providerCode: "ExpiredCodeException",
        },
      },
      {
        name: "policy-violating new password",
        operation: "respond-to-auth-challenge",
        error: cognitoException(InvalidPasswordException, "Password does not conform."),
        expected: {
          kind: "rejected",
          reason: "password-policy-violation",
          providerCode: "InvalidPasswordException",
        },
      },
      {
        name: "too many failed attempts",
        operation: "initiate-auth",
        error: cognitoException(TooManyFailedAttemptsException, "Too many failed attempts."),
        expected: {
          kind: "rejected",
          reason: "too-many-failed-attempts",
          providerCode: "TooManyFailedAttemptsException",
        },
      },
      {
        name: "invalid refresh token",
        operation: "refresh-token",
        error: cognitoException(NotAuthorizedException, "Invalid Refresh Token."),
        expected: {
          kind: "rejected",
          reason: "invalid-refresh-token",
          providerCode: "NotAuthorizedException",
        },
      },
      {
        name: "stale challenge session",
        operation: "respond-to-auth-challenge",
        error: cognitoException(NotAuthorizedException, "Invalid session for the user."),
        expected: {
          kind: "rejected",
          reason: "invalid-challenge-session",
          providerCode: "NotAuthorizedException",
        },
      },
      {
        name: "malformed challenge session",
        operation: "respond-to-auth-challenge",
        error: cognitoException(InvalidParameterException, "Invalid session."),
        expected: {
          kind: "rejected",
          reason: "invalid-challenge-session",
          providerCode: "InvalidParameterException",
        },
      },
      {
        name: "unusable access token",
        operation: "verify-software-token",
        error: cognitoException(NotAuthorizedException, "Access Token has expired."),
        expected: {
          kind: "rejected",
          reason: "invalid-access-token",
          providerCode: "NotAuthorizedException",
        },
      },
      {
        name: "malformed refresh token",
        operation: "refresh-token",
        error: cognitoException(InvalidParameterException, "Invalid refresh token."),
        expected: {
          kind: "rejected",
          reason: "invalid-refresh-token",
          providerCode: "InvalidParameterException",
        },
      },
      {
        name: "too many API requests",
        operation: "initiate-auth",
        error: cognitoException(TooManyRequestsException, "Too many requests."),
        expected: { kind: "operational", category: "throttled", retryable: true },
      },
      {
        name: "WAF forbidden",
        operation: "initiate-auth",
        error: cognitoException(ForbiddenException, "Request forbidden by WAF."),
        expected: {
          kind: "operational",
          category: "request-blocked",
          retryable: false,
        },
      },
      {
        name: "IAM access denied",
        operation: "admin-initiate-auth",
        error: cognitoException(AccessDeniedException, "User is not authorized to perform."),
        expected: {
          kind: "operational",
          category: "iam-authorization",
          retryable: false,
        },
      },
      {
        name: "Lambda internal error",
        operation: "initiate-auth",
        error: cognitoException(UnexpectedLambdaException, "Lambda threw an error."),
        expected: { kind: "operational", category: "service", retryable: true },
      },
      {
        name: "Cognito internal error",
        operation: "initiate-auth",
        error: cognitoException(InternalErrorException, "Internal error."),
        expected: { kind: "operational", category: "service", retryable: true },
      },
      {
        name: "Lambda validation failure",
        operation: "initiate-auth",
        error: cognitoException(UserLambdaValidationException, "PreAuthentication failed."),
        expected: { kind: "operational", category: "service", retryable: false },
      },
      {
        name: "network timeout",
        operation: "initiate-auth",
        error: Object.assign(new Error("socket hang up"), { name: "TimeoutError" }),
        expected: { kind: "operational", category: "network", retryable: true },
      },
      {
        name: "invalid pool configuration",
        operation: "initiate-auth",
        error: cognitoException(
          InvalidUserPoolConfigurationException,
          "Invalid user pool configuration.",
        ),
        expected: {
          kind: "operational",
          category: "configuration",
          retryable: false,
        },
      },
      {
        name: "code delivery failure",
        operation: "initiate-auth",
        error: cognitoException(CodeDeliveryFailureException, "Failed to deliver code."),
        expected: {
          kind: "operational",
          category: "delivery",
          retryable: false,
        },
      },
    ];

    for (const row of rows) {
      const run = () =>
        mapAuthenticationOutcome({
          operation: row.operation,
          error: row.error,
          ...(row.challengeName ? { challengeName: row.challengeName } : {}),
        });

      if (row.expected.kind === "rejected") {
        expectRejected(run(), row.expected.reason, row.expected.providerCode);
      } else {
        expectOperational(run, {
          category: row.expected.category,
          retryable: row.expected.retryable,
          operation: row.operation,
        });
      }
    }
  });

  it("does not mark semantic rejections as retryable", () => {
    const outcome = mapAuthenticationOutcome({
      operation: "initiate-auth",
      error: cognitoException(NotAuthorizedException, "Incorrect username or password."),
    });

    expect(outcome.kind).toBe("rejected");
    expect(outcome).not.toHaveProperty("retryable");
  });
});

describe("retryAuthenticationOperation", () => {
  it("retries selected throttle, service, and network failures with bounded backoff and preserved request IDs", async () => {
    const sleeps: number[] = [];
    let attempts = 0;
    const requestIds = ["req-a", "req-b", "req-c"];

    await expect(
      retryAuthenticationOperation(
        async () => {
          const requestId = requestIds[attempts];
          attempts += 1;
          throw new OperationalAuthenticationFailure({
            category: "throttled",
            operation: "initiate-auth",
            retryable: true,
            diagnostic: { requestId, providerCode: "TooManyRequestsException" },
          });
        },
        {
          maxAttempts: 3,
          random: () => 0.5,
          sleep: async (ms) => {
            sleeps.push(ms);
          },
        },
      ),
    ).rejects.toMatchObject({
      category: "throttled",
      retryable: true,
      diagnostic: {
        requestIds: ["req-a", "req-b", "req-c"],
        requestId: "req-c",
      },
    });

    expect(attempts).toBe(3);
    expect(sleeps).toEqual([50, 100]);
  });

  it("does not retry semantic rejection or request-blocked failures", async () => {
    let rejectionAttempts = 0;
    const rejected = await retryAuthenticationOperation(async () => {
      rejectionAttempts += 1;
      return mapAuthenticationOutcome({
        operation: "initiate-auth",
        error: cognitoException(NotAuthorizedException, "Incorrect username or password."),
      });
    });
    expectRejected(rejected, "invalid-credentials");
    expect(rejectionAttempts).toBe(1);

    let blockedAttempts = 0;
    await expect(
      retryAuthenticationOperation(async () => {
        blockedAttempts += 1;
        return mapAuthenticationOutcome({
          operation: "initiate-auth",
          error: cognitoException(ForbiddenException, "Request forbidden by WAF."),
        });
      }),
    ).rejects.toMatchObject({
      category: "request-blocked",
      retryable: false,
    });
    expect(blockedAttempts).toBe(1);
  });
});

describe("toSafeDiagnostic", () => {
  it("never includes secrets, tokens, usernames, sessions, codes, or raw provider messages", () => {
    const secrets = [
      "super-secret-password",
      "access-token-value",
      "id-token-value",
      "refresh-token-value",
      "challenge-session-secret",
      "persona@example.com",
      "123456",
      "SECRET_HASH_VALUE",
      "Incorrect username or password.",
    ];

    const authenticated = mapAuthenticationOutcome({
      operation: "initiate-auth",
      response: {
        AuthenticationResult: {
          AccessToken: "access-token-value",
          IdToken: "id-token-value",
          RefreshToken: "refresh-token-value",
        },
      },
    });

    const challenged = mapAuthenticationOutcome({
      operation: "initiate-auth",
      continuation: {
        username: "persona@example.com",
        profileId: "user-pool-public",
      },
      response: {
        ChallengeName: "SOFTWARE_TOKEN_MFA",
        Session: "challenge-session-secret",
        ChallengeParameters: { USERNAME: "persona@example.com" },
      },
    });

    const rejected = mapAuthenticationOutcome({
      operation: "initiate-auth",
      error: cognitoException(
        NotAuthorizedException,
        "Incorrect username or password.",
        "req-safe",
      ),
    });

    const failure = expectOperational(
      () =>
        mapAuthenticationOutcome({
          operation: "initiate-auth",
          error: cognitoException(
            TooManyRequestsException,
            "Too many requests for super-secret-password",
            "req-throttle",
          ),
        }),
      { category: "throttled", retryable: true },
    );

    const diagnostics = [
      toSafeDiagnostic(authenticated, {
        operation: "initiate-auth",
        profileId: "user-pool-public",
      }),
      toSafeDiagnostic(challenged, { operation: "initiate-auth" }),
      toSafeDiagnostic(rejected, {
        operation: "initiate-auth",
        profileId: "user-pool-public",
      }),
      toSafeDiagnostic(failure, {
        operation: "initiate-auth",
        profileId: "user-pool-public",
      }),
    ];

    expect(diagnostics[0]).toEqual({
      operation: "initiate-auth",
      outcomeKind: "authenticated",
      profileId: "user-pool-public",
    });
    expect(diagnostics[1]).toEqual({
      operation: "initiate-auth",
      outcomeKind: "challenged",
      challengeType: "software-token-mfa",
      profileId: "user-pool-public",
    });
    expect(diagnostics[2]).toEqual({
      operation: "initiate-auth",
      outcomeKind: "rejected",
      rejectionReason: "invalid-credentials",
      providerCode: "NotAuthorizedException",
      requestId: "req-safe",
      profileId: "user-pool-public",
    });
    expect(diagnostics[3]).toEqual({
      operation: "initiate-auth",
      outcomeKind: "operational-failure",
      category: "throttled",
      retryable: true,
      providerCode: "TooManyRequestsException",
      requestId: "req-throttle",
      requestIds: ["req-throttle"],
      profileId: "user-pool-public",
    });

    const serialized = JSON.stringify(diagnostics);
    for (const secret of secrets) {
      expect(serialized).not.toContain(secret);
    }
  });
});

