import {
  AssociateSoftwareTokenCommand,
  AuthFlowType,
  ChallengeNameType,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
  SetUserMFAPreferenceCommand,
  VerifySoftwareTokenCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  mapAuthenticationOutcome,
  OperationalAuthenticationFailure,
  retryAuthenticationOperation,
  type AuthenticationOutcome,
  type AuthenticationRejection,
  type RetryAuthenticationDependencies,
} from "./authenticationOutcome.js";
import type { CognitoCommandSender } from "./cognitoAdminAuthDriver.js";

export type PublicUserPoolAuthProfile = {
  id: "user-pool-public";
  userPoolId: string;
  clientId: string;
};

export type NewPasswordChallengeInput = {
  session: string;
  username: string;
  newPassword: string;
};

export type SoftwareTokenMfaChallengeInput = {
  session: string;
  username: string;
  code: string;
};

export type VerifySoftwareTokenInput = {
  accessToken: string;
  code: string;
};

export type VerifySoftwareTokenResult =
  | { kind: "verified" }
  | { kind: "rejected"; rejection: AuthenticationRejection };

export class CognitoUserPoolAuthDriver {
  constructor(
    private readonly sender: CognitoCommandSender,
    private readonly profile: PublicUserPoolAuthProfile,
    private readonly retry: RetryAuthenticationDependencies = {},
  ) {}

  async authenticatePassword(
    username: string,
    password: string,
  ): Promise<AuthenticationOutcome> {
    return retryAuthenticationOperation(async () => {
      try {
        const response = await this.sender.send(
          new InitiateAuthCommand({
            ClientId: this.profile.clientId,
            AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
            AuthParameters: {
              USERNAME: username,
              PASSWORD: password,
            },
          }),
        );
        return mapAuthenticationOutcome({
          operation: "initiate-auth",
          response,
          continuation: {
            username,
            profileId: this.profile.id,
          },
        });
      } catch (error) {
        if (error instanceof OperationalAuthenticationFailure) {
          throw error;
        }
        return mapAuthenticationOutcome({
          operation: "initiate-auth",
          error,
          continuation: {
            username,
            profileId: this.profile.id,
          },
        });
      }
    }, this.retry);
  }

  async refresh(refreshToken: string): Promise<AuthenticationOutcome> {
    return retryAuthenticationOperation(async () => {
      try {
        const response = await this.sender.send(
          new InitiateAuthCommand({
            ClientId: this.profile.clientId,
            AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
            AuthParameters: {
              REFRESH_TOKEN: refreshToken,
            },
          }),
        );
        return mapAuthenticationOutcome({
          operation: "refresh-token",
          response,
          continuation: {
            profileId: this.profile.id,
          },
        });
      } catch (error) {
        if (error instanceof OperationalAuthenticationFailure) {
          throw error;
        }
        return mapAuthenticationOutcome({
          operation: "refresh-token",
          error,
          continuation: {
            profileId: this.profile.id,
          },
        });
      }
    }, this.retry);
  }

  async respondToNewPasswordChallenge(
    input: NewPasswordChallengeInput,
  ): Promise<AuthenticationOutcome> {
    return retryAuthenticationOperation(async () => {
      const challengeResponses: Record<string, string> = {
        USERNAME: input.username,
        NEW_PASSWORD: input.newPassword,
      };

      try {
        const response = await this.sender.send(
          new RespondToAuthChallengeCommand({
            ClientId: this.profile.clientId,
            ChallengeName: ChallengeNameType.NEW_PASSWORD_REQUIRED,
            Session: input.session,
            ChallengeResponses: challengeResponses,
          }),
        );
        return mapAuthenticationOutcome({
          operation: "respond-to-auth-challenge",
          response,
          challengeName: ChallengeNameType.NEW_PASSWORD_REQUIRED,
          continuation: {
            username: input.username,
            profileId: this.profile.id,
          },
        });
      } catch (error) {
        if (error instanceof OperationalAuthenticationFailure) {
          throw error;
        }
        return mapAuthenticationOutcome({
          operation: "respond-to-auth-challenge",
          error,
          challengeName: ChallengeNameType.NEW_PASSWORD_REQUIRED,
          continuation: {
            username: input.username,
            profileId: this.profile.id,
          },
        });
      }
    }, this.retry);
  }

  async associateSoftwareToken(accessToken: string): Promise<string> {
    return retryAuthenticationOperation(async () => {
      try {
        const response = await this.sender.send(
          new AssociateSoftwareTokenCommand({ AccessToken: accessToken }),
        );
        if (!response.SecretCode) {
          throw new OperationalAuthenticationFailure({
            category: "unsupported-response",
            operation: "associate-software-token",
            retryable: false,
          });
        }
        return response.SecretCode;
      } catch (error) {
        if (error instanceof OperationalAuthenticationFailure) {
          throw error;
        }
        const outcome = mapAuthenticationOutcome({
          operation: "associate-software-token",
          error,
        });
        if (outcome.kind === "rejected") {
          throw new OperationalAuthenticationFailure({
            category: "configuration",
            operation: "associate-software-token",
            retryable: false,
            diagnostic: outcome.rejection.diagnostic,
          });
        }
        throw new OperationalAuthenticationFailure({
          category: "unsupported-response",
          operation: "associate-software-token",
          retryable: false,
        });
      }
    }, this.retry);
  }

  async verifySoftwareToken(
    input: VerifySoftwareTokenInput,
  ): Promise<VerifySoftwareTokenResult> {
    return retryAuthenticationOperation(async () => {
      try {
        const response = await this.sender.send(
          new VerifySoftwareTokenCommand({
            AccessToken: input.accessToken,
            UserCode: input.code,
            FriendlyDeviceName: "cognito-test-harness",
          }),
        );
        if (response.Status === "SUCCESS") {
          return { kind: "verified" };
        }
        const outcome = mapAuthenticationOutcome({
          operation: "verify-software-token",
          response,
        });
        if (outcome.kind === "rejected") {
          return outcome;
        }
        throw new OperationalAuthenticationFailure({
          category: "unsupported-response",
          operation: "verify-software-token",
          retryable: false,
        });
      } catch (error) {
        if (error instanceof OperationalAuthenticationFailure) {
          throw error;
        }
        const outcome = mapAuthenticationOutcome({
          operation: "verify-software-token",
          error,
        });
        if (outcome.kind === "rejected") {
          return outcome;
        }
        throw new OperationalAuthenticationFailure({
          category: "unsupported-response",
          operation: "verify-software-token",
          retryable: false,
        });
      }
    }, this.retry);
  }

  async setSoftwareTokenMfaPreferred(accessToken: string): Promise<void> {
    return retryAuthenticationOperation(async () => {
      try {
        await this.sender.send(
          new SetUserMFAPreferenceCommand({
            AccessToken: accessToken,
            SoftwareTokenMfaSettings: {
              Enabled: true,
              PreferredMfa: true,
            },
          }),
        );
      } catch (error) {
        if (error instanceof OperationalAuthenticationFailure) {
          throw error;
        }
        const outcome = mapAuthenticationOutcome({
          operation: "set-user-mfa-preference",
          error,
        });
        if (outcome.kind === "rejected") {
          throw new OperationalAuthenticationFailure({
            category: "configuration",
            operation: "set-user-mfa-preference",
            retryable: false,
            diagnostic: outcome.rejection.diagnostic,
          });
        }
        throw new OperationalAuthenticationFailure({
          category: "unsupported-response",
          operation: "set-user-mfa-preference",
          retryable: false,
        });
      }
    }, this.retry);
  }

  async respondToSoftwareTokenMfa(
    input: SoftwareTokenMfaChallengeInput,
  ): Promise<AuthenticationOutcome> {
    return retryAuthenticationOperation(async () => {
      try {
        const response = await this.sender.send(
          new RespondToAuthChallengeCommand({
            ClientId: this.profile.clientId,
            ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
            Session: input.session,
            ChallengeResponses: {
              USERNAME: input.username,
              SOFTWARE_TOKEN_MFA_CODE: input.code,
            },
          }),
        );
        return mapAuthenticationOutcome({
          operation: "respond-to-auth-challenge",
          response,
          challengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
          continuation: {
            username: input.username,
            profileId: this.profile.id,
          },
        });
      } catch (error) {
        if (error instanceof OperationalAuthenticationFailure) {
          throw error;
        }
        return mapAuthenticationOutcome({
          operation: "respond-to-auth-challenge",
          error,
          challengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
          continuation: {
            username: input.username,
            profileId: this.profile.id,
          },
        });
      }
    }, this.retry);
  }
}
