import {
  AuthFlowType,
  InitiateAuthCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  mapAuthenticationOutcome,
  OperationalAuthenticationFailure,
  retryAuthenticationOperation,
  type AuthenticationOutcome,
  type RetryAuthenticationDependencies,
} from "./authenticationOutcome.js";
import type { CognitoCommandSender } from "./cognitoAdminAuthDriver.js";

export type PublicUserPoolAuthProfile = {
  id: "user-pool-public";
  userPoolId: string;
  clientId: string;
};

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
}
