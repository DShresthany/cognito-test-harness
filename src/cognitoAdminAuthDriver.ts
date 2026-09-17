import {
  AdminInitiateAuthCommand,
  AuthFlowType,
  type CognitoIdentityProviderClient,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  mapAuthenticationOutcome,
  OperationalAuthenticationFailure,
  retryAuthenticationOperation,
  type AuthenticationOutcome,
  type RetryAuthenticationDependencies,
} from "./authenticationOutcome.js";
import { getSecretHash } from "./secretHash.js";

export type ConfidentialAdminAuthProfile = {
  id: "admin-confidential";
  userPoolId: string;
  clientId: string;
  clientSecret: string;
};

export type CognitoCommandSender = Pick<CognitoIdentityProviderClient, "send">;

export class CognitoAdminAuthDriver {
  constructor(
    private readonly sender: CognitoCommandSender,
    private readonly profile: ConfidentialAdminAuthProfile,
    private readonly retry: RetryAuthenticationDependencies = {},
  ) {}

  async authenticatePassword(
    username: string,
    password: string,
  ): Promise<AuthenticationOutcome> {
    return retryAuthenticationOperation(async () => {
      try {
        const response = await this.sender.send(
          new AdminInitiateAuthCommand({
            UserPoolId: this.profile.userPoolId,
            ClientId: this.profile.clientId,
            AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
            AuthParameters: {
              USERNAME: username,
              PASSWORD: password,
              SECRET_HASH: getSecretHash(
                username,
                this.profile.clientId,
                this.profile.clientSecret,
              ),
            },
          }),
        );
        return mapAuthenticationOutcome({
          operation: "admin-initiate-auth",
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
          operation: "admin-initiate-auth",
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
