import {
  AdminInitiateAuthCommand,
  AuthFlowType,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  mapAuthenticationOutcome,
  type AuthenticationOutcome,
} from "./authenticationOutcome.js";
import {
  CognitoAdminAuthDriver,
  type ConfidentialAdminAuthProfile,
  type CognitoCommandSender,
} from "./cognitoAdminAuthDriver.js";

type Credentials = {
  username: string;
  password: string;
};

type RefreshCredentials = {
  /** Access/ID token `sub` — required for confidential SECRET_HASH on refresh. */
  subject: string;
  refreshToken: string;
};

export function attemptLoginWithInvalidSecretHash(
  sender: CognitoCommandSender,
  profile: ConfidentialAdminAuthProfile,
  credentials: Credentials,
) {
  const driver = new CognitoAdminAuthDriver(sender, {
    ...profile,
    clientSecret: `${profile.clientSecret}-wrong`,
  });
  return driver.authenticatePassword(credentials.username, credentials.password);
}

/** Missing SECRET_HASH on a confidential client — still domain invalid-credentials. */
export async function attemptLoginWithMissingSecretHash(
  sender: CognitoCommandSender,
  profile: ConfidentialAdminAuthProfile,
  credentials: Credentials,
): Promise<AuthenticationOutcome> {
  try {
    const response = await sender.send(
      new AdminInitiateAuthCommand({
        UserPoolId: profile.userPoolId,
        ClientId: profile.clientId,
        AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
        AuthParameters: {
          USERNAME: credentials.username,
          PASSWORD: credentials.password,
        },
      }),
    );
    return mapAuthenticationOutcome({
      operation: "admin-initiate-auth",
      response,
      continuation: {
        username: credentials.username,
        profileId: profile.id,
      },
    });
  } catch (error) {
    return mapAuthenticationOutcome({
      operation: "admin-initiate-auth",
      error,
      continuation: {
        username: credentials.username,
        profileId: profile.id,
      },
    });
  }
}

export function attemptRefreshWithInvalidSecretHash(
  sender: CognitoCommandSender,
  profile: ConfidentialAdminAuthProfile,
  credentials: RefreshCredentials,
) {
  const driver = new CognitoAdminAuthDriver(sender, {
    ...profile,
    clientSecret: `${profile.clientSecret}-wrong`,
  });
  return driver.refresh(credentials.subject, credentials.refreshToken);
}

/** Missing SECRET_HASH on confidential refresh — domain invalid-refresh-token. */
export async function attemptRefreshWithMissingSecretHash(
  sender: CognitoCommandSender,
  profile: ConfidentialAdminAuthProfile,
  credentials: RefreshCredentials,
): Promise<AuthenticationOutcome> {
  try {
    const response = await sender.send(
      new AdminInitiateAuthCommand({
        UserPoolId: profile.userPoolId,
        ClientId: profile.clientId,
        AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
        AuthParameters: {
          REFRESH_TOKEN: credentials.refreshToken,
        },
      }),
    );
    return mapAuthenticationOutcome({
      operation: "refresh-token",
      response,
      continuation: {
        profileId: profile.id,
      },
    });
  } catch (error) {
    return mapAuthenticationOutcome({
      operation: "refresh-token",
      error,
      continuation: {
        profileId: profile.id,
      },
    });
  }
}
