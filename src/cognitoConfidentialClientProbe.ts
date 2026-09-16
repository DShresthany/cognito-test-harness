import {
  AdminInitiateAuthCommand,
  AuthFlowType,
} from "@aws-sdk/client-cognito-identity-provider";
import { createCognitoClient, required } from "./cognitoAuth.js";
import { getSecretHash } from "./secretHash.js";

type Credentials = {
  username: string;
  password: string;
};

export async function attemptLoginWithInvalidSecretHash(
  credentials: Credentials,
) {
  const client = createCognitoClient();
  const userPoolId = required("COGNITO_USER_POOL_ID");
  const clientId = required("COGNITO_CLIENT_ID");
  const clientSecret = required("COGNITO_CLIENT_SECRET");

  return client.send(
    new AdminInitiateAuthCommand({
      UserPoolId: userPoolId,
      ClientId: clientId,
      AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
      AuthParameters: {
        USERNAME: credentials.username,
        PASSWORD: credentials.password,
        SECRET_HASH: getSecretHash(
          credentials.username,
          clientId,
          `${clientSecret}-wrong`,
        ),
      },
    }),
  );
}
