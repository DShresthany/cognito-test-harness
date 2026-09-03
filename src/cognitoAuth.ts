import {
    CognitoIdentityProviderClient,
    AdminInitiateAuthCommand,
    AuthFlowType,
  } from "@aws-sdk/client-cognito-identity-provider";
  import { getSecretHash } from "./secretHash.js";
  
export function required(name: string): string {
    const value = process.env[name];
    if (!value) throw new Error(`Missing required env: ${name}`);
    return value;
  }
  
  export function createCognitoClient() {
    return new CognitoIdentityProviderClient({
      region: required("AWS_REGION"),
    });
  }
  
  export async function adminLogin(username: string, password: string) {
    const clientId = required("COGNITO_CLIENT_ID");
    const clientSecret = required("COGNITO_CLIENT_SECRET");
    const userPoolId = required("COGNITO_USER_POOL_ID");
  
    const client = createCognitoClient();
    return client.send(
      new AdminInitiateAuthCommand({
        UserPoolId: userPoolId,
        ClientId: clientId,
        AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
        AuthParameters: {
          USERNAME: username,
          PASSWORD: password,
          SECRET_HASH: getSecretHash(username, clientId, clientSecret),
        },
      })
    );
  }