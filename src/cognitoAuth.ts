import { CognitoIdentityProviderClient } from "@aws-sdk/client-cognito-identity-provider";

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
