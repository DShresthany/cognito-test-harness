import { resolve } from "node:path";
import {
  DescribeUserPoolClientCommand,
  DescribeUserPoolCommand,
  GetUserPoolMfaConfigCommand,
  type CognitoIdentityProviderClient,
} from "@aws-sdk/client-cognito-identity-provider";
import type { CognitoCapabilityDescriber } from "./cognitoTestRuntime.js";

export function resolveCognitoConfigPath(): string {
  return (
    process.env.COGNITO_CONFIG_PATH ??
    resolve(process.cwd(), ".cognito/config.json")
  );
}

export function createAwsCapabilityDescriber(
  client: Pick<CognitoIdentityProviderClient, "send">,
): CognitoCapabilityDescriber {
  return {
    async describeUserPool({ userPoolId }) {
      return client.send(
        new DescribeUserPoolCommand({ UserPoolId: userPoolId }),
      );
    },
    async getUserPoolMfaConfig({ userPoolId }) {
      return client.send(
        new GetUserPoolMfaConfigCommand({ UserPoolId: userPoolId }),
      );
    },
    async describeUserPoolClient({ userPoolId, clientId }) {
      return client.send(
        new DescribeUserPoolClientCommand({
          UserPoolId: userPoolId,
          ClientId: clientId,
        }),
      );
    },
  };
}
