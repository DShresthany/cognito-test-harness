import * as cdk from "aws-cdk-lib/core";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";
import { HarnessCodeBuild } from "./harness-codebuild";

/** JSON secret: { userPoolId, clientId, clientSecret, region }. */
export const COGNITO_CONFIG_SECRET_NAME = "cognito-test-harness/cognito";

export interface CognitoHarnessStackProps extends cdk.StackProps {
  /** Inbox for CodeBuild failure emails (SNS subscription). */
  alertEmail: string;
}

export class CognitoHarnessStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CognitoHarnessStackProps) {
    super(scope, id, props);

    const userPool = new cognito.UserPool(this, "HarnessUserPool", {
      userPoolName: "cognito-test-harness",
      selfSignUpEnabled: false,
      signInAliases: {
        email: true,
      },
      autoVerify: {
        email: true,
      },
      standardAttributes: {
        email: {
          required: true,
          mutable: true,
        },
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Construct id bump replaces the app client (new client secret) when rotating after exposure.
    const client = userPool.addClient("HarnessWebClient", {
      userPoolClientName: "cognito-test-harness-web",
      generateSecret: true,
      authFlows: {
        adminUserPassword: true,
      },
      disableOAuth: true,
      preventUserExistenceErrors: true,
    });

    // Source of truth for harness + CI (no plaintext client secret in stack outputs).
    const cognitoConfig = new secretsmanager.Secret(this, "CognitoConfig", {
      secretName: COGNITO_CONFIG_SECRET_NAME,
      description:
        "Cognito harness config (userPoolId, clientId, clientSecret, region)",
      secretObjectValue: {
        userPoolId: cdk.SecretValue.unsafePlainText(userPool.userPoolId),
        clientId: cdk.SecretValue.unsafePlainText(client.userPoolClientId),
        clientSecret: client.userPoolClientSecret,
        region: cdk.SecretValue.unsafePlainText(this.region),
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    new HarnessCodeBuild(this, "Ci", {
      userPool,
      cognitoConfigSecret: cognitoConfig,
      alertEmail: props.alertEmail,
    });

    new cdk.CfnOutput(this, "UserPoolId", {
      value: userPool.userPoolId,
      description: "Map to COGNITO_USER_POOL_ID (also in Secrets Manager)",
    });

    new cdk.CfnOutput(this, "UserPoolClientId", {
      value: client.userPoolClientId,
      description: "Map to COGNITO_CLIENT_ID (also in Secrets Manager)",
    });

    new cdk.CfnOutput(this, "Region", {
      value: this.region,
      description: "Map to AWS_REGION (also in Secrets Manager)",
    });

    new cdk.CfnOutput(this, "CognitoConfigSecretName", {
      value: cognitoConfig.secretName,
      description:
        "Secrets Manager secret with Cognito config (includes client secret)",
    });
  }
}
