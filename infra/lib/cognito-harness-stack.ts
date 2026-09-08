import * as cdk from "aws-cdk-lib/core";
import * as cognito from "aws-cdk-lib/aws-cognito";
import { Construct } from "constructs";
import { HarnessCodeBuild } from "./harness-codebuild";

export class CognitoHarnessStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
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

    const client = userPool.addClient("ConfidentialWebClient", {
      userPoolClientName: "cognito-test-harness-web",
      generateSecret: true,
      authFlows: {
        adminUserPassword: true,
      },
      disableOAuth: true,
      preventUserExistenceErrors: true,
    });

    new HarnessCodeBuild(this, "Ci", {
      userPool,
    });

    new cdk.CfnOutput(this, "UserPoolId", {
      value: userPool.userPoolId,
      description: "Map to COGNITO_USER_POOL_ID",
    });

    new cdk.CfnOutput(this, "UserPoolClientId", {
      value: client.userPoolClientId,
      description: "Map to COGNITO_CLIENT_ID",
    });

    new cdk.CfnOutput(this, "UserPoolClientSecret", {
      value: client.userPoolClientSecret.unsafeUnwrap(),
      description:
        "Map to COGNITO_CLIENT_SECRET (learning repo only — treat as secret)",
    });

    new cdk.CfnOutput(this, "Region", {
      value: this.region,
      description: "Map to AWS_REGION",
    });
  }
}
