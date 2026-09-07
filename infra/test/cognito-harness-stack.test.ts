import * as cdk from "aws-cdk-lib/core";
import { Template } from "aws-cdk-lib/assertions";
import { CognitoHarnessStack } from "../lib/cognito-harness-stack";

test("User Pool and confidential client with admin password auth", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStack", {
    env: { account: "111111111111", region: "us-east-1" },
  });
  const template = Template.fromStack(stack);

  template.hasResourceProperties("AWS::Cognito::UserPool", {
    UserPoolName: "cognito-test-harness",
    AdminCreateUserConfig: {
      AllowAdminCreateUserOnly: true,
    },
    UsernameAttributes: ["email"],
    Policies: {
      PasswordPolicy: {
        MinimumLength: 8,
        RequireLowercase: true,
        RequireUppercase: true,
        RequireNumbers: true,
        RequireSymbols: true,
      },
    },
  });

  template.hasResourceProperties("AWS::Cognito::UserPoolClient", {
    ClientName: "cognito-test-harness-web",
    GenerateSecret: true,
    ExplicitAuthFlows: [
      "ALLOW_ADMIN_USER_PASSWORD_AUTH",
      "ALLOW_REFRESH_TOKEN_AUTH",
    ],
  });
});
