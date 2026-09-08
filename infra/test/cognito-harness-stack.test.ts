import * as cdk from "aws-cdk-lib/core";
import { Match, Template } from "aws-cdk-lib/assertions";
import { CognitoHarnessStack } from "../lib/cognito-harness-stack";

test("User Pool, confidential client, CodeBuild, and failure email alerts", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStack", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
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

  template.hasResourceProperties("AWS::CodeBuild::Project", {
    Name: "cognito-test-harness-ci",
  });

  template.resourceCountIs("AWS::CodeBuild::Project", 1);

  template.hasResourceProperties("AWS::SNS::Topic", {
    TopicName: "cognito-test-harness-ci-alerts",
  });

  template.hasResourceProperties("AWS::SNS::Subscription", {
    Protocol: "email",
    Endpoint: "ci-alerts@example.com",
  });

  template.hasResourceProperties("AWS::Events::Rule", {
    EventPattern: {
      source: ["aws.codebuild"],
      "detail-type": ["CodeBuild Build State Change"],
      detail: {
        "build-status": ["FAILED", "FAULT", "STOPPED", "TIMED_OUT"],
        "project-name": Match.anyValue(),
      },
    },
  });
});
