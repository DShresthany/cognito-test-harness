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

  template.hasResourceProperties("AWS::SecretsManager::Secret", {
    Name: "cognito-test-harness/cognito",
  });

  // Client secret must not appear as a plaintext stack output.
  expect(template.findOutputs("*").UserPoolClientSecret).toBeUndefined();
  expect(template.findOutputs("*").CognitoConfigSecretName).toBeDefined();

  // Least-privilege: no PowerUser; CDK deploy via AssumeRole; Cognito + CFN outputs scoped.
  const roles = template.findResources("AWS::IAM::Role");
  for (const role of Object.values(roles)) {
    const arns = role.Properties?.ManagedPolicyArns as string[] | undefined;
    expect(arns?.join(" ") ?? "").not.toMatch(/PowerUserAccess/);
  }

  const statements = Object.values(template.findResources("AWS::IAM::Policy"))
    .flatMap(
      (p) =>
        (p.Properties?.PolicyDocument?.Statement as Array<{ Sid?: string }>) ??
        [],
    )
    .map((s) => s.Sid)
    .filter(Boolean);

  expect(statements).toEqual(
    expect.arrayContaining([
      "CdkBootstrapAssumeRoles",
      "CognitoHarnessAdmin",
      "ReadHarnessStackOutputs",
      "CdkBootstrapVersion",
      "StsCallerIdentity",
    ]),
  );

  // CognitoHarnessAdmin allowlist must match CognitoLoginManager (no unused Admin APIs).
  const cognitoAdmin = Object.values(template.findResources("AWS::IAM::Policy"))
    .flatMap(
      (p) =>
        (p.Properties?.PolicyDocument?.Statement as Array<{
          Sid?: string;
          Action?: string | string[];
        }>) ?? [],
    )
    .find((s) => s.Sid === "CognitoHarnessAdmin");
  expect(cognitoAdmin).toBeDefined();
  expect([cognitoAdmin!.Action].flat().sort()).toEqual(
    [
      "cognito-idp:AdminCreateUser",
      "cognito-idp:AdminDeleteUser",
      "cognito-idp:AdminInitiateAuth",
      "cognito-idp:AdminSetUserPassword",
    ].sort(),
  );

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
    Targets: Match.arrayWith([
      Match.objectLike({
        InputTransformer: {
          InputPathsMap: Match.anyValue(),
          InputTemplate: Match.anyValue(),
        },
      }),
    ]),
  });

  const rule = Object.values(template.findResources("AWS::Events::Rule"))[0]!;
  const paths = Object.values(
    rule.Properties.Targets[0].InputTransformer.InputPathsMap as Record<
      string,
      string
    >,
  );
  expect(paths).toEqual(
    expect.arrayContaining([
      "$.detail.build-id",
      "$.detail.build-status",
    ]),
  );
  const templateParts = JSON.stringify(
    rule.Properties.Targets[0].InputTransformer.InputTemplate,
  );
  expect(templateParts).toMatch(/Status:/);
  expect(templateParts).toMatch(/Build ID:/);
  expect(templateParts).toMatch(/codesuite\/codebuild/);
});
