import * as cdk from "aws-cdk-lib/core";
import { Match, Template } from "aws-cdk-lib/assertions";
import {
  ADMIN_CONFIDENTIAL_PROFILE_ID,
  ALERT_EMAIL_PARAMETER_NAME,
  CognitoHarnessStack,
  USER_POOL_PUBLIC_PROFILE_ID,
} from "../lib/cognito-harness-stack";

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
  expect(template.findOutputs("*").AlertEmailParameterName).toBeDefined();

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
      "CognitoDescribeProfiles",
      "CdkBootstrapVersion",
      "StsCallerIdentity",
    ]),
  );
  expect(statements).not.toContain("ReadHarnessStackOutputs");

  // CognitoHarnessAdmin allowlist is the fixture, admin-driver, and global sign-out APIs.
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
      "cognito-idp:AdminUserGlobalSignOut",
    ].sort(),
  );
  const describeProfiles = Object.values(
    template.findResources("AWS::IAM::Policy"),
  )
    .flatMap(
      (p) =>
        (p.Properties?.PolicyDocument?.Statement as Array<{
          Sid?: string;
          Resource?: unknown;
        }>) ?? [],
    )
    .find((s) => s.Sid === "CognitoDescribeProfiles");
  expect(cognitoAdmin).toMatchObject({
    Resource: describeProfiles?.Resource,
  });

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
  expect(templateParts).toMatch(/Project history:/);
  expect(templateParts).toMatch(/codesuite\/codebuild/);
});

test("adds a public User Pool client for user-pool-public", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackPublicClient", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);

  template.resourceCountIs("AWS::Cognito::UserPoolClient", 5);
  template.hasResourceProperties("AWS::Cognito::UserPoolClient", {
    ClientName: "cognito-test-harness-public",
    GenerateSecret: false,
    AllowedOAuthFlowsUserPoolClient: false,
    ExplicitAuthFlows: [
      "ALLOW_USER_PASSWORD_AUTH",
      "ALLOW_REFRESH_TOKEN_AUTH",
    ],
    PreventUserExistenceErrors: "ENABLED",
    EnableTokenRevocation: true,
  });
});

test("keeps the confidential admin client with revocation and non-rotating refresh", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackConfidentialClient", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);

  template.hasResourceProperties("AWS::Cognito::UserPoolClient", {
    ClientName: "cognito-test-harness-web",
    GenerateSecret: true,
    AllowedOAuthFlowsUserPoolClient: false,
    ExplicitAuthFlows: [
      "ALLOW_ADMIN_USER_PASSWORD_AUTH",
      "ALLOW_REFRESH_TOKEN_AUTH",
    ],
    EnableTokenRevocation: true,
  });

  const clients = Object.values(
    template.findResources("AWS::Cognito::UserPoolClient"),
  );
  const firstReleaseClients = clients.filter((client) =>
    ["cognito-test-harness-web", "cognito-test-harness-public"].includes(
      client.Properties.ClientName as string,
    ),
  );
  expect(firstReleaseClients).toHaveLength(2);
  for (const client of firstReleaseClients) {
    expect(client.Properties.RefreshTokenRotation).toBeUndefined();
    expect(client.Properties.ExplicitAuthFlows).toContain(
      "ALLOW_REFRESH_TOKEN_AUTH",
    );
  }
  for (const client of clients) {
    expect(client.Properties.ExplicitAuthFlows).not.toContain("ALLOW_USER_AUTH");
  }
});

test("configures OPTIONAL software-token MFA on the pool", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackMfa", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);

  template.hasResourceProperties("AWS::Cognito::UserPool", {
    UserPoolName: "cognito-test-harness",
    UserPoolTier: "ESSENTIALS",
    MfaConfiguration: "OPTIONAL",
    EnabledMfas: ["SOFTWARE_TOKEN_MFA"],
  });
});

test("sets token and challenge durations on every app client", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackDurations", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);
  const clients = Object.values(
    template.findResources("AWS::Cognito::UserPoolClient"),
  );
  expect(clients).toHaveLength(5);
  // CDK emits minutes: 60 = 1 hour, 43200 = 30 days, 3 = challenge session.
  for (const client of clients) {
    expect(client.Properties).toMatchObject({
      AccessTokenValidity: 60,
      IdTokenValidity: 60,
      RefreshTokenValidity: 43200,
      AuthSessionValidity: 3,
      TokenValidityUnits: {
        AccessToken: "minutes",
        IdToken: "minutes",
        RefreshToken: "minutes",
      },
    });
  }
});

test("writes schema version 2 profiles without legacy top-level client fields", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackManifest", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);
  const secret = Object.values(
    template.findResources("AWS::SecretsManager::Secret"),
  ).find((resource) => resource.Properties.Name === "cognito-test-harness/cognito");
  expect(secret).toBeDefined();
  const secretString = secret!.Properties.SecretString as {
    "Fn::Sub": [string, Record<string, unknown>];
  };
  const document = secretString["Fn::Sub"][0];
  expect(document).toContain('"schemaVersion":2');
  expect(document).toContain(`"${ADMIN_CONFIDENTIAL_PROFILE_ID}"`);
  expect(document).toContain(`"${USER_POOL_PUBLIC_PROFILE_ID}"`);
  expect(document).toContain('"kind":"confidential"');
  expect(document).toContain('"kind":"public"');
  expect(document).toContain('"userPoolId"');
  expect(document).toContain('"region"');
  expect(document).not.toMatch(
    /"userPoolId":"\$\{UserPoolId\}","clientId":"\$\{ClientId\}"/,
  );
  expect(document).toContain(
    `"${ADMIN_CONFIDENTIAL_PROFILE_ID}":{"kind":"confidential","clientId":"\${ClientId}","clientSecret":"\${ClientSecret}"}`,
  );
  const publicRecord = document.match(
    /"user-pool-public":\{"kind":"public","clientId":"\$\{PublicClientId\}"\}/,
  )?.[0];
  expect(publicRecord).toBeDefined();
  expect(publicRecord).not.toContain("clientSecret");
  expect(secretString["Fn::Sub"][1]).toEqual(
    expect.objectContaining({
      UserPoolId: expect.anything(),
      ClientId: expect.anything(),
      ClientSecret: expect.anything(),
      PublicClientId: expect.anything(),
    }),
  );
});

test("publishes the three rotation profiles in the schema version 2 manifest", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackRotationManifest", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);
  const secret = Object.values(
    template.findResources("AWS::SecretsManager::Secret"),
  ).find((resource) => resource.Properties.Name === "cognito-test-harness/cognito");
  expect(secret).toBeDefined();
  const secretString = secret!.Properties.SecretString as {
    "Fn::Sub": [string, Record<string, unknown>];
  };
  const document = secretString["Fn::Sub"][0];
  const variables = secretString["Fn::Sub"][1];

  expect(document).toContain('"schemaVersion":2');
  expect(document).toContain(
    '"refresh-rotating-public":{"kind":"public","clientId":"${RefreshRotatingPublicClientId}"}',
  );
  expect(document).toContain(
    '"refresh-rotating-confidential":{"kind":"confidential","clientId":"${RefreshRotatingConfidentialClientId}","clientSecret":"${RefreshRotatingConfidentialClientSecret}"}',
  );
  expect(document).toContain(
    '"refresh-rotating-grace":{"kind":"public","clientId":"${RefreshRotatingGraceClientId}"}',
  );
  expect(
    document.match(/"refresh-rotating-public":\{[^}]*\}/)?.[0],
  ).not.toContain("clientSecret");
  expect(
    document.match(/"refresh-rotating-grace":\{[^}]*\}/)?.[0],
  ).not.toContain("clientSecret");
  expect(variables).toEqual(
    expect.objectContaining({
      RefreshRotatingPublicClientId: expect.anything(),
      RefreshRotatingConfidentialClientId: expect.anything(),
      RefreshRotatingConfidentialClientSecret: expect.anything(),
      RefreshRotatingGraceClientId: expect.anything(),
    }),
  );
});

test("grants describe IAM without AdminRespondToAuthChallenge", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackDescribeIam", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);
  const statements = Object.values(template.findResources("AWS::IAM::Policy"))
    .flatMap(
      (p) =>
        (p.Properties?.PolicyDocument?.Statement as Array<{
          Sid?: string;
          Action?: string | string[];
        }>) ?? [],
    );

  const describe = statements.find((s) => s.Sid === "CognitoDescribeProfiles");
  expect(describe).toBeDefined();
  expect([describe!.Action].flat().sort()).toEqual(
    [
      "cognito-idp:DescribeUserPool",
      "cognito-idp:DescribeUserPoolClient",
      "cognito-idp:GetUserPoolMfaConfig",
    ].sort(),
  );

  const allActions = statements.flatMap((s) => [s.Action].flat());
  expect(allActions).not.toContain("cognito-idp:AdminRespondToAuthChallenge");
});

test("adds refresh-rotating-public with zero-grace rotation and password auth only", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackRotatingPublic", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);

  template.hasResourceProperties("AWS::Cognito::UserPoolClient", {
    ClientName: "refresh-rotating-public",
    GenerateSecret: false,
    AllowedOAuthFlowsUserPoolClient: false,
    ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
    PreventUserExistenceErrors: "ENABLED",
    EnableTokenRevocation: true,
    AccessTokenValidity: 60,
    IdTokenValidity: 60,
    RefreshTokenValidity: 43200,
    AuthSessionValidity: 3,
    TokenValidityUnits: {
      AccessToken: "minutes",
      IdToken: "minutes",
      RefreshToken: "minutes",
    },
    RefreshTokenRotation: {
      Feature: "ENABLED",
      RetryGracePeriodSeconds: 0,
    },
  });
});

test("adds refresh-rotating-confidential with a secret and admin password auth only", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackRotatingConfidential", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);

  template.hasResourceProperties("AWS::Cognito::UserPoolClient", {
    ClientName: "refresh-rotating-confidential",
    GenerateSecret: true,
    AllowedOAuthFlowsUserPoolClient: false,
    ExplicitAuthFlows: ["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
    PreventUserExistenceErrors: "ENABLED",
    EnableTokenRevocation: true,
    AccessTokenValidity: 60,
    IdTokenValidity: 60,
    RefreshTokenValidity: 43200,
    AuthSessionValidity: 3,
    TokenValidityUnits: {
      AccessToken: "minutes",
      IdToken: "minutes",
      RefreshToken: "minutes",
    },
    RefreshTokenRotation: {
      Feature: "ENABLED",
      RetryGracePeriodSeconds: 0,
    },
  });
});

test("adds refresh-rotating-grace with a 10-second grace and password auth only", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackRotatingGrace", {
    env: { account: "111111111111", region: "us-east-1" },
    alertEmail: "ci-alerts@example.com",
  });
  const template = Template.fromStack(stack);

  template.hasResourceProperties("AWS::Cognito::UserPoolClient", {
    ClientName: "refresh-rotating-grace",
    GenerateSecret: false,
    AllowedOAuthFlowsUserPoolClient: false,
    ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
    PreventUserExistenceErrors: "ENABLED",
    EnableTokenRevocation: true,
    AccessTokenValidity: 60,
    IdTokenValidity: 60,
    RefreshTokenValidity: 43200,
    AuthSessionValidity: 3,
    TokenValidityUnits: {
      AccessToken: "minutes",
      IdToken: "minutes",
      RefreshToken: "minutes",
    },
    RefreshTokenRotation: {
      Feature: "ENABLED",
      RetryGracePeriodSeconds: 10,
    },
  });
});

test("default alert email uses SSM parameter reference", () => {
  const app = new cdk.App();
  const stack = new CognitoHarnessStack(app, "TestStackSsm", {
    env: { account: "111111111111", region: "us-east-1" },
  });
  const template = Template.fromStack(stack);

  template.hasResourceProperties("AWS::SNS::Subscription", {
    Protocol: "email",
    Endpoint: Match.objectLike({
      Ref: Match.stringLikeRegexp(
        `SsmParameterValue.*${ALERT_EMAIL_PARAMETER_NAME.replace(/\W/g, "")}`,
      ),
    }),
  });
});
