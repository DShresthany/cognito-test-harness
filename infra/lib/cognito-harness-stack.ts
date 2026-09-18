import * as cdk from "aws-cdk-lib/core";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as ssm from "aws-cdk-lib/aws-ssm";
import { Construct } from "constructs";
import { HarnessCodeBuild } from "./harness-codebuild";

/** JSON secret: schema version 2 authentication profile manifest. */
export const COGNITO_CONFIG_SECRET_NAME = "cognito-test-harness/cognito";

export const ADMIN_CONFIDENTIAL_PROFILE_ID = "admin-confidential";
export const USER_POOL_PUBLIC_PROFILE_ID = "user-pool-public";

/** SNS failure-alert inbox (String parameter; create once outside the stack). */
export const ALERT_EMAIL_PARAMETER_NAME = "/cognito-test-harness/alert-email";

export interface CognitoHarnessStackProps extends cdk.StackProps {
  /**
   * Optional SNS alert inbox override.
   * Default: SSM {@link ALERT_EMAIL_PARAMETER_NAME} via CloudFormation dynamic reference
   * (synth does not need the value; deploy resolves it). Prefer SSM for real deploys;
   * pass a concrete address in unit tests.
   */
  alertEmail?: string;
  /** GitHub owner for CodeBuild source (or CDK context `githubOwner`). */
  githubOwner?: string;
  /** GitHub repo for CodeBuild source (or CDK context `githubRepo`). */
  githubRepo?: string;
}

function resolveAlertEmail(scope: Construct, override?: string): string {
  const trimmed = override?.trim();
  if (trimmed) {
    return trimmed;
  }
  return ssm.StringParameter.valueForStringParameter(
    scope,
    ALERT_EMAIL_PARAMETER_NAME,
  );
}

export class CognitoHarnessStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    props: CognitoHarnessStackProps = {},
  ) {
    super(scope, id, props);

    const alertEmail = resolveAlertEmail(this, props.alertEmail);

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
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: {
        sms: false,
        otp: true,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const firstReleaseClientSettings = {
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.hours(1),
      refreshTokenValidity: cdk.Duration.days(30),
      authSessionValidity: cdk.Duration.minutes(3),
      enableTokenRevocation: true,
      disableOAuth: true,
      preventUserExistenceErrors: true,
    };

    // Construct id bump replaces the app client (new client secret) when rotating after exposure.
    const confidentialClient = userPool.addClient("HarnessWebClient", {
      userPoolClientName: "cognito-test-harness-web",
      generateSecret: true,
      authFlows: {
        adminUserPassword: true,
      },
      ...firstReleaseClientSettings,
    });

    const publicClient = userPool.addClient("HarnessPublicClient", {
      userPoolClientName: "cognito-test-harness-public",
      generateSecret: false,
      authFlows: {
        userPassword: true,
      },
      ...firstReleaseClientSettings,
    });

    // Source of truth for harness + CI (no plaintext client secret in stack outputs).
    const cognitoConfig = new secretsmanager.Secret(this, "CognitoConfig", {
      secretName: COGNITO_CONFIG_SECRET_NAME,
      description: "Cognito harness config (schema version 2 profiles)",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const cfnSecret = cognitoConfig.node.defaultChild as secretsmanager.CfnSecret;
    cfnSecret.generateSecretString = undefined;
    cfnSecret.secretString = cdk.Fn.sub(
      [
        '{"schemaVersion":2,',
        '"region":"${AWS::Region}",',
        '"userPoolId":"${UserPoolId}",',
        '"profiles":{',
        `"${ADMIN_CONFIDENTIAL_PROFILE_ID}":{"kind":"confidential","clientId":"\${ClientId}","clientSecret":"\${ClientSecret}"},`,
        `"${USER_POOL_PUBLIC_PROFILE_ID}":{"kind":"public","clientId":"\${PublicClientId}"}`,
        "}}",
      ].join(""),
      {
        UserPoolId: userPool.userPoolId,
        ClientId: confidentialClient.userPoolClientId,
        ClientSecret: confidentialClient.userPoolClientSecret.unsafeUnwrap(),
        PublicClientId: publicClient.userPoolClientId,
      },
    );

    new HarnessCodeBuild(this, "Ci", {
      userPool,
      cognitoConfigSecret: cognitoConfig,
      alertEmail,
      githubOwner: props.githubOwner,
      githubRepo: props.githubRepo,
    });

    new cdk.CfnOutput(this, "AlertEmailParameterName", {
      value: ALERT_EMAIL_PARAMETER_NAME,
      description:
        "SSM parameter for SNS failure-alert inbox (stack does not own the value)",
    });

    new cdk.CfnOutput(this, "AlertEmail", {
      value: alertEmail,
      description:
        "SNS failure-alert inbox (from SSM by default, or alertEmail override)",
    });

    new cdk.CfnOutput(this, "UserPoolId", {
      value: userPool.userPoolId,
      description: "Map to COGNITO_USER_POOL_ID (also in Secrets Manager)",
    });

    new cdk.CfnOutput(this, "UserPoolClientId", {
      value: confidentialClient.userPoolClientId,
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
