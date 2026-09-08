import * as cdk from "aws-cdk-lib/core";
import * as codebuild from "aws-cdk-lib/aws-codebuild";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import { Construct } from "constructs";

export interface HarnessCodeBuildProps {
  userPool: cognito.IUserPool;
  /** Email for CodeBuild failure alerts (SNS). Confirm the subscription in your inbox after deploy. */
  alertEmail: string;
  /** GitHub owner (user or org). */
  githubOwner?: string;
  /** GitHub repository name. */
  githubRepo?: string;
}

/**
 * CodeBuild project for Phase 6 CI (PR gate + main deploy-if-infra).
 * Requires a GitHub PAT in Secrets Manager: cognito-test-harness/github-pat
 * (repo + admin:repo_hook) so CodeBuild can clone the private repo and create webhooks.
 */
export class HarnessCodeBuild extends Construct {
  public readonly project: codebuild.Project;
  public readonly alertTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: HarnessCodeBuildProps) {
    super(scope, id);

    const owner = props.githubOwner ?? "DShresthany";
    const repo = props.githubRepo ?? "cognito-test-harness";

    // Account/region singleton — create once; see README if deploy conflicts.
    new codebuild.GitHubSourceCredentials(this, "GitHubCreds", {
      accessToken: cdk.SecretValue.secretsManager(
        "cognito-test-harness/github-pat",
      ),
    });

    const role = new iam.Role(this, "ServiceRole", {
      assumedBy: new iam.ServicePrincipal("codebuild.amazonaws.com"),
      description:
        "CodeBuild role for cognito-test-harness CI (Cognito Admin + CDK deploy)",
    });

    // Learning-friendly: PowerUser covers CFN/S3/Cognito; PassRole for CDK bootstrap roles.
    role.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("PowerUserAccess"),
    );
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: "CdkPassRoles",
        actions: [
          "iam:PassRole",
          "iam:GetRole",
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:DeleteRole",
          "iam:TagRole",
        ],
        resources: ["*"],
      }),
    );

    // Explicit pool-scoped Cognito Admin (documents intent even under PowerUser).
    role.addToPolicy(
      new iam.PolicyStatement({
        sid: "CognitoHarnessAdmin",
        actions: [
          "cognito-idp:AdminCreateUser",
          "cognito-idp:AdminSetUserPassword",
          "cognito-idp:AdminInitiateAuth",
          "cognito-idp:AdminDeleteUser",
          "cognito-idp:AdminGetUser",
          "cognito-idp:DescribeUserPool",
          "cognito-idp:DescribeUserPoolClient",
          "cognito-idp:ListUsers",
        ],
        resources: [props.userPool.userPoolArn],
      }),
    );

    this.project = new codebuild.Project(this, "Project", {
      projectName: "cognito-test-harness-ci",
      description:
        "PR + main CI: synth/tests against long-lived Cognito; deploy infra/ on main when needed",
      role,
      source: codebuild.Source.gitHub({
        owner,
        repo,
        reportBuildStatus: true,
        webhook: true,
        webhookFilters: [
          codebuild.FilterGroup.inEventOf(
            codebuild.EventAction.PULL_REQUEST_CREATED,
            codebuild.EventAction.PULL_REQUEST_UPDATED,
            codebuild.EventAction.PULL_REQUEST_REOPENED,
          ),
          codebuild.FilterGroup.inEventOf(
            codebuild.EventAction.PUSH,
          ).andBranchIs("main"),
        ],
      }),
      buildSpec: codebuild.BuildSpec.fromSourceFilename("buildspec.yml"),
      environment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_7_0,
        computeType: codebuild.ComputeType.SMALL,
      },
      timeout: cdk.Duration.minutes(30),
    });

    this.alertTopic = new sns.Topic(this, "AlertTopic", {
      displayName: "cognito-test-harness-ci failures",
      topicName: "cognito-test-harness-ci-alerts",
    });
    this.alertTopic.addSubscription(
      new subscriptions.EmailSubscription(props.alertEmail),
    );

    new events.Rule(this, "BuildFailedRule", {
      description:
        "Email when cognito-test-harness-ci fails, faults, stops, or times out",
      eventPattern: {
        source: ["aws.codebuild"],
        detailType: ["CodeBuild Build State Change"],
        detail: {
          "build-status": ["FAILED", "FAULT", "STOPPED", "TIMED_OUT"],
          "project-name": [this.project.projectName],
        },
      },
      targets: [
        new targets.SnsTopic(this.alertTopic, {
          message: events.RuleTargetInput.fromMultilineText(
            [
              "CodeBuild build did not succeed.",
              `Project: ${this.project.projectName}`,
              "Open the CodeBuild console (us-east-1) for logs.",
            ].join("\n"),
          ),
        }),
      ],
    });

    new cdk.CfnOutput(this, "CodeBuildProjectName", {
      value: this.project.projectName,
      description: "CodeBuild project for PR/main CI",
    });

    new cdk.CfnOutput(this, "CodeBuildProjectArn", {
      value: this.project.projectArn,
      description: "CodeBuild project ARN",
    });

    new cdk.CfnOutput(this, "AlertTopicArn", {
      value: this.alertTopic.topicArn,
      description: "SNS topic for CodeBuild failure emails",
    });

    new cdk.CfnOutput(this, "AlertEmail", {
      value: props.alertEmail,
      description:
        "Confirm the SNS subscription email AWS sends after deploy",
    });
  }
}
