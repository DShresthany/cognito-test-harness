import * as cdk from "aws-cdk-lib/core";
import * as codebuild from "aws-cdk-lib/aws-codebuild";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

export interface HarnessCodeBuildProps {
  userPool: cognito.IUserPool;
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
        actions: ["iam:PassRole", "iam:GetRole", "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:DeleteRole", "iam:TagRole"],
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

    new cdk.CfnOutput(this, "CodeBuildProjectName", {
      value: this.project.projectName,
      description: "CodeBuild project for PR/main CI",
    });

    new cdk.CfnOutput(this, "CodeBuildProjectArn", {
      value: this.project.projectArn,
      description: "CodeBuild project ARN",
    });
  }
}
