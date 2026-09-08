#!/usr/bin/env node
import * as cdk from "aws-cdk-lib/core";
import { CognitoHarnessStack } from "../lib/cognito-harness-stack";

const app = new cdk.App();

const alertEmail =
  process.env.ALERT_EMAIL ?? (app.node.tryGetContext("alertEmail") as string);

if (!alertEmail || alertEmail === "REPLACE_ME") {
  throw new Error(
    "Set ALERT_EMAIL or cdk context alertEmail to the inbox that should receive CodeBuild failure emails, e.g.\n" +
      "  ALERT_EMAIL=you@example.com npm run infra:deploy\n" +
      "  npx cdk deploy -c alertEmail=you@example.com --profile cognito-dev",
  );
}

new CognitoHarnessStack(app, "CognitoHarnessStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  alertEmail,
  description:
    "Cognito User Pool + confidential client + CodeBuild CI for the cognito-test-harness",
});
