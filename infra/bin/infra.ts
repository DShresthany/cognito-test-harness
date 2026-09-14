#!/usr/bin/env node
import * as cdk from "aws-cdk-lib/core";
import { CognitoHarnessStack } from "../lib/cognito-harness-stack";

const app = new cdk.App();

/**
 * Optional override of SSM /cognito-test-harness/alert-email.
 * Reject placeholders so CI/local cannot accidentally wire SNS to a fake inbox.
 */
function optionalAlertEmailOverride(): string | undefined {
  const raw =
    process.env.ALERT_EMAIL ??
    (app.node.tryGetContext("alertEmail") as string | undefined);
  if (raw === undefined || raw.trim() === "") {
    return undefined;
  }
  const value = raw.trim();
  const lower = value.toLowerCase();
  if (
    lower === "replace_me" ||
    lower.includes("placeholder") ||
    lower.endsWith("@example.com")
  ) {
    throw new Error(
      "ALERT_EMAIL / -c alertEmail looks like a placeholder. " +
        "Set SSM /cognito-test-harness/alert-email to your real inbox, or pass a real override.",
    );
  }
  return value;
}

function contextString(key: string): string | undefined {
  const raw = app.node.tryGetContext(key) as string | undefined;
  const value = raw?.trim();
  return value ? value : undefined;
}

const alertEmail = optionalAlertEmailOverride();
const githubOwner = contextString("githubOwner");
const githubRepo = contextString("githubRepo");

new CognitoHarnessStack(app, "CognitoHarnessStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  ...(alertEmail ? { alertEmail } : {}),
  ...(githubOwner ? { githubOwner } : {}),
  ...(githubRepo ? { githubRepo } : {}),
  description:
    "Cognito User Pool + confidential client + CodeBuild CI for the cognito-test-harness",
});
