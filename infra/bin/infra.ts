#!/usr/bin/env node
import * as cdk from "aws-cdk-lib/core";
import { CognitoHarnessStack } from "../lib/cognito-harness-stack";

const app = new cdk.App();
new CognitoHarnessStack(app, "CognitoHarnessStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  description:
    "Cognito User Pool + confidential client for the cognito-test-harness",
});
