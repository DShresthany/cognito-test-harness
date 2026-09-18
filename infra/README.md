# Cognito harness infra (CDK)

Defines `CognitoHarnessStack`: Cognito User Pool + confidential client + Secrets Manager
config secret (`cognito-test-harness/cognito`) + CodeBuild CI project + SNS failure alerts.

Test design, CI tradeoffs, and how to run Vitest live in the root [README](../README.md). This file is the **ops runbook**: bootstrap, deploy, secrets, and rotation.

Pool and config secret use `RemovalPolicy.DESTROY` so this throwaway demo can be deleted cleanly. **Do not copy that into a shared or production account** without switching to `RETAIN`.

CodeBuild’s GitHub source defaults via CDK context in `cdk.json` (`githubOwner` / `githubRepo`). Forks: `npx cdk deploy -c githubOwner=YOUR_USER -c githubRepo=YOUR_FORK --profile cognito-dev`.

## Deploy

```bash
cd infra
npm install

# once per account/region
npx cdk bootstrap --profile cognito-dev

# once: SNS alert inbox in SSM (not in git / buildspec)
aws ssm put-parameter \
  --name /cognito-test-harness/alert-email \
  --value 'you@example.com' \
  --type String \
  --overwrite \
  --profile cognito-dev \
  --region us-east-1

npx cdk synth --profile cognito-dev
npx cdk deploy --profile cognito-dev
```

From the repo root: `npm run infra:synth` / `npm run infra:deploy` / `npm run infra:test`.

`cdk synth` does **not** need `ALERT_EMAIL` — the stack references SSM `/cognito-test-harness/alert-email` (CloudFormation resolves it at deploy). Optional override for emergencies only: `ALERT_EMAIL=you@example.com` or `-c alertEmail=…` (placeholders like `*@example.com` / `*placeholder*` are rejected).

## Cognito config → `.cognito/config.json`

After deploy, pull config from Secrets Manager (never commit `.env` or `.cognito/`):

```bash
export AWS_PROFILE=cognito-dev
export AWS_REGION=us-east-1
npm run env:pull
```

Secret name: `cognito-test-harness/cognito` (JSON schema version 2: `region`, `userPoolId`, `profiles` for `admin-confidential` and `user-pool-public`).  
Stack output `CognitoConfigSecretName` points at that secret. Pool/client ids and region are also non-secret stack outputs — the **client secret is not** a CloudFormation output.

`env:pull` materializes owner-only `.cognito/config.json` (full secret JSON) and a bootstrap `.env` with `AWS_PROFILE`, `AWS_REGION`, and `COGNITO_CONFIG_PATH` only — no pool/client/secret env vars. Runtime and integration tests load profiles from that config path and run a live DescribeUserPoolClient preflight.

Keep `AWS_PROFILE=cognito-dev` (or your deploy profile) in `.env` for local Cognito Admin API calls.

## Failure email (SNS)

CodeBuild failures publish to SNS topic `cognito-test-harness-ci-alerts` via EventBridge. The email includes build status, build ID, and a link to the CodeBuild project history (paste the Build ID to open the exact run — EventBridge cannot URL-encode build ARNs for deep links).

**Source of truth:** SSM `/cognito-test-harness/alert-email` (not `buildspec.yml`). After creating or updating the parameter, redeploy and **confirm the AWS subscription email**. Changing the SSM value and redeploying updates the SNS subscription endpoint (re-confirm if AWS sends a new confirmation).

```bash
aws ssm put-parameter \
  --name /cognito-test-harness/alert-email \
  --value 'you@example.com' \
  --type String \
  --overwrite \
  --profile cognito-dev \
  --region us-east-1

export AWS_PROFILE=cognito-dev
export AWS_REGION=us-east-1
npm run infra:deploy
```

## One-time: GitHub PAT for CodeBuild

Create a fine-grained or classic PAT with access to this repo (`repo` / contents + webhooks as required — still needed for CodeBuild clone/webhooks on a public repo). Store it in Secrets Manager **before** (or as part of) deploy:

```bash
aws secretsmanager create-secret \
  --name cognito-test-harness/github-pat \
  --secret-string 'YOUR_GITHUB_PAT' \
  --profile cognito-dev \
  --region us-east-1
```

Then (SSM alert-email must already exist):

```bash
npm run infra:deploy
```

CodeBuild registers a GitHub webhook and reports status checks on PRs. Obsolete **GitHub Actions** repository secrets (`AWS_ACCESS_KEY_ID`, etc.) can be removed once CodeBuild is green.

## Rotate Cognito client secret

Cognito does not rotate an app client secret in place. Replace the client (CDK construct id change), deploy, then refresh local env:

```bash
export AWS_PROFILE=cognito-dev
npm run infra:deploy
npm run env:pull
npm run test:live:cognito
```

Also rotate the GitHub PAT in `cognito-test-harness/github-pat` if it was ever pasted into chat or logs.
