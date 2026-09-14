# Cognito harness infra (CDK)

Defines `CognitoHarnessStack`: Cognito User Pool + confidential client + Secrets Manager
config secret (`cognito-test-harness/cognito`) + CodeBuild CI project.

SNS failure alerts use SSM `/cognito-test-harness/alert-email` (not an env var in git).

See the root [README](../README.md) for bootstrap, GitHub PAT secret, deploy, `env:pull`, and CI.

```bash
npm install

# once
aws ssm put-parameter \
  --name /cognito-test-harness/alert-email \
  --value 'you@example.com' \
  --type String \
  --overwrite \
  --profile cognito-dev \
  --region us-east-1

npx cdk synth --profile cognito-dev
npx cdk deploy --profile cognito-dev
npm test
```

After deploy (from repo root): `AWS_PROFILE=cognito-dev npm run env:pull`
