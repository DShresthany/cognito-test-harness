# Cognito harness infra (CDK)

Defines `CognitoHarnessStack`: Cognito User Pool + confidential client + Secrets Manager
config secret (`cognito-test-harness/cognito`) + CodeBuild CI project.

See the root [README](../README.md) for bootstrap, GitHub PAT secret, deploy, `env:pull`, and CI.

```bash
npm install
npx cdk synth --profile cognito-dev
ALERT_EMAIL=you@example.com npx cdk deploy --profile cognito-dev
npm test
```

After deploy (from repo root): `AWS_PROFILE=cognito-dev npm run env:pull`
