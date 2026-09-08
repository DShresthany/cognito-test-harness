# Cognito harness infra (CDK)

Defines `CognitoHarnessStack`: Cognito User Pool + confidential client + CodeBuild CI project.

See the root [README](../README.md) for bootstrap, GitHub PAT secret, deploy, and CI behavior.

```bash
npm install
npx cdk synth --profile cognito-dev
ALERT_EMAIL=you@example.com npx cdk deploy --profile cognito-dev
npm test
```
