# Cognito harness infra (CDK)

Defines `CognitoHarnessStack`: User Pool (email sign-in, admin-create only) + confidential app client with `ALLOW_ADMIN_USER_PASSWORD_AUTH`.

See the root [README](../README.md) for bootstrap, deploy, and outputs → `.env` steps.

```bash
npm install
npm test                 # template assertions
npx cdk synth --profile cognito-dev
npx cdk deploy --profile cognito-dev
```
