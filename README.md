# Cognito test harness

TypeScript/Vitest harness for a **Cognito Traditional web app** (confidential client). The **server** holds the app client secret, computes `SECRET_HASH`, and authenticates with `AdminInitiateAuth`. Tests cover YAML-driven user provisioning, SDK login, and a stub HTTP API. Cognito infrastructure and **CodeBuild CI** are defined with **CDK** under `infra/`.

## What this demonstrates

- Confidential app client: `SECRET_HASH = Base64(HMAC-SHA256(client_secret, username + client_id))`
- Admin auth flow: `ADMIN_USER_PASSWORD_AUTH`
- YAML personas (no passwords in git)
- Unique users per run (`emailPrefix+runId@gmail.com`) + random passwords + `AdminDeleteUser` cleanup
- Stub API: `POST /login` (secret stays on the server) and `GET /confirmed` (Cognito JWT verify + confirmation payload)
- CDK-owned User Pool + confidential client (reproducible deploy)
- AWS CodeBuild CI (PR gate + main deploy-if-`infra/`) with an IAM service role (no GitHub Actions AWS keys)

This pool requires **Username to be an email**. Uniqueness comes from the Gmail `+runId` alias, not `user-${uuid}`.

## Prerequisites

- Node.js 20+
- AWS CLI profile that can call Cognito admin APIs and deploy CloudFormation (this repo uses `AWS_PROFILE=cognito-dev`)
- CDK bootstrap once per account/region (see Infra below)
- GitHub PAT in Secrets Manager for CodeBuild (see CI below)

## Infra (CDK)

Stack: `CognitoHarnessStack` in [`infra/`](infra/) — User Pool (email sign-in, no self-registration) + confidential app client with `ALLOW_ADMIN_USER_PASSWORD_AUTH` + CodeBuild project `cognito-test-harness-ci`.

```bash
cd infra
npm install

# once per account/region
npx cdk bootstrap --profile cognito-dev

npx cdk synth --profile cognito-dev
npx cdk deploy --profile cognito-dev
```

From the repo root you can also run `npm run infra:synth` / `npm run infra:deploy` / `npm run infra:test`.

### Outputs → `.env`

After deploy, copy stack outputs into the harness `.env` (never commit `.env`):

| Stack output | Env var |
|---|---|
| `UserPoolId` | `COGNITO_USER_POOL_ID` |
| `UserPoolClientId` | `COGNITO_CLIENT_ID` |
| `UserPoolClientSecret` | `COGNITO_CLIENT_SECRET` |
| `Region` | `AWS_REGION` |

Keep `AWS_PROFILE=cognito-dev` (or your deploy profile).

`UserPoolClientSecret` is emitted as a stack output for this **private learning** repo — treat it as a secret and do not paste it into public issues/PRs.

Integration tests create and delete their own Cognito users via `CognitoLoginManager.setupUsers` / `cleanup` — no long-lived seed user is required.

## Setup

```bash
cp .env.example .env
# fill in .env from CDK outputs — never commit it

npm install
npm test          # full suite (needs Cognito env)
npm run test:unit # no Cognito
```

### CI (Phase 6) — AWS CodeBuild

All automated checks run in **CodeBuild** (not GitHub Actions). Project: `cognito-test-harness-ci`. Spec: [`buildspec.yml`](buildspec.yml).

| Trigger | What runs |
|---|---|
| **Pull request** (open/sync/reopen → `main`) | infra Jest → `cdk synth` → `test:unit` → full `npm test` (**no** deploy) |
| **Push to `main`** | If `infra/` changed → `cdk deploy`, then the same checks |

Cognito env vars are **read from CloudFormation stack outputs** at the start of each build so CI stays aligned if the pool/client is replaced. The CodeBuild service role calls Cognito (no AWS access keys in GitHub).

#### Failure email (SNS)

CodeBuild failures publish to SNS topic `cognito-test-harness-ci-alerts` via EventBridge. Deploy with your inbox:

```bash
export AWS_PROFILE=cognito-dev
export AWS_REGION=us-east-1
export ALERT_EMAIL=you@example.com
npm run infra:deploy
```

After deploy, **confirm the AWS subscription email** (Subject like "AWS Notification - Subscription Confirmation") or you will not receive alerts.

#### One-time: GitHub PAT for CodeBuild

Create a fine-grained or classic PAT with access to this private repo (`repo` / contents + webhooks as required). Store it in Secrets Manager **before** (or as part of) deploy:

```bash
aws secretsmanager create-secret \
  --name cognito-test-harness/github-pat \
  --secret-string 'YOUR_GITHUB_PAT' \
  --profile cognito-dev \
  --region us-east-1
```

Then:

```bash
export ALERT_EMAIL=you@example.com   # required for SNS failure alerts
npm run infra:deploy
```

CodeBuild will register a GitHub webhook and report status checks on PRs. Confirm the SNS subscription email after deploy.

You can remove obsolete **GitHub Actions** repository secrets (`AWS_ACCESS_KEY_ID`, etc.) once CodeBuild is green — they are unused.

Optional local server (not required for tests; Vitest uses in-process `app.request()`):

```bash
npm start   # http://localhost:3000
```

## Layout

```text
buildspec.yml              CodeBuild CI phases
infra/                     CDK app (Cognito + CodeBuild)
src/
  secretHash.ts            HMAC helper
  cognitoAuth.ts           Cognito client + env helpers
  cognitoLoginManager.ts   provision, login, credentials, cleanup
  app.ts                   POST /login, GET /confirmed
  jwtVerifier.ts           aws-jwt-verify (access token)
  server.ts                optional Node listener
testData/users.yaml        personas (key + emailPrefix)
tests/
  secretHash.test.ts
  randomPassword.test.ts
  cognito.integration.test.ts  YAML + API, shared beforeAll
```

## Security

- Do not commit `.env`, client secrets, or tokens
- Do not log generated passwords
- Keep this GitHub repo **private** until you are sure no IDs/secrets leaked
- Prefer rotating the app client secret if it was ever exposed
- CodeBuild uses an IAM service role; GitHub holds a PAT only in Secrets Manager for clone/webhooks

## Roadmap

Cognito is **test infrastructure** for auth-backed coverage. Suggested order:

1. **Phase 6 – CI**  
   **Done:** AWS CodeBuild for PR + main (`buildspec.yml` + CDK project). PR runs full checks without deploy; main deploys when `infra/` changes then re-tests. Cognito config loaded from stack outputs. **Failure email:** EventBridge → SNS on CodeBuild FAILED/FAULT/STOPPED/TIMED_OUT (confirm SNS subscription after deploy with `ALERT_EMAIL`). **Optional polish:** tighten CodeBuild IAM below PowerUser.

2. **Secrets in AWS**  
   Move client secret (and preferably pool id / client id / region) into Secrets Manager or SSM, updated on deploy. CI role reads them each run so GitHub/static config cannot drift after a replacing deploy. Stop plaintext client secret in CloudFormation outputs. Keep `.env` gitignored for local use.

3. **Optional – two envs (`dev` / `ci`)**  
   After CI works on one stack: `dev` for local experiments; `ci` as the long-lived pool CodeBuild hits on PRs. Not a full Dev→Staging→Prod pipeline.

4. **Phase 7 – Thin UI (optional)**  
   Browser demo: `/login` → `POST /login` → `/confirmed` page calling `GET /confirmed`. Secret stays on the server.

5. **Phase 8 – Third-party login (optional)**  
   Federated IdP (e.g. Google) via Cognito Hosted UI after CI. Keep password YAML tests as the PR gate.

6. **Hygiene**  
   Delete unused Phase 0 console pool if present; least-privilege IAM; optional billing alert.
