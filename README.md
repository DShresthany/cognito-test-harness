# Cognito test harness

TypeScript/Vitest harness for a **Cognito Traditional web app** (confidential client). The **server** holds the app client secret, computes `SECRET_HASH`, and authenticates with `AdminInitiateAuth`. Tests cover YAML-driven user provisioning, SDK login, and a stub HTTP API. Cognito infrastructure is defined with **CDK** under `infra/`.

## What this demonstrates

- Confidential app client: `SECRET_HASH = Base64(HMAC-SHA256(client_secret, username + client_id))`
- Admin auth flow: `ADMIN_USER_PASSWORD_AUTH`
- YAML personas (no passwords in git)
- Unique users per run (`emailPrefix+runId@gmail.com`) + random passwords + `AdminDeleteUser` cleanup
- Stub API: `POST /login` (secret stays on the server) and `GET /confirmed` (Cognito JWT verify + confirmation payload)
- CDK-owned User Pool + confidential client (reproducible deploy)

This pool requires **Username to be an email**. Uniqueness comes from the Gmail `+runId` alias, not `user-${uuid}`.

## Prerequisites

- Node.js 20+
- AWS CLI profile that can call Cognito admin APIs and deploy CloudFormation (this repo uses `AWS_PROFILE=cognito-dev`)
- CDK bootstrap once per account/region (see Infra below)

## Infra (CDK)

Stack: `CognitoHarnessStack` in [`infra/`](infra/) — User Pool (email sign-in, no self-registration) + confidential app client with `ALLOW_ADMIN_USER_PASSWORD_AUTH`.

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
npm run test:unit # CI slice 1 — no Cognito
```

### CI (Phase 6)

PRs to `main` run [`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml):

1. **Infra + unit** — infra Jest, `cdk synth`, `npm run test:unit` (no Cognito)
2. **Cognito integration** — full `npm test` against the long-lived CDK pool

Configure these **repository secrets** (Settings → Secrets and variables → Actions) from your IAM user + CDK stack outputs:

| Secret | Purpose |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM user that can call Cognito Admin APIs on the harness pool |
| `AWS_SECRET_ACCESS_KEY` | Matching secret key |
| `AWS_REGION` | e.g. `us-east-1` |
| `COGNITO_USER_POOL_ID` | Stack output `UserPoolId` |
| `COGNITO_CLIENT_ID` | Stack output `UserPoolClientId` |
| `COGNITO_CLIENT_SECRET` | Stack output `UserPoolClientSecret` |

Do not set `AWS_PROFILE` in CI — the workflow uses access keys via `aws-actions/configure-aws-credentials`. Prefer migrating to **OIDC** (no long-lived keys) as a later Phase 6 hardening step.

Optional local server (not required for tests; Vitest uses in-process `app.request()`):

```bash
npm start   # http://localhost:3000
```

## Layout

```text
infra/                     CDK app (CognitoHarnessStack)
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
- CI uses GitHub Actions secrets for Cognito + IAM keys today; prefer OIDC later

## Roadmap

Cognito is **test infrastructure** for auth-backed coverage. Suggested order:

1. **Phase 6 – CI (in progress)**  
   GitHub Actions merge gate. **Done (slice 1):** infra Jest + `cdk synth` + `npm run test:unit`. **Done (slice 2):** Cognito integration job runs full `npm test` against the long-lived CDK pool via GitHub secrets (IAM access keys). **Next:** prefer OIDC IAM role over long-lived keys; optional `cdk diff`; on `main`, `cdk deploy` if `infra/` changed then `npm test`. No new Cognito stack per PR.

2. **Secrets in AWS**  
   Move the client secret off CloudFormation plaintext output into Secrets Manager or SSM. Stack outputs ARN/name; CI role reads the secret. Keep `.env` gitignored.

3. **Optional – two envs (`dev` / `ci`)**  
   After CI works on one stack: `dev` for local experiments; `ci` as the long-lived pool GitHub Actions hits on PRs. Not a full Dev→Staging→Prod pipeline.

4. **Phase 7 – Thin UI (optional)**  
   Browser demo: `/login` → `POST /login` → `/confirmed` page calling `GET /confirmed`. Secret stays on the server.

5. **Phase 8 – Third-party login (optional)**  
   Federated IdP (e.g. Google) via Cognito Hosted UI after CI. Keep password YAML tests as the PR gate.

6. **Hygiene**  
   Delete unused Phase 0 console pool if present; least-privilege IAM; optional billing alert.
