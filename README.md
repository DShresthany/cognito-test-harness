# Cognito test harness

TypeScript/Vitest harness for a **Cognito Traditional web app** (confidential client). The **server** holds the app client secret, computes `SECRET_HASH`, and authenticates with `AdminInitiateAuth`. Tests cover SDK login, YAML-driven user provisioning, and a stub HTTP API.

## What this demonstrates

- Confidential app client: `SECRET_HASH = Base64(HMAC-SHA256(client_secret, username + client_id))`
- Admin auth flow: `ADMIN_USER_PASSWORD_AUTH`
- YAML personas (no passwords in git)
- Unique users per run (`emailPrefix+runId@gmail.com`) + random passwords + `AdminDeleteUser` cleanup
- Stub API: `POST /login` (secret stays on the server) and `GET /confirmed` (Cognito JWT verify + confirmation payload)

This pool requires **Username to be an email**. Uniqueness comes from the Gmail `+runId` alias, not `user-${uuid}`.

## Prerequisites

- Node.js 20+
- AWS CLI profile that can call Cognito admin APIs (this repo uses `AWS_PROFILE`)
- A Cognito User Pool with:
  - Self-registration off
  - Traditional web app client **with secret**
  - `ALLOW_ADMIN_USER_PASSWORD_AUTH` enabled
- One confirmed user for the SDK smoke tests (`COGNITO_TEST_*`)

## Setup

```bash
cp .env.example .env
# fill in .env — never commit it

npm install
npm test
```

Optional local server (not required for tests; Vitest uses in-process `app.request()`):

```bash
npm start   # http://localhost:3000
```

## Layout

```text
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
  adminAuth.test.ts        existing .env user
  cognito.integration.test.ts  YAML + API, shared beforeAll
```

## Security

- Do not commit `.env`, client secrets, or tokens
- Do not log generated passwords
- Keep this GitHub repo **private** until you are sure no IDs/secrets leaked

## Roadmap

- CDK stack for the User Pool + confidential client
- GitHub Actions: synth/diff on PR, deploy + `npm test` on main
