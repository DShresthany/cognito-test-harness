# First-capability release

This document closes the first Cognito auth-framework release: password, JWT, refresh, temporary password, and deterministic TOTP on the required PR gate.

## Profiles

| Profile id | Kind | Purpose |
|---|---|---|
| `admin-confidential` | Confidential app client | Privileged admin password auth + refresh (`SECRET_HASH`) |
| `user-pool-public` | Public app client | End-user password, `NEW_PASSWORD_REQUIRED`, software-token MFA |

Both profiles share one User Pool. Config is schema version **2** JSON in Secrets Manager (`cognito-test-harness/cognito`): `schemaVersion`, `region`, `userPoolId`, and `profiles` only — no legacy top-level `clientId` / `clientSecret`.

## Local setup

```bash
export AWS_PROFILE=cognito-dev
export AWS_REGION=us-east-1
npm install
npm run env:pull          # owner-only .cognito/config.json + bootstrap .env
npm run preflight         # manifest + live Describe (no users)
npm test                  # unit + HTTP (no AWS)
npm run test:live:cognito # serial live matrix including TOTP
```

Never commit `.env` or `.cognito/`.

## CI setup

CodeBuild project `cognito-test-harness-ci` runs `scripts/codebuild-pre-build.sh` (materialize secret; deploy on main when `infra/` changes) then `npm run ci:gate`:

1. typecheck  
2. unit  
3. HTTP  
4. infra assertions  
5. synth  
6. preflight  
7. live Cognito (serial, no Vitest retries)  
8. remove secret files  

Failures are classified (`static`, `infrastructure`, `profile-drift`, `semantic-scenario`, …) and stay red — never relabeled flaky. Static/infra/preflight failure does not create personas.

## Scenario inventory (acceptance matrix)

| ID | Surface | Story |
|---|---|---|
| PA-1…PA-5 | Admin + public | Permanent-password sign-in and rejection privacy |
| TV-1…TV-4 | Admin + public | Access/ID verify, tamper, cross-profile binding |
| RF-1…RF-5 | Admin + public | Non-rotating refresh and wrong-client / proof rejection |
| NP-1…NP-4 | Public | `NEW_PASSWORD_REQUIRED` continue, policy recover, bad session |
| TP-1…TP-3 + reuse | Public | Software-token enroll, wrong codes, reused-code rejection |

All of the above gate pull requests via `test:live:cognito` inside `ci:gate`.

## Safe diagnostics

Reports and stubs may emit only allowlisted fields (see `REPORT_ALLOWLIST_FIELDS` / `toSafeDiagnostic`): operation, outcome kind, challenge/rejection type, provider code, request id(s), retryability, profile id, cleanup-oriented booleans. They must never include usernames, passwords, tokens, sessions, secrets, or TOTP codes.

## Cleanup

- Fixture manager owns persona deletion; drivers never delete users.  
- Live suites call fixture `cleanup` in `afterAll` even when assertions fail.  
- `ci:gate` always removes materialized secret files on exit once config exists or live has started.  
- Unexplained semantic TOTP failure or cleanup leak keeps the build red (no auto-retry).

## TOTP graduation note

Deterministic TOTP graduated into the required live suite after ten consecutive successful separate CodeBuild soak executions (operator-attested for this release). Soak is no longer a separate PR command.
