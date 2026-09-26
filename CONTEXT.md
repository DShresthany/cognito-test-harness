# Cognito Test Harness

Vocabulary for the Cognito authentication test framework that exercises authentication, challenge, token, recovery, and browser/OAuth behavior.

## Language

**Cognito authentication test framework**:
A portfolio-quality, Cognito-specific test system that exercises authentication, challenge, token, recovery, and browser/OAuth behavior through incremental capability releases.
_Avoid_: Full login framework, provider-neutral identity framework

**Authentication outcome**:
The result of one authentication step: authenticated, challenged, or rejected. Operational failure is not an authentication outcome.
_Avoid_: Login response

**Authentication challenge**:
An intermediate Cognito result that requires a caller to continue with an opaque challenge context before authentication can finish.
_Avoid_: Partial login, failed login

**Authentication rejection**:
An expected refusal to authenticate or continue, such as invalid credentials or an invalid challenge code.
_Avoid_: Operational failure, exception

**Operational authentication failure**:
A configuration, authorization, blocking, throttling, service, network, delivery, or unsupported-response condition that prevents the framework from determining an authentication outcome.
_Avoid_: Authentication rejection

**Authentication profile**:
A stable combination of Cognito pool and app-client capabilities required by a group of authentication scenarios.
_Avoid_: Temporary configuration, test environment

**Authentication profile manifest**:
A versioned runtime document that maps canonical authentication-profile names to their deployed Cognito pool, client, and confidential proof values. It does not define expected behavior.
_Avoid_: Capability source of truth, environment-variable bundle

**Authentication driver**:
A one-step adapter to one Cognito authentication surface. It does not own test personas or multi-step workflow progress.
_Avoid_: Authentication manager, identity provider

**Scenario flow**:
An explicit sequence of authentication steps that proves one user story and returns its relevant evidence.
_Avoid_: Generic authentication engine, test script

**HTTP authentication stub**:
A thin test application that demonstrates terminal password authentication and access-token protection without implementing complete authentication workflows.
_Avoid_: Authentication service, product API

**Test persona**:
A named identity definition used to exercise a distinct authentication scenario.
_Avoid_: Seed user, test account

**Test persona fixture**:
The temporary runtime identity and credentials provisioned for a harness run and owned until cleanup.
_Avoid_: Seed user, shared test account

**Harness run**:
One isolated execution that owns its temporary test personas and their cleanup.
_Avoid_: Session

**Confidential-client probe**:
A focused test operation that demonstrates a confidential-client risk by intentionally presenting invalid client proof.
_Avoid_: Auth helper, negative utility

**Refresh lineage**:
One independently issued refresh token and every rotated replacement plus their associated access and ID tokens, correlated by `origin_jti`.
_Avoid_: User session, token list

**Controlled code sink**:
A test-only delivery boundary that retains a Cognito-encrypted one-time code envelope for one correlated scenario without exposing the plaintext through logs or evidence.
_Avoid_: Test inbox, production email delivery

**OAuth authorization attempt**:
One browser authorization-code transaction with independently generated PKCE verifier/challenge, state, nonce, callback, and one-use authorization code.
_Avoid_: Browser session, login

**Provider subject**:
The stable identifier issued by a controlled identity provider and used as the trusted linking input into Cognito.
_Avoid_: Email, federated username

**One-time SAML login grant**:
A single-use SAML authentication authorization issued for one harness run.
_Avoid_: Shared SAML user, seed IdP account

**Federated shadow profile**:
The Cognito user created by an unlinked federated sign-in, distinct from a local persona linked with `AdminLinkProviderForUser`.
_Avoid_: Linked account, seed user
