# Cognito Test Harness

Vocabulary for the privileged test infrastructure that exercises Cognito confidential-client admin authentication.

## Language

**Test persona**:
A named identity definition used to exercise a distinct authentication scenario.
_Avoid_: Seed user, test account

**Harness run**:
One isolated execution that owns its temporary test personas and their cleanup.
_Avoid_: Session

**Confidential-client probe**:
A focused test operation that demonstrates a confidential-client risk by intentionally presenting invalid client proof.
_Avoid_: Auth helper, negative utility
