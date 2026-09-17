import type {
  AuthenticationChallenge,
  AuthenticationOutcome,
  AuthenticationRejectionReason,
} from "./authenticationOutcome.js";
import type { NewPasswordChallengeInput } from "./cognitoUserPoolAuthDriver.js";
import type { ProfileTokenVerifiers } from "./jwtVerifier.js";
import { verifyQuietly } from "./permanentPasswordScenarios.js";

export type TemporaryPasswordChallengeEvidence = {
  outcomeKind: "authenticated" | "challenged" | "rejected";
  challengeType?: AuthenticationChallenge["type"];
  requiredAttributes?: string[];
  rejectionReason?: AuthenticationRejectionReason;
  providerCode?: string;
};

export type TemporaryPasswordCompletionEvidence = {
  outcomeKind: "authenticated" | "challenged" | "rejected";
  challengeType?: AuthenticationChallenge["type"];
  accessVerified: boolean | null;
  idVerified: boolean | null;
  temporaryPasswordRejected: boolean | null;
  newPasswordAuthenticates: boolean | null;
  refreshTokenIssued: boolean | null;
  rejectionReason?: AuthenticationRejectionReason;
  providerCode?: string;
};

export type PolicyViolationRecoverEvidence = {
  policyViolationReason: AuthenticationRejectionReason | null;
  recovered: boolean;
  accessVerified: boolean | null;
  idVerified: boolean | null;
  providerCode?: string;
};

export type InvalidChallengeSessionEvidence = {
  outcomeKind: "rejected" | "authenticated" | "challenged";
  rejectionReason?: AuthenticationRejectionReason;
  providerCode?: string;
};

export async function runTemporaryPasswordChallengeScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  username: string;
  temporaryPassword: string;
}): Promise<TemporaryPasswordChallengeEvidence> {
  const outcome = await input.authenticate(
    input.username,
    input.temporaryPassword,
  );
  return toChallengeEvidence(outcome);
}

export async function runTemporaryPasswordCompletionScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  respondToNewPassword: (
    challenge: NewPasswordChallengeInput,
  ) => Promise<AuthenticationOutcome>;
  verifiers: ProfileTokenVerifiers;
  username: string;
  temporaryPassword: string;
  newPassword: string;
}): Promise<TemporaryPasswordCompletionEvidence> {
  const first = await input.authenticate(
    input.username,
    input.temporaryPassword,
  );
  if (
    first.kind !== "challenged" ||
    first.challenge.type !== "new-password-required"
  ) {
    return {
      ...emptyCompletion(),
      ...toChallengeEvidence(first),
    };
  }

  const { session, username } = first.challenge.continuation;
  const continued = await input.respondToNewPassword({
    session,
    username,
    newPassword: input.newPassword,
  });
  if (continued.kind !== "authenticated") {
    return {
      ...emptyCompletion(),
      outcomeKind: continued.kind,
      challengeType: "new-password-required",
      ...(continued.kind === "rejected"
        ? {
            rejectionReason: continued.rejection.reason,
            ...(continued.rejection.diagnostic.providerCode
              ? { providerCode: continued.rejection.diagnostic.providerCode }
              : {}),
          }
        : {}),
    };
  }

  const accessVerified = await verifyQuietly(
    input.verifiers.access.verify(continued.tokens.accessToken),
  );
  const idVerified = await verifyQuietly(
    input.verifiers.id.verify(continued.tokens.idToken),
  );

  const tempRejected = await input.authenticate(
    input.username,
    input.temporaryPassword,
  );
  const newSignIn = await input.authenticate(input.username, input.newPassword);

  return {
    outcomeKind: "authenticated",
    challengeType: "new-password-required",
    accessVerified,
    idVerified,
    temporaryPasswordRejected:
      tempRejected.kind === "rejected" &&
      tempRejected.rejection.reason === "invalid-credentials",
    newPasswordAuthenticates: newSignIn.kind === "authenticated",
    refreshTokenIssued: Boolean(continued.tokens.refreshToken),
  };
}

export async function runPolicyViolatingThenRecoverScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  respondToNewPassword: (
    challenge: NewPasswordChallengeInput,
  ) => Promise<AuthenticationOutcome>;
  verifiers: ProfileTokenVerifiers;
  username: string;
  temporaryPassword: string;
  violatingPassword: string;
  recoveringPassword: string;
}): Promise<PolicyViolationRecoverEvidence> {
  const first = await input.authenticate(
    input.username,
    input.temporaryPassword,
  );
  if (
    first.kind !== "challenged" ||
    first.challenge.type !== "new-password-required"
  ) {
    return {
      policyViolationReason: null,
      recovered: false,
      accessVerified: null,
      idVerified: null,
    };
  }

  const violated = await input.respondToNewPassword({
    session: first.challenge.continuation.session,
    username: first.challenge.continuation.username,
    newPassword: input.violatingPassword,
  });
  const policyViolationReason =
    violated.kind === "rejected" ? violated.rejection.reason : null;
  const providerCode =
    violated.kind === "rejected"
      ? violated.rejection.diagnostic.providerCode
      : undefined;

  const fresh = await input.authenticate(
    input.username,
    input.temporaryPassword,
  );
  if (
    fresh.kind !== "challenged" ||
    fresh.challenge.type !== "new-password-required"
  ) {
    return {
      policyViolationReason,
      recovered: false,
      accessVerified: null,
      idVerified: null,
      ...(providerCode ? { providerCode } : {}),
    };
  }

  const recovered = await input.respondToNewPassword({
    session: fresh.challenge.continuation.session,
    username: fresh.challenge.continuation.username,
    newPassword: input.recoveringPassword,
  });
  if (recovered.kind !== "authenticated") {
    return {
      policyViolationReason,
      recovered: false,
      accessVerified: null,
      idVerified: null,
      ...(providerCode ? { providerCode } : {}),
    };
  }

  return {
    policyViolationReason,
    recovered: true,
    accessVerified: await verifyQuietly(
      input.verifiers.access.verify(recovered.tokens.accessToken),
    ),
    idVerified: await verifyQuietly(
      input.verifiers.id.verify(recovered.tokens.idToken),
    ),
    ...(providerCode ? { providerCode } : {}),
  };
}

export async function runInvalidChallengeSessionScenario(input: {
  respondToNewPassword: (
    challenge: NewPasswordChallengeInput,
  ) => Promise<AuthenticationOutcome>;
  session: string;
  username: string;
  newPassword: string;
}): Promise<InvalidChallengeSessionEvidence> {
  const outcome = await input.respondToNewPassword({
    session: input.session,
    username: input.username,
    newPassword: input.newPassword,
  });
  if (outcome.kind === "rejected") {
    return {
      outcomeKind: "rejected",
      rejectionReason: outcome.rejection.reason,
      ...(outcome.rejection.diagnostic.providerCode
        ? { providerCode: outcome.rejection.diagnostic.providerCode }
        : {}),
    };
  }
  return { outcomeKind: outcome.kind };
}

function toChallengeEvidence(
  outcome: AuthenticationOutcome,
): TemporaryPasswordChallengeEvidence {
  if (outcome.kind === "challenged") {
    return {
      outcomeKind: "challenged",
      challengeType: outcome.challenge.type,
      ...(outcome.challenge.type === "new-password-required"
        ? { requiredAttributes: outcome.challenge.requiredAttributes }
        : {}),
    };
  }
  if (outcome.kind === "authenticated") {
    return { outcomeKind: "authenticated" };
  }
  return {
    outcomeKind: "rejected",
    rejectionReason: outcome.rejection.reason,
    ...(outcome.rejection.diagnostic.providerCode
      ? { providerCode: outcome.rejection.diagnostic.providerCode }
      : {}),
  };
}

function emptyCompletion(): Pick<
  TemporaryPasswordCompletionEvidence,
  | "accessVerified"
  | "idVerified"
  | "temporaryPasswordRejected"
  | "newPasswordAuthenticates"
  | "refreshTokenIssued"
> {
  return {
    accessVerified: null,
    idVerified: null,
    temporaryPasswordRejected: null,
    newPasswordAuthenticates: null,
    refreshTokenIssued: null,
  };
}
