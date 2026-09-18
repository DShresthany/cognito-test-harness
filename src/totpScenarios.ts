import type {
  AuthenticationChallenge,
  AuthenticationOutcome,
  AuthenticationRejectionReason,
} from "./authenticationOutcome.js";
import type {
  SoftwareTokenMfaChallengeInput,
  VerifySoftwareTokenInput,
  VerifySoftwareTokenResult,
} from "./cognitoUserPoolAuthDriver.js";
import type { ProfileTokenVerifiers } from "./jwtVerifier.js";
import { verifyQuietly } from "./permanentPasswordScenarios.js";
import {
  alterTotpCode,
  generateTotpCode,
  waitForMinimumStepRemainder,
  waitForNextTotpStep,
  type TotpClock,
} from "./totpCode.js";

export type TotpEnrollmentEvidence = {
  enrollmentVerified: boolean;
  preferredMfaSet: boolean;
  challengeType?: AuthenticationChallenge["type"];
  mfaAuthenticated: boolean;
  accessVerified: boolean | null;
  idVerified: boolean | null;
  rejectionReason?: AuthenticationRejectionReason;
  providerCode?: string;
};

export type TotpWrongEnrollmentEvidence = {
  outcomeKind: "rejected" | "verified";
  rejectionReason?: AuthenticationRejectionReason;
  providerCode?: string;
};

export type TotpWrongSignInEvidence = {
  wrongCodeRejected: boolean;
  wrongCodeReason?: AuthenticationRejectionReason;
  recovered: boolean;
  accessVerified: boolean | null;
  idVerified: boolean | null;
  providerCode?: string;
};

export type TotpReusedCodeEvidence = {
  reuseRejected: boolean;
  rejectionReason?: AuthenticationRejectionReason;
  providerCode?: string;
};

export async function runTotpEnrollmentScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  associateSoftwareToken: (accessToken: string) => Promise<string>;
  verifySoftwareToken: (
    input: VerifySoftwareTokenInput,
  ) => Promise<VerifySoftwareTokenResult>;
  setSoftwareTokenMfaPreferred: (accessToken: string) => Promise<void>;
  respondToSoftwareTokenMfa: (
    input: SoftwareTokenMfaChallengeInput,
  ) => Promise<AuthenticationOutcome>;
  verifiers: ProfileTokenVerifiers;
  username: string;
  password: string;
  clock?: TotpClock;
}): Promise<TotpEnrollmentEvidence> {
  const clock = input.clock;
  const signedIn = await input.authenticate(input.username, input.password);
  if (signedIn.kind !== "authenticated") {
    return {
      enrollmentVerified: false,
      preferredMfaSet: false,
      mfaAuthenticated: false,
      accessVerified: null,
      idVerified: null,
      ...rejectionFields(signedIn),
    };
  }

  const secret = await input.associateSoftwareToken(
    signedIn.tokens.accessToken,
  );
  await waitForMinimumStepRemainder(clock);
  const verified = await input.verifySoftwareToken({
    accessToken: signedIn.tokens.accessToken,
    code: generateTotpCode(secret, clock),
  });
  if (verified.kind !== "verified") {
    return {
      enrollmentVerified: false,
      preferredMfaSet: false,
      mfaAuthenticated: false,
      accessVerified: null,
      idVerified: null,
      rejectionReason: verified.rejection.reason,
      ...(verified.rejection.diagnostic.providerCode
        ? { providerCode: verified.rejection.diagnostic.providerCode }
        : {}),
    };
  }

  await input.setSoftwareTokenMfaPreferred(signedIn.tokens.accessToken);
  await waitForNextTotpStep(clock);

  const challenged = await input.authenticate(input.username, input.password);
  if (
    challenged.kind !== "challenged" ||
    challenged.challenge.type !== "software-token-mfa"
  ) {
    return {
      enrollmentVerified: true,
      preferredMfaSet: true,
      mfaAuthenticated: false,
      accessVerified: null,
      idVerified: null,
      ...(challenged.kind === "challenged"
        ? { challengeType: challenged.challenge.type }
        : rejectionFields(challenged)),
    };
  }

  await waitForMinimumStepRemainder(clock);
  const continued = await input.respondToSoftwareTokenMfa({
    session: challenged.challenge.continuation.session,
    username: challenged.challenge.continuation.username,
    code: generateTotpCode(secret, clock),
  });
  if (continued.kind !== "authenticated") {
    return {
      enrollmentVerified: true,
      preferredMfaSet: true,
      challengeType: "software-token-mfa",
      mfaAuthenticated: false,
      accessVerified: null,
      idVerified: null,
      ...rejectionFields(continued),
    };
  }

  return {
    enrollmentVerified: true,
    preferredMfaSet: true,
    challengeType: "software-token-mfa",
    mfaAuthenticated: true,
    accessVerified: await verifyQuietly(
      input.verifiers.access.verify(continued.tokens.accessToken),
    ),
    idVerified: await verifyQuietly(
      input.verifiers.id.verify(continued.tokens.idToken),
    ),
  };
}

export async function runTotpWrongEnrollmentScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  associateSoftwareToken: (accessToken: string) => Promise<string>;
  verifySoftwareToken: (
    input: VerifySoftwareTokenInput,
  ) => Promise<VerifySoftwareTokenResult>;
  username: string;
  password: string;
  clock?: TotpClock;
}): Promise<TotpWrongEnrollmentEvidence> {
  const signedIn = await input.authenticate(input.username, input.password);
  if (signedIn.kind !== "authenticated") {
    return {
      outcomeKind: "rejected",
      ...rejectionFields(signedIn),
    };
  }

  const secret = await input.associateSoftwareToken(
    signedIn.tokens.accessToken,
  );
  const wrong = await input.verifySoftwareToken({
    accessToken: signedIn.tokens.accessToken,
    code: alterTotpCode(generateTotpCode(secret, input.clock)),
  });
  if (wrong.kind === "verified") {
    return { outcomeKind: "verified" };
  }
  return {
    outcomeKind: "rejected",
    rejectionReason: wrong.rejection.reason,
    ...(wrong.rejection.diagnostic.providerCode
      ? { providerCode: wrong.rejection.diagnostic.providerCode }
      : {}),
  };
}

export async function runTotpWrongSignInScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  associateSoftwareToken: (accessToken: string) => Promise<string>;
  verifySoftwareToken: (
    input: VerifySoftwareTokenInput,
  ) => Promise<VerifySoftwareTokenResult>;
  setSoftwareTokenMfaPreferred: (accessToken: string) => Promise<void>;
  respondToSoftwareTokenMfa: (
    input: SoftwareTokenMfaChallengeInput,
  ) => Promise<AuthenticationOutcome>;
  verifiers: ProfileTokenVerifiers;
  username: string;
  password: string;
  clock?: TotpClock;
}): Promise<TotpWrongSignInEvidence> {
  const enrolled = await enrollSoftwareTokenMfa(input);
  if (!enrolled.ok) {
    return {
      wrongCodeRejected: false,
      recovered: false,
      accessVerified: null,
      idVerified: null,
      ...(enrolled.providerCode ? { providerCode: enrolled.providerCode } : {}),
    };
  }

  const wrongChallenge = await input.authenticate(
    input.username,
    input.password,
  );
  if (
    wrongChallenge.kind !== "challenged" ||
    wrongChallenge.challenge.type !== "software-token-mfa"
  ) {
    return {
      wrongCodeRejected: false,
      recovered: false,
      accessVerified: null,
      idVerified: null,
    };
  }

  const wrong = await input.respondToSoftwareTokenMfa({
    session: wrongChallenge.challenge.continuation.session,
    username: wrongChallenge.challenge.continuation.username,
    code: alterTotpCode(generateTotpCode(enrolled.secret, input.clock)),
  });
  const wrongCodeRejected =
    wrong.kind === "rejected" && wrong.rejection.reason === "invalid-code";
  const providerCode =
    wrong.kind === "rejected"
      ? wrong.rejection.diagnostic.providerCode
      : undefined;

  await waitForMinimumStepRemainder(input.clock);
  const fresh = await input.authenticate(input.username, input.password);
  if (
    fresh.kind !== "challenged" ||
    fresh.challenge.type !== "software-token-mfa"
  ) {
    return {
      wrongCodeRejected,
      wrongCodeReason:
        wrong.kind === "rejected" ? wrong.rejection.reason : undefined,
      recovered: false,
      accessVerified: null,
      idVerified: null,
      ...(providerCode ? { providerCode } : {}),
    };
  }

  const recovered = await input.respondToSoftwareTokenMfa({
    session: fresh.challenge.continuation.session,
    username: fresh.challenge.continuation.username,
    code: generateTotpCode(enrolled.secret, input.clock),
  });
  if (recovered.kind !== "authenticated") {
    return {
      wrongCodeRejected,
      wrongCodeReason:
        wrong.kind === "rejected" ? wrong.rejection.reason : undefined,
      recovered: false,
      accessVerified: null,
      idVerified: null,
      ...(providerCode ? { providerCode } : {}),
    };
  }

  return {
    wrongCodeRejected,
    wrongCodeReason:
      wrong.kind === "rejected" ? wrong.rejection.reason : undefined,
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

export async function runTotpReusedCodeScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  associateSoftwareToken: (accessToken: string) => Promise<string>;
  verifySoftwareToken: (
    input: VerifySoftwareTokenInput,
  ) => Promise<VerifySoftwareTokenResult>;
  setSoftwareTokenMfaPreferred: (accessToken: string) => Promise<void>;
  respondToSoftwareTokenMfa: (
    input: SoftwareTokenMfaChallengeInput,
  ) => Promise<AuthenticationOutcome>;
  username: string;
  password: string;
  clock?: TotpClock;
}): Promise<TotpReusedCodeEvidence> {
  const enrolled = await enrollSoftwareTokenMfa(input);
  if (!enrolled.ok) {
    return {
      reuseRejected: false,
      ...(enrolled.providerCode ? { providerCode: enrolled.providerCode } : {}),
    };
  }

  await waitForMinimumStepRemainder(input.clock);
  const firstChallenge = await input.authenticate(
    input.username,
    input.password,
  );
  if (
    firstChallenge.kind !== "challenged" ||
    firstChallenge.challenge.type !== "software-token-mfa"
  ) {
    return { reuseRejected: false };
  }

  const code = generateTotpCode(enrolled.secret, input.clock);
  const first = await input.respondToSoftwareTokenMfa({
    session: firstChallenge.challenge.continuation.session,
    username: firstChallenge.challenge.continuation.username,
    code,
  });
  if (first.kind !== "authenticated") {
    return {
      reuseRejected: false,
      ...rejectionFields(first),
    };
  }

  const reuseChallenge = await input.authenticate(
    input.username,
    input.password,
  );
  if (
    reuseChallenge.kind !== "challenged" ||
    reuseChallenge.challenge.type !== "software-token-mfa"
  ) {
    return { reuseRejected: false };
  }

  const reused = await input.respondToSoftwareTokenMfa({
    session: reuseChallenge.challenge.continuation.session,
    username: reuseChallenge.challenge.continuation.username,
    code,
  });
  if (reused.kind !== "rejected") {
    return { reuseRejected: false };
  }
  return {
    reuseRejected:
      reused.rejection.reason === "expired-code" ||
      reused.rejection.reason === "invalid-code",
    rejectionReason: reused.rejection.reason,
    ...(reused.rejection.diagnostic.providerCode
      ? { providerCode: reused.rejection.diagnostic.providerCode }
      : {}),
  };
}

async function enrollSoftwareTokenMfa(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  associateSoftwareToken: (accessToken: string) => Promise<string>;
  verifySoftwareToken: (
    input: VerifySoftwareTokenInput,
  ) => Promise<VerifySoftwareTokenResult>;
  setSoftwareTokenMfaPreferred: (accessToken: string) => Promise<void>;
  username: string;
  password: string;
  clock?: TotpClock;
}): Promise<
  | { ok: true; secret: string }
  | { ok: false; providerCode?: string }
> {
  const signedIn = await input.authenticate(input.username, input.password);
  if (signedIn.kind !== "authenticated") {
    return {
      ok: false,
      ...(signedIn.kind === "rejected" &&
      signedIn.rejection.diagnostic.providerCode
        ? { providerCode: signedIn.rejection.diagnostic.providerCode }
        : {}),
    };
  }

  const secret = await input.associateSoftwareToken(
    signedIn.tokens.accessToken,
  );
  await waitForMinimumStepRemainder(input.clock);
  const verified = await input.verifySoftwareToken({
    accessToken: signedIn.tokens.accessToken,
    code: generateTotpCode(secret, input.clock),
  });
  if (verified.kind !== "verified") {
    return {
      ok: false,
      ...(verified.rejection.diagnostic.providerCode
        ? { providerCode: verified.rejection.diagnostic.providerCode }
        : {}),
    };
  }

  await input.setSoftwareTokenMfaPreferred(signedIn.tokens.accessToken);
  await waitForNextTotpStep(input.clock);
  return { ok: true, secret };
}

function rejectionFields(
  outcome: AuthenticationOutcome,
): Pick<TotpEnrollmentEvidence, "rejectionReason" | "providerCode"> {
  if (outcome.kind !== "rejected") {
    return {};
  }
  return {
    rejectionReason: outcome.rejection.reason,
    ...(outcome.rejection.diagnostic.providerCode
      ? { providerCode: outcome.rejection.diagnostic.providerCode }
      : {}),
  };
}
