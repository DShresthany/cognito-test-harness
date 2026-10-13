import {
  OperationalAuthenticationFailure,
  type AuthenticationOutcome,
  type AuthenticationRejectionReason,
} from "./authenticationOutcome.js";
import type { CognitoCommandSender } from "./cognitoAdminAuthDriver.js";
import {
  CognitoUserPoolAuthDriver,
  type PublicUserPoolAuthProfile,
} from "./cognitoUserPoolAuthDriver.js";
import type {
  AccessTokenClaims,
  IdTokenClaims,
  ProfileTokenVerifiers,
} from "./jwtVerifier.js";
import type { LineageFingerprinter } from "./lineageFingerprint.js";
import { finalizeScenario, type ScenarioTokenHandles } from "./scenarioFinalizer.js";

export type RotationGenerationLabel = "initial" | "rotated";

export type RotationGenerationEvidence = {
  label: RotationGenerationLabel;
  accessOriginJtiFingerprint: string | null;
  idOriginJtiFingerprint: string | null;
  accessJtiFingerprint: string | null;
  idJtiFingerprint: string | null;
};

export type PublicZeroGraceRotationEvidence = {
  initialOutcomeKind: AuthenticationOutcome["kind"];
  initialRejectionReason?: AuthenticationRejectionReason;
  rotationOutcomeKind: AuthenticationOutcome["kind"] | null;
  rotationRejectionReason?: AuthenticationRejectionReason;
  reuseOutcomeKind: AuthenticationOutcome["kind"] | null;
  reuseRejectionReason?: AuthenticationRejectionReason;
  reuseProviderCode?: string;
  initialRefreshPresent: boolean | null;
  replacementRefreshPresent: boolean | null;
  accessVerified: boolean | null;
  idVerified: boolean | null;
  subjectMatches: boolean | null;
  originJtiFingerprintStable: boolean | null;
  jtiFingerprintsUnique: boolean | null;
  generations: RotationGenerationEvidence[];
};

export async function runPublicZeroGraceRotationScenario(input: {
  sender: CognitoCommandSender;
  profile: PublicUserPoolAuthProfile;
  verifiers: ProfileTokenVerifiers;
  username: string;
  password: string;
  fingerprinter: LineageFingerprinter;
  deletePersona: () => Promise<void>;
}): Promise<PublicZeroGraceRotationEvidence> {
  const driver = new CognitoUserPoolAuthDriver(input.sender, input.profile);
  const handles: ScenarioTokenHandles = { refreshTokens: [] };

  let revokedCurrentRefreshToken = false;
  let revokeIndex = 0;
  const refreshTokenCount = () => handles.refreshTokens.length;
  try {
    return await runRotation(input, driver, handles);
  } finally {
    const knownRefreshTokens = refreshTokenCount();
    await finalizeScenario(handles, {
      revokeRefreshToken: async (refreshToken) => {
        const isCurrent = revokeIndex === knownRefreshTokens - 1;
        revokeIndex += 1;
        const revoked = await revokeForCleanup(driver, refreshToken, !isCurrent);
        if (revoked && isCurrent) {
          revokedCurrentRefreshToken = true;
        }
      },
      globalSignOut: (accessToken) =>
        signOutForCleanup(driver, accessToken, revokedCurrentRefreshToken),
      deletePersona: input.deletePersona,
    });
  }
}

async function runRotation(
  input: {
    verifiers: ProfileTokenVerifiers;
    username: string;
    password: string;
    fingerprinter: LineageFingerprinter;
  },
  driver: CognitoUserPoolAuthDriver,
  handles: ScenarioTokenHandles,
): Promise<PublicZeroGraceRotationEvidence> {
  const signIn = await driver.authenticatePassword(input.username, input.password);
  if (signIn.kind !== "authenticated" || !signIn.tokens.refreshToken) {
    if (signIn.kind === "authenticated") {
      handles.accessToken = signIn.tokens.accessToken;
    }
    return evidenceFromInitial(signIn);
  }

  const initialRefreshToken = signIn.tokens.refreshToken;
  handles.refreshTokens.push(initialRefreshToken);
  handles.accessToken = signIn.tokens.accessToken;

  const initialAccess = await verifyClaims(
    input.verifiers.access.verify(signIn.tokens.accessToken),
  );
  const initialId = await verifyClaims(
    input.verifiers.id.verify(signIn.tokens.idToken),
  );
  const initialGeneration = generationEvidence(
    "initial",
    initialAccess,
    initialId,
    input.fingerprinter,
  );

  const rotated = await driver.rotateRefreshToken(initialRefreshToken);
  if (rotated.kind !== "authenticated") {
    return {
      initialOutcomeKind: "authenticated",
      initialRefreshPresent: true,
      rotationOutcomeKind: rotated.kind,
      ...rejectionFields("rotationRejectionReason", rotated),
      reuseOutcomeKind: null,
      replacementRefreshPresent: null,
      accessVerified: null,
      idVerified: null,
      subjectMatches: null,
      originJtiFingerprintStable: null,
      jtiFingerprintsUnique: null,
      generations: [initialGeneration],
    };
  }

  if (rotated.tokens.refreshToken) {
    handles.refreshTokens.push(rotated.tokens.refreshToken);
  }
  handles.accessToken = rotated.tokens.accessToken;

  const rotatedAccess = await verifyClaims(
    input.verifiers.access.verify(rotated.tokens.accessToken),
  );
  const rotatedId = await verifyClaims(
    input.verifiers.id.verify(rotated.tokens.idToken),
  );
  const generations = [
    initialGeneration,
    generationEvidence("rotated", rotatedAccess, rotatedId, input.fingerprinter),
  ];

  const reuse = await driver.rotateRefreshToken(initialRefreshToken);
  return {
    initialOutcomeKind: "authenticated",
    initialRefreshPresent: true,
    rotationOutcomeKind: "authenticated",
    replacementRefreshPresent: Boolean(rotated.tokens.refreshToken),
    reuseOutcomeKind: reuse.kind,
    ...rejectionFields("reuseRejectionReason", reuse),
    accessVerified: rotatedAccess !== null,
    idVerified: rotatedId !== null,
    subjectMatches: subjectsMatch(
      initialAccess,
      initialId,
      rotatedAccess,
      rotatedId,
    ),
    originJtiFingerprintStable: originsStable(generations),
    jtiFingerprintsUnique: jtisUnique(generations),
    generations,
  };
}

function evidenceFromInitial(
  signIn: AuthenticationOutcome,
): PublicZeroGraceRotationEvidence {
  return {
    initialOutcomeKind: signIn.kind,
    ...rejectionFields("initialRejectionReason", signIn),
    rotationOutcomeKind: null,
    reuseOutcomeKind: null,
    initialRefreshPresent:
      signIn.kind === "authenticated" ? Boolean(signIn.tokens.refreshToken) : null,
    replacementRefreshPresent: null,
    accessVerified: null,
    idVerified: null,
    subjectMatches: null,
    originJtiFingerprintStable: null,
    jtiFingerprintsUnique: null,
    generations: [],
  };
}

function rejectionFields(
  reasonKey: "initialRejectionReason" | "rotationRejectionReason" | "reuseRejectionReason",
  outcome: AuthenticationOutcome,
): Partial<
  Pick<
    PublicZeroGraceRotationEvidence,
    | "initialRejectionReason"
    | "rotationRejectionReason"
    | "reuseRejectionReason"
    | "reuseProviderCode"
  >
> {
  switch (outcome.kind) {
    case "rejected":
      return {
        [reasonKey]: outcome.rejection.reason,
        ...(reasonKey === "reuseRejectionReason" &&
        outcome.rejection.diagnostic.providerCode
          ? { reuseProviderCode: outcome.rejection.diagnostic.providerCode }
          : {}),
      };
    case "authenticated":
    case "challenged":
      return {};
    default: {
      const exhaustive: never = outcome;
      return exhaustive;
    }
  }
}

function generationEvidence(
  label: RotationGenerationLabel,
  access: AccessTokenClaims | null,
  id: IdTokenClaims | null,
  fingerprinter: LineageFingerprinter,
): RotationGenerationEvidence {
  return {
    label,
    accessOriginJtiFingerprint: fingerprintOf(fingerprinter, access?.origin_jti),
    idOriginJtiFingerprint: fingerprintOf(fingerprinter, id?.origin_jti),
    accessJtiFingerprint: fingerprintOf(fingerprinter, access?.jti),
    idJtiFingerprint: fingerprintOf(fingerprinter, id?.jti),
  };
}

function fingerprintOf(
  fingerprinter: LineageFingerprinter,
  identifier: string | undefined,
): string | null {
  if (identifier === undefined) {
    return null;
  }
  return fingerprinter.fingerprint(identifier);
}

function originsStable(generations: RotationGenerationEvidence[]): boolean {
  const present = completeFingerprints(
    generations.flatMap((generation) => [
      generation.accessOriginJtiFingerprint,
      generation.idOriginJtiFingerprint,
    ]),
  );
  if (present === null) {
    return false;
  }
  return present.every((fingerprint) => fingerprint === present[0]);
}

function jtisUnique(generations: RotationGenerationEvidence[]): boolean {
  const present = completeFingerprints(
    generations.flatMap((generation) => [
      generation.accessJtiFingerprint,
      generation.idJtiFingerprint,
    ]),
  );
  if (present === null) {
    return false;
  }
  return new Set(present).size === present.length;
}

function completeFingerprints(
  fingerprints: Array<string | null>,
): string[] | null {
  if (fingerprints.length === 0 || fingerprints.some((fingerprint) => fingerprint === null)) {
    return null;
  }
  return fingerprints.filter((fingerprint): fingerprint is string => fingerprint !== null);
}

function subjectsMatch(
  initialAccess: AccessTokenClaims | null,
  initialId: IdTokenClaims | null,
  rotatedAccess: AccessTokenClaims | null,
  rotatedId: IdTokenClaims | null,
): boolean {
  if (!initialAccess || !initialId || !rotatedAccess || !rotatedId) {
    return false;
  }
  return (
    initialAccess.sub === initialId.sub &&
    initialAccess.sub === rotatedAccess.sub &&
    initialAccess.sub === rotatedId.sub
  );
}

async function revokeForCleanup(
  driver: CognitoUserPoolAuthDriver,
  refreshToken: string,
  alreadyInvalidIsDone: boolean,
): Promise<boolean> {
  const result = await driver.revokeRefreshToken(refreshToken);
  switch (result.kind) {
    case "revoked":
      return true;
    case "rejected":
      if (
        alreadyInvalidIsDone &&
        result.rejection.reason === "invalid-refresh-token"
      ) {
        return false;
      }
      throw new Error("refresh token revocation rejected");
    default: {
      const exhaustive: never = result;
      throw new Error(
        `refresh token revocation rejected: ${String(exhaustive)}`,
      );
    }
  }
}

async function signOutForCleanup(
  driver: CognitoUserPoolAuthDriver,
  accessToken: string,
  currentRefreshTokenRevoked: boolean,
): Promise<void> {
  const result = await driver.globalSignOut(accessToken);
  switch (result.kind) {
    case "signed-out":
      return;
    case "rejected":
      if (
        currentRefreshTokenRevoked &&
        result.rejection.reason === "invalid-access-token"
      ) {
        return;
      }
      throw new Error("global sign-out rejected");
    default: {
      const exhaustive: never = result;
      throw new Error(`global sign-out rejected: ${String(exhaustive)}`);
    }
  }
}

async function verifyClaims<T>(promise: Promise<T>): Promise<T | null> {
  try {
    return await promise;
  } catch (error) {
    if (error instanceof OperationalAuthenticationFailure) {
      throw error;
    }
    return null;
  }
}
