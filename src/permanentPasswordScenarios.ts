import type {
  AuthenticationOutcome,
  AuthenticationRejectionReason,
  CognitoTokenSet,
} from "./authenticationOutcome.js";
import type { ProfileTokenVerifiers } from "./jwtVerifier.js";

export type PasswordScenarioEvidence = {
  outcomeKind: "authenticated" | "challenged" | "rejected";
  rejectionReason?: AuthenticationRejectionReason;
  refreshTokenIssued: boolean;
  accessVerified: boolean | null;
  idVerified: boolean | null;
  providerCode?: string;
};

export type TokenVerificationEvidence = {
  accessVerifiesOnAccess: boolean;
  idVerifiesOnId: boolean;
  accessRejectedAsId: boolean;
  idRejectedAsAccess: boolean;
  tamperedAccessRejected: boolean;
  tamperedIdRejected: boolean;
  crossProfileAccessRejected: boolean;
};

export function toPasswordScenarioEvidence(
  outcome: AuthenticationOutcome,
  options: {
    accessVerified?: boolean;
    idVerified?: boolean;
  } = {},
): PasswordScenarioEvidence {
  if (outcome.kind === "authenticated") {
    return {
      outcomeKind: "authenticated",
      refreshTokenIssued: Boolean(outcome.tokens.refreshToken),
      accessVerified: options.accessVerified ?? null,
      idVerified: options.idVerified ?? null,
    };
  }
  if (outcome.kind === "challenged") {
    return {
      outcomeKind: "challenged",
      refreshTokenIssued: false,
      accessVerified: null,
      idVerified: null,
    };
  }
  return {
    outcomeKind: "rejected",
    rejectionReason: outcome.rejection.reason,
    refreshTokenIssued: false,
    accessVerified: null,
    idVerified: null,
    ...(outcome.rejection.diagnostic.providerCode
      ? { providerCode: outcome.rejection.diagnostic.providerCode }
      : {}),
  };
}

export async function runValidPermanentPasswordScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  verifiers: ProfileTokenVerifiers;
  username: string;
  password: string;
}): Promise<PasswordScenarioEvidence> {
  const outcome = await input.authenticate(input.username, input.password);
  if (outcome.kind !== "authenticated") {
    return toPasswordScenarioEvidence(outcome);
  }

  const accessVerified = await verifyQuietly(
    input.verifiers.access.verify(outcome.tokens.accessToken),
  );
  const idVerified = await verifyQuietly(
    input.verifiers.id.verify(outcome.tokens.idToken),
  );

  return toPasswordScenarioEvidence(outcome, { accessVerified, idVerified });
}

export async function runRejectedPasswordScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  username: string;
  password: string;
}): Promise<PasswordScenarioEvidence> {
  const outcome = await input.authenticate(input.username, input.password);
  return toPasswordScenarioEvidence(outcome);
}

export async function runTokenVerificationScenario(input: {
  tokens: CognitoTokenSet;
  issuing: ProfileTokenVerifiers;
  otherProfile: ProfileTokenVerifiers;
}): Promise<TokenVerificationEvidence> {
  const { tokens, issuing, otherProfile } = input;
  if (!tokens.refreshToken) {
    throw new Error("token verification scenario requires a refresh token");
  }
  // Refresh stays opaque: never pass it to JWT verifiers.
  const tamperedAccess = tamperJwt(tokens.accessToken);
  const tamperedId = tamperJwt(tokens.idToken);

  return {
    accessVerifiesOnAccess: await verifyQuietly(
      issuing.access.verify(tokens.accessToken),
    ),
    idVerifiesOnId: await verifyQuietly(issuing.id.verify(tokens.idToken)),
    accessRejectedAsId: !(await verifyQuietly(
      issuing.id.verify(tokens.accessToken),
    )),
    idRejectedAsAccess: !(await verifyQuietly(
      issuing.access.verify(tokens.idToken),
    )),
    tamperedAccessRejected: !(await verifyQuietly(
      issuing.access.verify(tamperedAccess),
    )),
    tamperedIdRejected: !(await verifyQuietly(issuing.id.verify(tamperedId))),
    crossProfileAccessRejected: !(await verifyQuietly(
      otherProfile.access.verify(tokens.accessToken),
    )),
  };
}

async function verifyQuietly(promise: Promise<unknown>): Promise<boolean> {
  try {
    await promise;
    return true;
  } catch {
    return false;
  }
}

function tamperJwt(token: string): string {
  const parts = token.split(".");
  if (parts.length < 2) {
    return `${token}x`;
  }
  const payload = parts[1]!;
  const flipped = payload.endsWith("A")
    ? `${payload.slice(0, -1)}B`
    : `${payload.slice(0, -1)}A`;
  return `${parts[0]}.${flipped}.${parts.slice(2).join(".")}`;
}
