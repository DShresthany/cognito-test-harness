import {
  OperationalAuthenticationFailure,
  type AuthenticationOutcome,
  type AuthenticationRejectionReason,
} from "./authenticationOutcome.js";
import type { ProfileTokenVerifiers } from "./jwtVerifier.js";

export type RefreshScenarioEvidence = {
  outcomeKind: "authenticated" | "challenged" | "rejected";
  rejectionReason?: AuthenticationRejectionReason;
  accessVerified: boolean | null;
  idVerified: boolean | null;
  subjectMatches: boolean | null;
  tokensRenewed: boolean | null;
  refreshTokenReplaced: boolean | null;
  providerCode?: string;
};

export function toRefreshScenarioEvidence(
  outcome: AuthenticationOutcome,
  options: {
    accessVerified?: boolean;
    idVerified?: boolean;
    subjectMatches?: boolean;
    tokensRenewed?: boolean;
  } = {},
): RefreshScenarioEvidence {
  if (outcome.kind === "authenticated") {
    return {
      outcomeKind: "authenticated",
      accessVerified: options.accessVerified ?? null,
      idVerified: options.idVerified ?? null,
      subjectMatches: options.subjectMatches ?? null,
      tokensRenewed: options.tokensRenewed ?? null,
      refreshTokenReplaced: Boolean(outcome.tokens.refreshToken),
    };
  }
  if (outcome.kind === "challenged") {
    return {
      outcomeKind: "challenged",
      accessVerified: null,
      idVerified: null,
      subjectMatches: null,
      tokensRenewed: null,
      refreshTokenReplaced: null,
    };
  }
  return {
    outcomeKind: "rejected",
    rejectionReason: outcome.rejection.reason,
    accessVerified: null,
    idVerified: null,
    subjectMatches: null,
    tokensRenewed: null,
    refreshTokenReplaced: null,
    ...(outcome.rejection.diagnostic.providerCode
      ? { providerCode: outcome.rejection.diagnostic.providerCode }
      : {}),
  };
}

export async function runValidRefreshScenario(input: {
  authenticate: (
    username: string,
    password: string,
  ) => Promise<AuthenticationOutcome>;
  refresh: (refreshToken: string) => Promise<AuthenticationOutcome>;
  verifiers: ProfileTokenVerifiers;
  username: string;
  password: string;
}): Promise<RefreshScenarioEvidence> {
  const signIn = await input.authenticate(input.username, input.password);
  if (signIn.kind !== "authenticated" || !signIn.tokens.refreshToken) {
    return toRefreshScenarioEvidence(signIn);
  }

  const previousAccess = await input.verifiers.access.verify(
    signIn.tokens.accessToken,
  );
  const previousId = await input.verifiers.id.verify(signIn.tokens.idToken);
  const refreshToken = signIn.tokens.refreshToken;

  const refreshed = await input.refresh(refreshToken);
  if (refreshed.kind !== "authenticated") {
    return toRefreshScenarioEvidence(refreshed);
  }

  const access = await verifyClaims(
    input.verifiers.access.verify(refreshed.tokens.accessToken),
  );
  const id = await verifyClaims(
    input.verifiers.id.verify(refreshed.tokens.idToken),
  );

  const accessVerified = access !== null;
  const idVerified = id !== null;
  const subjectMatches =
    access !== null &&
    id !== null &&
    access.sub === previousAccess.sub &&
    id.sub === previousId.sub &&
    previousAccess.sub === previousId.sub;
  const tokensRenewed =
    access !== null &&
    id !== null &&
    Boolean(previousAccess.jti) &&
    Boolean(previousId.jti) &&
    Boolean(access.jti) &&
    Boolean(id.jti) &&
    access.jti !== previousAccess.jti &&
    id.jti !== previousId.jti;

  return toRefreshScenarioEvidence(refreshed, {
    accessVerified,
    idVerified,
    subjectMatches,
    tokensRenewed,
  });
}

export async function runRejectedRefreshScenario(input: {
  refresh: (refreshToken: string) => Promise<AuthenticationOutcome>;
  refreshToken: string;
}): Promise<RefreshScenarioEvidence> {
  const outcome = await input.refresh(input.refreshToken);
  return toRefreshScenarioEvidence(outcome);
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
