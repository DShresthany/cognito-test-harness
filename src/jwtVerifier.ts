import { CognitoJwtVerifier } from "aws-jwt-verify";
import {
  FetchError,
  NonRetryableFetchError,
  WaitPeriodNotYetEndedJwkError,
} from "aws-jwt-verify/error";
import { OperationalAuthenticationFailure } from "./authenticationOutcome.js";

export type AccessTokenClaims = {
  sub: string;
  username: string;
  jti?: string;
  origin_jti?: string;
  iat?: number;
};
export type IdTokenClaims = {
  sub: string;
  email?: string;
  jti?: string;
  origin_jti?: string;
  iat?: number;
};


export type TokenVerifierPort<TClaims> = {
  verify(token: string): Promise<TClaims>;
};

export type ProfileTokenVerifiers = {
  access: TokenVerifierPort<AccessTokenClaims>;
  id: TokenVerifierPort<IdTokenClaims>;
};

export function createAccessTokenVerifier(input: {
  userPoolId: string;
  clientId: string;
}) {
  return CognitoJwtVerifier.create({
    userPoolId: input.userPoolId,
    tokenUse: "access",
    clientId: input.clientId,
  });
}

export function createIdTokenVerifier(input: {
  userPoolId: string;
  clientId: string;
}) {
  return CognitoJwtVerifier.create({
    userPoolId: input.userPoolId,
    tokenUse: "id",
    clientId: input.clientId,
  });
}

export function wrapAccessTokenVerifier(verifier: {
  verify(accessToken: string): Promise<{
    sub: string;
    username: string;
    jti?: string;
    origin_jti?: string;
    iat?: number;
  }>;
}): TokenVerifierPort<AccessTokenClaims> {
  return wrapTokenVerifier(verifier, "verify-access-token", (claims) => ({
    sub: claims.sub,
    username: claims.username,
    ...optionalClaim("jti", claims.jti),
    ...optionalClaim("origin_jti", claims.origin_jti),
    ...optionalNumber("iat", claims.iat),
  }));
}

export function wrapIdTokenVerifier(verifier: {
  verify(idToken: string): Promise<{
    sub: string;
    email?: string;
    jti?: string;
    origin_jti?: string;
    iat?: number;
  }>;
}): TokenVerifierPort<IdTokenClaims> {
  return wrapTokenVerifier(verifier, "verify-id-token", (claims) => ({
    sub: claims.sub,
    ...optionalClaim("email", claims.email),
    ...optionalClaim("jti", claims.jti),
    ...optionalClaim("origin_jti", claims.origin_jti),
    ...optionalNumber("iat", claims.iat),
  }));
}

export function createAccessTokenVerifierPort(input: {
  userPoolId: string;
  clientId: string;
}): TokenVerifierPort<AccessTokenClaims> {
  return wrapAccessTokenVerifier(createAccessTokenVerifier(input));
}

export function createIdTokenVerifierPort(input: {
  userPoolId: string;
  clientId: string;
}): TokenVerifierPort<IdTokenClaims> {
  return wrapIdTokenVerifier(createIdTokenVerifier(input));
}

export function createProfileTokenVerifiers(input: {
  userPoolId: string;
  clientId: string;
}): ProfileTokenVerifiers {
  return {
    access: createAccessTokenVerifierPort(input),
    id: createIdTokenVerifierPort(input),
  };
}

function wrapTokenVerifier<TClaims, TVerified>(
  verifier: { verify(token: string): Promise<TVerified> },
  operation: "verify-access-token" | "verify-id-token",
  project: (claims: TVerified) => TClaims,
): TokenVerifierPort<TClaims> {
  return {
    async verify(token) {
      try {
        return project(await verifier.verify(token));
      } catch (error) {
        if (error instanceof NonRetryableFetchError) {
          throw new OperationalAuthenticationFailure({
            category: "configuration",
            operation,
            retryable: false,
            cause: error,
          });
        }
        if (isRetryableJwksFailure(error)) {
          throw new OperationalAuthenticationFailure({
            category: "network",
            operation,
            retryable: true,
            cause: error,
          });
        }
        throw error;
      }
    },
  };
}

function optionalClaim(
  key: string,
  value: string | undefined,
): Record<string, string> {
  if (value === undefined) {
    return {};
  }
  return { [key]: value };
}

function optionalNumber(
  key: string,
  value: number | undefined,
): Record<string, number> {
  if (value === undefined) {
    return {};
  }
  return { [key]: value };
}

function isRetryableJwksFailure(error: unknown): boolean {
  if (error instanceof WaitPeriodNotYetEndedJwkError) {
    return true;
  }
  return error instanceof FetchError;
}
