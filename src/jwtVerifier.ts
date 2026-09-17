import { CognitoJwtVerifier } from "aws-jwt-verify";
import {
  FetchError,
  NonRetryableFetchError,
  WaitPeriodNotYetEndedJwkError,
} from "aws-jwt-verify/error";
import { OperationalAuthenticationFailure } from "./authenticationOutcome.js";
import { required } from "./cognitoAuth.js";

export function createAccessTokenVerifier() {
  return CognitoJwtVerifier.create({
    userPoolId: required("COGNITO_USER_POOL_ID"),
    tokenUse: "access",
    clientId: required("COGNITO_CLIENT_ID"),
  });
}

export function wrapAccessTokenVerifier(verifier: {
  verify(accessToken: string): Promise<{ sub: string; username: string }>;
}): {
  verify(accessToken: string): Promise<{ sub: string; username: string }>;
} {
  return {
    async verify(accessToken) {
      try {
        const payload = await verifier.verify(accessToken);
        return { sub: payload.sub, username: payload.username };
      } catch (error) {
        if (error instanceof NonRetryableFetchError) {
          throw new OperationalAuthenticationFailure({
            category: "configuration",
            operation: "verify-access-token",
            retryable: false,
            cause: error,
          });
        }
        if (isRetryableJwksFailure(error)) {
          throw new OperationalAuthenticationFailure({
            category: "network",
            operation: "verify-access-token",
            retryable: true,
            cause: error,
          });
        }
        throw error;
      }
    },
  };
}

export function createAccessTokenVerifierPort(): {
  verify(accessToken: string): Promise<{ sub: string; username: string }>;
} {
  return wrapAccessTokenVerifier(createAccessTokenVerifier());
}

function isRetryableJwksFailure(error: unknown): boolean {
  if (error instanceof WaitPeriodNotYetEndedJwkError) {
    return true;
  }
  return error instanceof FetchError;
}
