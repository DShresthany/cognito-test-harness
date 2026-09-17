import { describe, expect, it } from "vitest";
import { FetchError, NonRetryableFetchError } from "aws-jwt-verify/error";
import { OperationalAuthenticationFailure } from "../../src/authenticationOutcome.js";
import { wrapAccessTokenVerifier } from "../../src/jwtVerifier.js";

describe("wrapAccessTokenVerifier", () => {
  it("maps retryable JWKS fetch failure to a retryable operational failure", async () => {
    const verifier = wrapAccessTokenVerifier({
      async verify() {
        throw new FetchError("https://example.invalid/jwks", "network down");
      },
    });

    await expect(verifier.verify("access-token")).rejects.toMatchObject({
      name: "OperationalAuthenticationFailure",
      category: "network",
      operation: "verify-access-token",
      retryable: true,
    });
    await expect(verifier.verify("access-token")).rejects.toBeInstanceOf(
      OperationalAuthenticationFailure,
    );
  });

  it("maps a non-retryable JWKS fetch failure to a non-retryable operational failure", async () => {
    const verifier = wrapAccessTokenVerifier({
      async verify() {
        throw new NonRetryableFetchError(
          "https://example.invalid/jwks",
          "bad jwks",
        );
      },
    });

    await expect(verifier.verify("access-token")).rejects.toMatchObject({
      name: "OperationalAuthenticationFailure",
      category: "configuration",
      operation: "verify-access-token",
      retryable: false,
    });
  });
});
