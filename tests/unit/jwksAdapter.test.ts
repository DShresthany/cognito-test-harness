import { describe, expect, it, vi } from "vitest";
import { createJwksAdapter, UnknownSigningKeyFailure } from "../../src/jwksAdapter.js";

const jwkA = { kid: "kid-a", kty: "RSA", n: "n-a", e: "AQAB" };
const jwkB = { kid: "kid-b", kty: "RSA", n: "n-b", e: "AQAB" };

describe("createJwksAdapter", () => {
  it("returns a cached key without refetching", async () => {
    const fetchJwks = vi.fn().mockResolvedValue({ keys: [jwkA] });
    const adapter = createJwksAdapter({ fetchJwks, jwksUri: "https://example/.well-known/jwks.json" });

    await expect(adapter.resolveKey("kid-a")).resolves.toEqual(jwkA);
    await expect(adapter.resolveKey("kid-a")).resolves.toEqual(jwkA);
    expect(fetchJwks).toHaveBeenCalledTimes(1);
  });

  it("refreshes JWKS once when the kid is missing from cache", async () => {
    const fetchJwks = vi
      .fn()
      .mockResolvedValueOnce({ keys: [jwkA] })
      .mockResolvedValueOnce({ keys: [jwkA, jwkB] });
    const adapter = createJwksAdapter({ fetchJwks, jwksUri: "https://example/.well-known/jwks.json" });

    await adapter.resolveKey("kid-a");
    await expect(adapter.resolveKey("kid-b")).resolves.toEqual(jwkB);
    expect(fetchJwks).toHaveBeenCalledTimes(2);
  });

  it("fails without a second refresh when the kid is still missing", async () => {
    const fetchJwks = vi.fn().mockResolvedValue({ keys: [jwkA] });
    const adapter = createJwksAdapter({ fetchJwks, jwksUri: "https://example/.well-known/jwks.json" });

    await adapter.resolveKey("kid-a");
    await expect(adapter.resolveKey("kid-missing")).rejects.toBeInstanceOf(
      UnknownSigningKeyFailure,
    );
    expect(fetchJwks).toHaveBeenCalledTimes(2);
  });

  it("maps a JWKS fetch failure to a retryable network operational failure", async () => {
    const fetchJwks = vi.fn().mockRejectedValue(new Error("ECONNRESET"));
    const adapter = createJwksAdapter({ fetchJwks, jwksUri: "https://example/.well-known/jwks.json" });

    await expect(adapter.resolveKey("kid-a")).rejects.toMatchObject({
      name: "OperationalAuthenticationFailure",
      category: "network",
      retryable: true,
      operation: "verify-access-token",
    });
    expect(fetchJwks).toHaveBeenCalledTimes(1);
  });
});
