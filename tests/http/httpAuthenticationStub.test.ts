import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  OperationalAuthenticationFailure,
  type AuthenticationOutcome,
} from "../../src/authenticationOutcome.js";
import { createApp } from "../../src/app.js";
import {
  createAccessTokenVerifier,
  wrapAccessTokenVerifier,
} from "../../src/jwtVerifier.js";

const authenticated: AuthenticationOutcome = {
  kind: "authenticated",
  tokens: {
    accessToken: "access-token",
    idToken: "id-token",
    refreshToken: "refresh-token",
  },
};

function createStubApp(overrides?: {
  authenticate?: (username: string, password: string) => Promise<AuthenticationOutcome>;
  verify?: (token: string) => Promise<{ sub: string; username: string }>;
}) {
  const report = vi.fn();
  const app = createApp({
    authenticatePassword: {
      authenticate:
        overrides?.authenticate ??
        (async () => authenticated),
    },
    verifyAccessToken: {
      verify:
        overrides?.verify ??
        (async () => ({ sub: "sub-1", username: "user" })),
    },
    reportDiagnostic: { report },
  });
  return { app, report };
}

const TEST_USER_POOL_ID = "us-east-1_TestPool1";
const TEST_ISSUER = `https://cognito-idp.us-east-1.amazonaws.com/${TEST_USER_POOL_ID}`;
const TEST_CLIENT_ID = "test-client-id";
const TEST_KID = "test-signing-key";

function createStubAppWithRealAccessTokenVerifier() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const verifier = createAccessTokenVerifier({
    userPoolId: TEST_USER_POOL_ID,
    clientId: TEST_CLIENT_ID,
  });
  const { n, e } = publicKey.export({ format: "jwk" });
  if (!n || !e) {
    throw new Error("RSA public JWK is missing modulus or exponent");
  }
  verifier.cacheJwks({
    keys: [{ kty: "RSA", n, e, kid: TEST_KID, alg: "RS256", use: "sig" }],
  });
  const accessTokenVerifier = wrapAccessTokenVerifier(verifier);

  return {
    ...createStubApp({ verify: (token) => accessTokenVerifier.verify(token) }),
    signAccessToken: (expiresAtSeconds: number) =>
      signJwt(privateKey, {
        iss: TEST_ISSUER,
        token_use: "access",
        client_id: TEST_CLIENT_ID,
        sub: "sub-1",
        username: "persona",
        iat: expiresAtSeconds - 3600,
        exp: expiresAtSeconds,
      }),
  };
}

function signJwt(privateKey: KeyObject, payload: Record<string, unknown>) {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const signingInput = `${encode({ alg: "RS256", kid: TEST_KID, typ: "JWT" })}.${encode(payload)}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKey);
  return `${signingInput}.${signature.toString("base64url")}`;
}

describe("HTTP authentication stub", () => {
  it("returns access and ID tokens on authenticated without a refresh token", async () => {
    const { app } = createStubApp();

    const res = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "user@example.com",
        password: "Password1!",
      }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      accessToken: "access-token",
      idToken: "id-token",
    });
  });

  it("returns 400 when username or password is missing", async () => {
    const { app } = createStubApp();
    const res = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "user@example.com" }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "username and password required",
    });
  });

  it("returns 400 invalid request for malformed JSON", async () => {
    const { app } = createStubApp();
    const res = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not-json",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid request" });
  });

  it("collapses every authentication rejection to 401 invalid credentials", async () => {
    const reasons = [
      "invalid-credentials",
      "user-not-confirmed",
      "password-reset-required",
      "invalid-code",
      "expired-code",
      "invalid-refresh-token",
      "invalid-access-token",
      "invalid-challenge-session",
      "recovery-unavailable",
      "password-policy-violation",
      "too-many-failed-attempts",
    ] as const;

    for (const reason of reasons) {
      const { app } = createStubApp({
        authenticate: async () => ({
          kind: "rejected",
          rejection: {
            reason,
            diagnostic: { operation: "admin-initiate-auth" },
          },
        }),
      });
      const res = await app.request("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: "user@example.com",
          password: "Password1!",
        }),
      });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid credentials" });
    }
  });

  it("returns 409 when authentication is challenged without leaking the session", async () => {
    const { app, report } = createStubApp({
      authenticate: async () => ({
        kind: "challenged",
        challenge: {
          type: "new-password-required",
          requiredAttributes: [],
          continuation: {
            session: "challenge-session-secret" as never,
            username: "persona@example.com" as never,
            profileId: "admin-confidential" as never,
          },
        },
      }),
    });

    const res = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "user@example.com",
        password: "TempPass1!",
      }),
    });

    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body).toEqual({ error: "additional authentication required" });
    expect(JSON.stringify(body)).not.toContain("challenge-session-secret");
    expect(JSON.stringify(report.mock.calls)).not.toContain(
      "challenge-session-secret",
    );
  });

  it("maps retryable operational failure to 503 and non-retryable to 500", async () => {
    const retryable = createStubApp({
      authenticate: async () => {
        throw new OperationalAuthenticationFailure({
          category: "throttled",
          operation: "admin-initiate-auth",
          retryable: true,
        });
      },
    });
    const retryableRes = await retryable.app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "user@example.com",
        password: "Password1!",
      }),
    });
    expect(retryableRes.status).toBe(503);
    expect(await retryableRes.json()).toEqual({
      error: "authentication service unavailable",
    });

    const blocked = createStubApp({
      authenticate: async () => {
        throw new OperationalAuthenticationFailure({
          category: "request-blocked",
          operation: "admin-initiate-auth",
          retryable: false,
        });
      },
    });
    const blockedRes = await blocked.app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "user@example.com",
        password: "Password1!",
      }),
    });
    expect(blockedRes.status).toBe(500);
    expect(await blockedRes.json()).toEqual({
      error: "authentication service error",
    });
  });

  it("rejects GET /confirmed without a bearer token", async () => {
    const { app } = createStubApp();
    const res = await app.request("/confirmed");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "missing bearer token" });
  });

  it("rejects GET /confirmed with an invalid token", async () => {
    const { app } = createStubApp({
      verify: async () => {
        throw new Error("invalid token");
      },
    });
    const res = await app.request("/confirmed", {
      headers: { Authorization: "Bearer not-a-token" },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid token" });
  });

  it("maps retryable JWKS failure on GET /confirmed to 503", async () => {
    const { app } = createStubApp({
      verify: async () => {
        throw new OperationalAuthenticationFailure({
          category: "network",
          operation: "verify-access-token",
          retryable: true,
        });
      },
    });
    const res = await app.request("/confirmed", {
      headers: { Authorization: "Bearer access-token" },
    });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({
      error: "authentication service unavailable",
    });
  });

  it("maps non-retryable verifier failure on GET /confirmed to 500", async () => {
    const { app } = createStubApp({
      verify: async () => {
        throw new OperationalAuthenticationFailure({
          category: "configuration",
          operation: "verify-access-token",
          retryable: false,
        });
      },
    });
    const res = await app.request("/confirmed", {
      headers: { Authorization: "Bearer access-token" },
    });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({
      error: "authentication service error",
    });
  });
});

describe("HTTP authentication stub with the real access-token verifier", () => {
  const { app, signAccessToken } = createStubAppWithRealAccessTokenVerifier();
  const nowSeconds = () => Math.floor(Date.now() / 1000);

  it("accepts a locally signed access token on GET /confirmed when it has not expired", async () => {
    const res = await app.request("/confirmed", {
      headers: { Authorization: `Bearer ${signAccessToken(nowSeconds() + 3600)}` },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "signed_in",
      message: "Login confirmed",
      user: { sub: "sub-1", username: "persona" },
    });
  });

  it("rejects an expired access token on GET /confirmed with 401 invalid token", async () => {
    const res = await app.request("/confirmed", {
      headers: { Authorization: `Bearer ${signAccessToken(nowSeconds() - 60)}` },
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid token" });
  });
});
