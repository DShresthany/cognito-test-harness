import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import {
  CognitoAdminAuthDriver,
  type ConfidentialAdminAuthProfile,
} from "../../src/cognitoAdminAuthDriver.js";
import { createCognitoClient, required } from "../../src/cognitoAuth.js";
import { attemptLoginWithInvalidSecretHash } from "../../src/cognitoConfidentialClientProbe.js";
import { CognitoLoginManager } from "../../src/cognitoLoginManager.js";
import { createAccessTokenVerifierPort } from "../../src/jwtVerifier.js";
import { loadTestUsers } from "../../src/loadTestUsers.js";

config();

const users = loadTestUsers();

let manager: CognitoLoginManager;
let app: ReturnType<typeof createApp>;
let client: ReturnType<typeof createCognitoClient>;
let profile: ConfidentialAdminAuthProfile;

beforeAll(async () => {
  // Cognito env (pool/client/secret) is read here, not at module load.
  client = createCognitoClient();
  profile = {
    id: "admin-confidential",
    userPoolId: required("COGNITO_USER_POOL_ID"),
    clientId: required("COGNITO_CLIENT_ID"),
    clientSecret: required("COGNITO_CLIENT_SECRET"),
  };
  manager = new CognitoLoginManager(
    client,
    profile.userPoolId,
    profile.clientId,
    profile.clientSecret,
  );
  const driver = new CognitoAdminAuthDriver(client, profile);
  app = createApp({
    authenticatePassword: {
      authenticate: (username, password) =>
        driver.authenticatePassword(username, password),
    },
    verifyAccessToken: createAccessTokenVerifierPort(),
    reportDiagnostic: { report() {} },
  });
  await manager.setupUsers(users);
}, 90_000);

afterAll(async () => {
  await manager?.cleanup();
}, 90_000);

describe("YAML provision + login", () => {
  it.each(users.map((user) => [user.key] as const))(
    "logs in YAML user %s",
    (key) => {
      const auth = manager.getAuthResult(key);
      expect(auth.email).toContain(manager.runId);
      expect(auth.username).toBeTruthy();
      expect(auth.accessToken).toBeTruthy();
      expect(auth.idToken).toBeTruthy();
    },
  );
});

describe("stub API", () => {
  it("POST /login then GET /confirmed with access token", async () => {
    const creds = manager.getCredentials("smoke");

    const login = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: creds.username,
        password: creds.password,
      }),
    });
    expect(login.status).toBe(200);
    const tokens = (await login.json()) as {
      accessToken?: string;
      idToken?: string;
    };
    expect(tokens.accessToken).toBeTruthy();

    const confirmed = await app.request("/confirmed", {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });
    expect(confirmed.status).toBe(200);
    const body = (await confirmed.json()) as {
      status?: string;
      message?: string;
      user?: { sub?: string; username?: string };
    };
    expect(body.status).toBe("signed_in");
    expect(body.message).toBe("Login confirmed");
    expect(body.user?.username).toBeTruthy();
    expect(body.user?.sub).toBeTruthy();
  });

  it("rejects GET /confirmed with an ID token (access-only verifier)", async () => {
    const auth = manager.getAuthResult("smoke");
    const res = await app.request("/confirmed", {
      headers: { Authorization: `Bearer ${auth.idToken}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid token" });
  });

  it("rejects GET /confirmed with a tampered access token", async () => {
    const auth = manager.getAuthResult("smoke");
    const tampered = tamperJwt(auth.accessToken);
    expect(tampered).not.toBe(auth.accessToken);

    const res = await app.request("/confirmed", {
      headers: { Authorization: `Bearer ${tampered}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid token" });
  });

  it("rejects a bad password", async () => {
    const creds = manager.getCredentials("smoke");
    const res = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: creds.username,
        password: "WrongPassword123!",
      }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid credentials" });
  });

  it("maps unknown user and wrong password to the same 401 body", async () => {
    const creds = manager.getCredentials("smoke");
    const unknown = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: `nobody+${manager.runId}@gmail.com`,
        password: "WhateverPass123!",
      }),
    });
    const wrongPassword = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: creds.username,
        password: "WrongPassword123!",
      }),
    });

    expect(unknown.status).toBe(401);
    expect(wrongPassword.status).toBe(401);
    expect(await unknown.json()).toEqual({ error: "invalid credentials" });
    expect(await wrongPassword.json()).toEqual({ error: "invalid credentials" });
  });

  it("rejects GET /confirmed without a token", async () => {
    const res = await app.request("/confirmed");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "missing bearer token" });
  });
});

describe("confidential client SECRET_HASH", () => {
  it("rejects AdminInitiateAuth with a wrong SECRET_HASH", async () => {
    const creds = manager.getCredentials("smoke");

    const outcome = await attemptLoginWithInvalidSecretHash(
      client,
      profile,
      creds,
    );
    expect(outcome).toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-credentials" },
    });
  });
});

/** Flip one character in the JWT signature so aws-jwt-verify must reject it. */
function tamperJwt(token: string): string {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[2]) {
    throw new Error("expected a three-part JWT");
  }
  const sig = parts[2];
  const i = 0;
  const flipped =
    sig[i] === "A" ? `B${sig.slice(1)}` : `A${sig.slice(1)}`;
  return `${parts[0]}.${parts[1]}.${flipped}`;
}
