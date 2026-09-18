import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { requireAuthenticated } from "../../src/authenticationOutcome.js";
import { attemptLoginWithInvalidSecretHash } from "../../src/cognitoConfidentialClientProbe.js";
import { createHarnessComposition } from "../../src/createHarnessComposition.js";
import type { ProvisionedPersona } from "../../src/cognitoUserFixtureManager.js";
import { loadTestUsers } from "../../src/loadTestUsers.js";

config();

const users = loadTestUsers();

type ProvisionedSession = {
  persona: ProvisionedPersona;
  accessToken: string;
  idToken: string;
};

let composition: Awaited<ReturnType<typeof createHarnessComposition>>;
const sessions = new Map<string, ProvisionedSession>();

beforeAll(async () => {
  composition = await createHarnessComposition();
  for (const user of users) {
    const persona = await composition.fixtures.provision(user, {
      kind: "permanent-password",
    });
    const tokens = requireAuthenticated(
      await composition.driver.authenticatePassword(
        persona.username,
        persona.password,
      ),
    );
    sessions.set(user.key, {
      persona,
      accessToken: tokens.accessToken,
      idToken: tokens.idToken,
    });
  }
}, 90_000);

afterAll(async () => {
  await composition?.fixtures.cleanup();
}, 90_000);

describe("YAML provision + login", () => {
  it.each(users.map((user) => [user.key] as const))(
    "logs in YAML user %s",
    (key) => {
      const session = sessions.get(key);
      expect(session).toBeDefined();
      expect(session!.persona.email).toContain(composition.fixtures.runId);
      expect(session!.persona.username).toBeTruthy();
      expect(session!.accessToken).toBeTruthy();
      expect(session!.idToken).toBeTruthy();
    },
  );
});

describe("stub API", () => {
  it("POST /login then GET /confirmed with access token", async () => {
    const session = sessions.get("smoke");
    expect(session).toBeDefined();

    const login = await composition.app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: session!.persona.username,
        password: session!.persona.password,
      }),
    });
    expect(login.status).toBe(200);
    const tokens = (await login.json()) as {
      accessToken?: string;
      idToken?: string;
    };
    expect(tokens.accessToken).toBeTruthy();

    const confirmed = await composition.app.request("/confirmed", {
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
    const session = sessions.get("smoke");
    expect(session).toBeDefined();
    const res = await composition.app.request("/confirmed", {
      headers: { Authorization: `Bearer ${session!.idToken}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid token" });
  });

  it("rejects GET /confirmed with a tampered access token", async () => {
    const session = sessions.get("smoke");
    expect(session).toBeDefined();
    const tampered = tamperJwt(session!.accessToken);
    expect(tampered).not.toBe(session!.accessToken);

    const res = await composition.app.request("/confirmed", {
      headers: { Authorization: `Bearer ${tampered}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid token" });
  });

  it("rejects a bad password", async () => {
    const session = sessions.get("smoke");
    expect(session).toBeDefined();
    const res = await composition.app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: session!.persona.username,
        password: "WrongPassword123!",
      }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid credentials" });
  });

  it("maps unknown user and wrong password to the same 401 body", async () => {
    const session = sessions.get("smoke");
    expect(session).toBeDefined();
    const unknown = await composition.app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: `nobody+${composition.fixtures.runId}@gmail.com`,
        password: "WhateverPass123!",
      }),
    });
    const wrongPassword = await composition.app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: session!.persona.username,
        password: "WrongPassword123!",
      }),
    });

    expect(unknown.status).toBe(401);
    expect(wrongPassword.status).toBe(401);
    expect(await unknown.json()).toEqual({ error: "invalid credentials" });
    expect(await wrongPassword.json()).toEqual({ error: "invalid credentials" });
  });

  it("rejects GET /confirmed without a token", async () => {
    const res = await composition.app.request("/confirmed");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "missing bearer token" });
  });
});

describe("confidential client SECRET_HASH", () => {
  it("rejects AdminInitiateAuth with a wrong SECRET_HASH", async () => {
    const session = sessions.get("smoke");
    expect(session).toBeDefined();

    const outcome = await attemptLoginWithInvalidSecretHash(
      composition.client,
      composition.profile,
      {
        username: session!.persona.username,
        password: session!.persona.password,
      },
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
