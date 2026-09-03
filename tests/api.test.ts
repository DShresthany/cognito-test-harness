import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { CognitoLoginManager } from "../src/cognitoLoginManager.js";
import { loadTestUsers } from "../src/loadTestUsers.js";

config();

describe("stub API", () => {
  const manager = CognitoLoginManager.fromEnv();
  const app = createApp(manager);
  const users = loadTestUsers();

  beforeAll(async () => {
    await manager.setupUsers(users);
  }, 90_000);

  afterAll(async () => {
    await manager.cleanup();
  }, 90_000);

  it("POST /login then GET /me", async () => {
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

    const me = await app.request("/me", {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });
    expect(me.status).toBe(200);
    const body = (await me.json()) as {
      sub?: string;
      username?: string;
    };
    expect(body.username).toBeTruthy();
    expect(body.sub).toBeTruthy();
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
  });

  it("rejects GET /me without a token", async () => {
    const res = await app.request("/me");
    expect(res.status).toBe(401);
  });
});
