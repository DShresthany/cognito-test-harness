import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { CognitoLoginManager } from "../src/cognitoLoginManager.js";
import { loadTestUsers } from "../src/loadTestUsers.js";

config();

const users = loadTestUsers();

let manager: CognitoLoginManager;
let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  // Cognito env (pool/client/secret) is read here, not at module load.
  manager = CognitoLoginManager.fromEnv();
  app = createApp(manager);
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
  it("POST /login then GET /confirmed", async () => {
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

  it("rejects GET /confirmed without a token", async () => {
    const res = await app.request("/confirmed");
    expect(res.status).toBe(401);
  });
});
