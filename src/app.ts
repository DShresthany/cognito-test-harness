import { Hono } from "hono";
import type { CognitoLoginManager } from "./cognitoLoginManager.js";
import { createAccessTokenVerifier } from "./jwtVerifier.js";

export function createApp(manager: CognitoLoginManager) {
  const app = new Hono();
  const verifier = createAccessTokenVerifier();

  app.post("/login", async (c) => {
    const body = await c.req.json<{ username?: string; password?: string }>();
    if (!body.username || !body.password) {
      return c.json({ error: "username and password required" }, 400);
    }

    try {
      const auth = await manager.loginUser(body.username, body.password, {
        key: "http",
        email: body.username,
      });
      return c.json({
        accessToken: auth.accessToken,
        idToken: auth.idToken,
      });
    } catch {
      return c.json({ error: "invalid credentials" }, 401);
    }
  });

  app.get("/me", async (c) => {
    const header = c.req.header("Authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) {
      return c.json({ error: "missing bearer token" }, 401);
    }

    try {
      const payload = await verifier.verify(token);
      return c.json({
        sub: payload.sub,
        username: payload.username,
        clientId: payload.client_id,
      });
    } catch {
      return c.json({ error: "invalid token" }, 401);
    }
  });

  return app;
}
