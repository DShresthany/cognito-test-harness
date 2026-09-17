import { Hono } from "hono";
import {
  OperationalAuthenticationFailure,
  toSafeDiagnostic,
  type AuthenticationOutcome,
  type SafeDiagnostic,
} from "./authenticationOutcome.js";

export type PasswordAuthenticationPort = {
  authenticate(
    username: string,
    password: string,
  ): Promise<AuthenticationOutcome>;
};

export type AccessTokenVerifierPort = {
  verify(accessToken: string): Promise<{ sub: string; username: string }>;
};

export type SafeDiagnosticReporter = {
  report(diagnostic: SafeDiagnostic): void;
};

export type HttpAuthenticationStubDependencies = {
  authenticatePassword: PasswordAuthenticationPort;
  verifyAccessToken: AccessTokenVerifierPort;
  reportDiagnostic: SafeDiagnosticReporter;
};

export function createApp(deps: HttpAuthenticationStubDependencies) {
  const app = new Hono();

  app.post("/login", async (c) => {
    let body: { username?: string; password?: string };
    try {
      body = await c.req.json<{ username?: string; password?: string }>();
    } catch {
      return c.json({ error: "invalid request" }, 400);
    }

    if (!body.username || !body.password) {
      return c.json({ error: "username and password required" }, 400);
    }

    try {
      const outcome = await deps.authenticatePassword.authenticate(
        body.username,
        body.password,
      );
      deps.reportDiagnostic.report(
        toSafeDiagnostic(outcome, { operation: "admin-initiate-auth" }),
      );
      return httpResponseForOutcome(outcome);
    } catch (error) {
      return thrownAuthHttpResponse(deps, error, {
        error: "invalid credentials",
      });
    }
  });

  app.get("/confirmed", async (c) => {
    const header = c.req.header("Authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) {
      return c.json({ error: "missing bearer token" }, 401);
    }

    try {
      const payload = await deps.verifyAccessToken.verify(token);
      return c.json({
        status: "signed_in",
        message: "Login confirmed",
        user: {
          sub: payload.sub,
          username: payload.username,
        },
      });
    } catch (error) {
      return thrownAuthHttpResponse(deps, error, { error: "invalid token" });
    }
  });

  return app;
}

function httpResponseForOutcome(outcome: AuthenticationOutcome) {
  switch (outcome.kind) {
    case "authenticated":
      return Response.json(
        {
          accessToken: outcome.tokens.accessToken,
          idToken: outcome.tokens.idToken,
        },
        { status: 200 },
      );
    case "rejected":
      return Response.json({ error: "invalid credentials" }, { status: 401 });
    case "challenged":
      return Response.json(
        { error: "additional authentication required" },
        { status: 409 },
      );
    default: {
      const exhaustive: never = outcome;
      throw new Error(`unhandled authentication outcome: ${String(exhaustive)}`);
    }
  }
}

function thrownAuthHttpResponse(
  deps: HttpAuthenticationStubDependencies,
  error: unknown,
  invalidFallback: { error: string },
) {
  if (error instanceof OperationalAuthenticationFailure) {
    deps.reportDiagnostic.report(
      toSafeDiagnostic(error, { operation: error.operation }),
    );
    if (error.retryable) {
      return Response.json(
        { error: "authentication service unavailable" },
        { status: 503 },
      );
    }
    return Response.json(
      { error: "authentication service error" },
      { status: 500 },
    );
  }

  return Response.json(invalidFallback, { status: 401 });
}
