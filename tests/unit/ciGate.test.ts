import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CI_GATE_PHASES,
  DEFAULT_TEST_SUITES,
  NAMED_SUITES,
  PHASES_BEFORE_LIVE,
  REQUIRED_NPM_SCRIPTS,
  assertReportKeysAllowlisted,
  classifyFailedPhase,
} from "../../src/ciGate.js";

describe("named suites and CI gate contract", () => {
  it("names unit, http, and live-cognito suites", () => {
    expect([...NAMED_SUITES]).toEqual(["unit", "http", "live-cognito"]);
    expect([...DEFAULT_TEST_SUITES]).toEqual(["unit", "http"]);
  });

  it("orders the PR gate so live Cognito cannot run before static/infra/preflight", () => {
    expect([...CI_GATE_PHASES]).toEqual([
      "typecheck",
      "unit",
      "http",
      "infra-typecheck-and-assertions",
      "synth",
      "validate-manifest-and-preflight",
      "live-cognito",
      "cleanup-secret-files",
    ]);
    expect(CI_GATE_PHASES.indexOf("live-cognito")).toBeGreaterThan(
      CI_GATE_PHASES.indexOf("validate-manifest-and-preflight"),
    );
    expect([...PHASES_BEFORE_LIVE]).not.toContain("live-cognito");
    expect(PHASES_BEFORE_LIVE).toEqual(
      CI_GATE_PHASES.slice(0, CI_GATE_PHASES.indexOf("live-cognito")),
    );
  });

  it("classifies failed phases without labeling them flaky", () => {
    expect(classifyFailedPhase("typecheck")).toBe("static");
    expect(classifyFailedPhase("unit")).toBe("static");
    expect(classifyFailedPhase("http")).toBe("static");
    expect(classifyFailedPhase("infra-typecheck-and-assertions")).toBe(
      "infrastructure",
    );
    expect(classifyFailedPhase("synth")).toBe("infrastructure");
    expect(classifyFailedPhase("validate-manifest-and-preflight")).toBe(
      "profile-drift",
    );
    expect(classifyFailedPhase("live-cognito")).toBe("semantic-scenario");
    expect(classifyFailedPhase("cleanup-secret-files")).toBe("cleanup");

    const categories = CI_GATE_PHASES.map(classifyFailedPhase);
    expect(categories).not.toContain("flaky");
  });

  it("rejects report objects with non-allowlisted keys", () => {
    expect(() =>
      assertReportKeysAllowlisted({
        outcomeKind: "authenticated",
        accessVerified: true,
      }),
    ).not.toThrow();
    expect(() =>
      assertReportKeysAllowlisted({
        outcomeKind: "authenticated",
        accessToken: "secret",
      }),
    ).toThrow(/not allowlisted/);
  });

  it("requires npm scripts for suites and the CI gate", () => {
    const pkg = JSON.parse(
      readFileSync(resolve(process.cwd(), "package.json"), "utf8"),
    ) as { scripts: Record<string, string> };

    for (const script of Object.keys(REQUIRED_NPM_SCRIPTS)) {
      expect(pkg.scripts[script], `missing script ${script}`).toEqual(
        expect.any(String),
      );
    }

    expect(pkg.scripts.test).toMatch(/test:unit/);
    expect(pkg.scripts.test).toMatch(/test:http/);
    expect(pkg.scripts.test).not.toMatch(/live/);
    expect(pkg.scripts["test:live:cognito"]).toMatch(/live/);
    expect(pkg.scripts["test:soak:totp"]).toBeUndefined();
  });
});
