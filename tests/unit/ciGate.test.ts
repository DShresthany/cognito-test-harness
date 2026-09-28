import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

describe("CI gate contract", () => {
  const gate = readFileSync(
    resolve(process.cwd(), "scripts/ci-gate.sh"),
    "utf8",
  );
  const gateScripts = [...gate.matchAll(/npm run (\S+)/g)].map((m) => m[1]);

  it("runs the gate scripts in order so live Cognito comes last", () => {
    expect(gateScripts).toEqual([
      "typecheck",
      "test:unit",
      "test:http",
      "infra:test",
      "infra:synth",
      "preflight",
      "test:live:cognito",
    ]);
  });

  it("leaves local secret files in place", () => {
    expect(gate).not.toMatch(/\.cognito|\.env\b/);
  });

  it("removes secret files after every CodeBuild build, pass or fail", () => {
    const buildspec = parse(
      readFileSync(resolve(process.cwd(), "buildspec.yml"), "utf8"),
    ) as { phases: { build: { finally?: string[] } } };
    const cleanup = (buildspec.phases.build.finally ?? []).join("\n");

    expect(cleanup).toMatch(/rm -f .*\.cognito\/config\.json/);
    expect(cleanup).toMatch(/rm -f .*\.env\b/);
  });

  it("defines every npm script the gate runs, and keeps live out of npm test", () => {
    const pkg = JSON.parse(
      readFileSync(resolve(process.cwd(), "package.json"), "utf8"),
    ) as { scripts: Record<string, string> };

    for (const script of [...gateScripts, "ci:gate", "test"]) {
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
