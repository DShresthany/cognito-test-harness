import { describe, it, expect } from "vitest";

/** Temporary: intentional fail to verify PR CodeBuild gate. Close without merge. */
describe("ci fail smoke", () => {
  it("fails on purpose for PR gate", () => {
    expect(true).toBe(false);
  });
});
