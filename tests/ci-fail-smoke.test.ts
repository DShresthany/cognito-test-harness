import { describe, it, expect } from "vitest";

/** Temporary: intentional fail to smoke-test CodeBuild → SNS email. Remove after. */
describe("ci fail smoke", () => {
  it("fails on purpose for SNS alert", () => {
    expect(true).toBe(false);
  });
});
