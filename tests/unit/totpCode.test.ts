import { describe, expect, it, vi } from "vitest";
import {
  alterTotpCode,
  generateTotpCode,
  stepRemainderMs,
  waitForMinimumStepRemainder,
  waitForNextTotpStep,
} from "../../src/totpCode.js";

describe("deterministic TOTP helper", () => {
  it("generates a six-digit SHA1/30s code for a known secret", () => {
    const secret = "JBSWY3DPEHPK3PXP";
    const fixedNow = 1_700_000_000_000;
    const code = generateTotpCode(secret, {
      now: () => fixedNow,
      sleep: async () => undefined,
    });
    expect(code).toMatch(/^\d{6}$/);
    expect(generateTotpCode(secret, { now: () => fixedNow, sleep: async () => undefined })).toBe(
      code,
    );
  });

  it("alters a code without logging secrets", () => {
    expect(alterTotpCode("012345")).toBe("112345");
    expect(alterTotpCode("112345")).toBe("012345");
  });

  it("waits when step remainder is below the minimum", async () => {
    const sleeps: number[] = [];
    // 1000ms into a 30s window → 29000ms remainder (> 5000) → no wait
    await waitForMinimumStepRemainder({
      now: () => 1_000,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    expect(sleeps).toEqual([]);

    // 28_000ms into window → 2000ms remainder (< 5000) → sleep remainder+1000
    await waitForMinimumStepRemainder({
      now: () => 28_000,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    expect(sleeps).toEqual([3_000]);
  });

  it("waits for the next step after enrollment", async () => {
    const sleeps: number[] = [];
    await waitForNextTotpStep({
      now: () => 10_000,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    expect(sleeps).toEqual([stepRemainderMs(10_000) + 250]);
  });
});
