import { defineConfig } from "vitest/config";

const noRetry = {
  retry: 0,
} as const;

export default defineConfig({
  test: {
    ...noRetry,
    projects: [
      {
        test: {
          name: "unit",
          include: ["tests/unit/**/*.test.ts"],
          ...noRetry,
          testTimeout: 30_000,
          hookTimeout: 90_000,
        },
      },
      {
        test: {
          name: "http",
          include: ["tests/http/**/*.test.ts"],
          ...noRetry,
          testTimeout: 30_000,
          hookTimeout: 90_000,
        },
      },
      {
        test: {
          name: "live-cognito",
          include: ["tests/live/**/*.test.ts"],
          ...noRetry,
          fileParallelism: false,
          maxWorkers: 1,
          testTimeout: 120_000,
          hookTimeout: 90_000,
        },
      },
      {
        test: {
          name: "soak-totp",
          include: ["tests/soak/**/*.test.ts"],
          ...noRetry,
          fileParallelism: false,
          maxWorkers: 1,
          testTimeout: 180_000,
          hookTimeout: 90_000,
        },
      },
    ],
  },
});
