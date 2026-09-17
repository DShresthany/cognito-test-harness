import { describe, expect, it, vi } from "vitest";
import {
  CognitoUserFixtureManager,
  type TestPersonaFixtureCommands,
} from "../../src/cognitoUserFixtureManager.js";

const identity = { key: "smoke", emailPrefix: "harness-smoke" };

function createCommands(overrides: Partial<TestPersonaFixtureCommands> = {}): {
  commands: TestPersonaFixtureCommands;
  deleted: string[];
  setPasswordCalls: Array<{
    username: string;
    password: string;
    permanent: boolean;
  }>;
} {
  const deleted: string[] = [];
  const setPasswordCalls: Array<{
    username: string;
    password: string;
    permanent: boolean;
  }> = [];

  const commands: TestPersonaFixtureCommands = {
    async createUser({ username }) {
      return { username: username.replace("@gmail.com", "") };
    },
    async setPassword(input) {
      setPasswordCalls.push(input);
    },
    async deleteUser({ username }) {
      deleted.push(username);
    },
    ...overrides,
  };

  return { commands, deleted, setPasswordCalls };
}

describe("CognitoUserFixtureManager", () => {
  it("provisions a persona handle from identity data and a permanent-password recipe", async () => {
    const { commands, setPasswordCalls } = createCommands({
      async createUser() {
        return { username: "created-user" };
      },
    });
    const fixtures = new CognitoUserFixtureManager(commands, {
      generatePassword: () => "KnownPass1!",
    });

    const persona = await fixtures.provision(identity, {
      kind: "permanent-password",
    });

    expect(persona).toEqual({
      key: "smoke",
      username: "created-user",
      email: `harness-smoke+${fixtures.runId}@gmail.com`,
      password: "KnownPass1!",
    });
    expect(persona).not.toHaveProperty("accessToken");
    expect(setPasswordCalls).toEqual([
      {
        username: "created-user",
        password: "KnownPass1!",
        permanent: true,
      },
    ]);
  });

  it("owns the username after create even when password assignment fails", async () => {
    const { commands, deleted } = createCommands({
      async createUser() {
        return { username: "created-user" };
      },
      async setPassword() {
        throw new Error("password assignment failed");
      },
    });
    const fixtures = new CognitoUserFixtureManager(commands, {
      generatePassword: () => "KnownPass1!",
    });

    await expect(
      fixtures.provision(identity, { kind: "permanent-password" }),
    ).rejects.toThrow("password assignment failed");
    await fixtures.cleanup();

    expect(deleted).toEqual(["created-user"]);
  });

  it("does not own a username when create fails", async () => {
    const { commands, deleted } = createCommands({
      async createUser() {
        throw new Error("User already exists");
      },
    });
    const fixtures = new CognitoUserFixtureManager(commands);

    await expect(
      fixtures.provision(identity, { kind: "permanent-password" }),
    ).rejects.toThrow("User already exists");
    await fixtures.cleanup();

    expect(deleted).toEqual([]);
  });

  it("assigns a temporary password for the temporary-password recipe", async () => {
    const { commands, setPasswordCalls } = createCommands({
      async createUser() {
        return { username: "temp-user" };
      },
    });
    const fixtures = new CognitoUserFixtureManager(commands, {
      generatePassword: () => "TempPass1!",
    });

    await fixtures.provision(identity, { kind: "temporary-password" });

    expect(setPasswordCalls).toEqual([
      {
        username: "temp-user",
        password: "TempPass1!",
        permanent: false,
      },
    ]);
  });

  it("provisions totp-enabled personas with a permanent password", async () => {
    const { commands, setPasswordCalls } = createCommands({
      async createUser() {
        return { username: "totp-user" };
      },
    });
    const fixtures = new CognitoUserFixtureManager(commands, {
      generatePassword: () => "TotpPass1!",
    });

    const persona = await fixtures.provision(identity, { kind: "totp-enabled" });

    expect(persona.username).toBe("totp-user");
    expect(setPasswordCalls[0]?.permanent).toBe(true);
  });

  it("attempts every owned deletion and stays red if any cleanup fails", async () => {
    const { commands, deleted } = createCommands({
      async createUser({ username }) {
        return { username };
      },
      async deleteUser({ username }) {
        deleted.push(username);
        if (username.includes("harness-smoke")) {
          throw new Error("delete denied");
        }
      },
    });
    const fixtures = new CognitoUserFixtureManager(commands, {
      generatePassword: () => "KnownPass1!",
      runId: "run-1",
    });

    await fixtures.provision(identity, { kind: "permanent-password" });
    await fixtures.provision(
      { key: "other", emailPrefix: "harness-other" },
      { kind: "permanent-password" },
    );

    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const error = await fixtures.cleanup().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("cleanup: 1/2 user delete(s) failed");
    expect((error as Error).message).not.toContain("harness-smoke");
    expect((error as Error).message).not.toContain("@gmail.com");
    expect((error as Error).message).not.toContain("delete denied");
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
    expect(deleted).toHaveLength(2);
    expect(deleted).toEqual(
      expect.arrayContaining([
        "harness-smoke+run-1@gmail.com",
        "harness-other+run-1@gmail.com",
      ]),
    );
  });

  it("ignores already-deleted users during cleanup", async () => {
    const { commands } = createCommands({
      async createUser() {
        return { username: "created-user" };
      },
      async deleteUser() {
        throw Object.assign(new Error("User does not exist."), {
          name: "UserNotFoundException",
        });
      },
    });
    const fixtures = new CognitoUserFixtureManager(commands, {
      generatePassword: () => "KnownPass1!",
    });

    await fixtures.provision(identity, { kind: "permanent-password" });
    await expect(fixtures.cleanup()).resolves.toBeUndefined();
  });
});
