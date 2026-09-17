import { randomUUID } from "node:crypto";
import {
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  MessageActionType,
} from "@aws-sdk/client-cognito-identity-provider";
import { randomPassword } from "./randomPassword.js";

export type TestPersonaIdentity = {
  key: string;
  emailPrefix: string;
};

export type FixtureStateRecipe =
  | { kind: "permanent-password" }
  | { kind: "temporary-password" }
  | { kind: "totp-enabled" };

export type ProvisionedPersona = {
  key: string;
  username: string;
  email: string;
  password: string;
};

export type TestPersonaFixtureCommands = {
  createUser(input: {
    username: string;
    email: string;
  }): Promise<{ username: string }>;
  setPassword(input: {
    username: string;
    password: string;
    permanent: boolean;
  }): Promise<void>;
  deleteUser(input: { username: string }): Promise<void>;
};

export type CognitoUserFixtureManagerOptions = {
  generatePassword?: () => string;
  runId?: string;
};

export function createCognitoFixtureCommands(
  client: CognitoIdentityProviderClient,
  userPoolId: string,
): TestPersonaFixtureCommands {
  return {
    async createUser({ username, email }) {
      const created = await client.send(
        new AdminCreateUserCommand({
          UserPoolId: userPoolId,
          Username: username,
          MessageAction: MessageActionType.SUPPRESS,
          UserAttributes: [
            { Name: "email", Value: email },
            { Name: "email_verified", Value: "true" },
          ],
        }),
      );
      return { username: created.User?.Username ?? username };
    },
    async setPassword({ username, password, permanent }) {
      await client.send(
        new AdminSetUserPasswordCommand({
          UserPoolId: userPoolId,
          Username: username,
          Password: password,
          Permanent: permanent,
        }),
      );
    },
    async deleteUser({ username }) {
      await client.send(
        new AdminDeleteUserCommand({
          UserPoolId: userPoolId,
          Username: username,
        }),
      );
    },
  };
}

export class CognitoUserFixtureManager {
  readonly runId: string;
  private readonly generatePassword: () => string;
  private readonly ownedUsernames: string[] = [];

  constructor(
    private readonly commands: TestPersonaFixtureCommands,
    options: CognitoUserFixtureManagerOptions = {},
  ) {
    this.runId = options.runId ?? randomUUID();
    this.generatePassword = options.generatePassword ?? randomPassword;
  }

  async provision(
    identity: TestPersonaIdentity,
    recipe: FixtureStateRecipe,
  ): Promise<ProvisionedPersona> {
    const email = `${identity.emailPrefix}+${this.runId}@gmail.com`;
    const password = this.generatePassword();
    const created = await this.commands.createUser({
      username: email,
      email,
    });
    const username = created.username;
    this.ownedUsernames.push(username);
    await this.commands.setPassword({
      username,
      password,
      permanent: isPermanentPassword(recipe),
    });

    return {
      key: identity.key,
      username,
      email,
      password,
    };
  }

  async cleanup(): Promise<void> {
    const usernames = [...new Set(this.ownedUsernames)];
    const results = await Promise.allSettled(
      usernames.map(async (username) => {
        try {
          await this.commands.deleteUser({ username });
        } catch (error) {
          if (isUserNotFound(error)) {
            return;
          }
          throw error;
        }
      }),
    );

    const failures = results.filter((result) => result.status === "rejected");
    if (failures.length > 0) {
      throw new Error(
        `cleanup: ${failures.length}/${usernames.length} user delete(s) failed`,
      );
    }
  }
}

function isPermanentPassword(recipe: FixtureStateRecipe): boolean {
  switch (recipe.kind) {
    case "permanent-password":
    case "totp-enabled":
      return true;
    case "temporary-password":
      return false;
    default:
      return assertNever(recipe);
  }
}

function isUserNotFound(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    (error as { name?: unknown }).name === "UserNotFoundException"
  );
}

function assertNever(_value: never): never {
  throw new Error("unhandled fixture-state recipe");
}
