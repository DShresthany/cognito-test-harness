import { randomUUID } from "node:crypto";
import {
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminInitiateAuthCommand,
  AdminSetUserPasswordCommand,
  AuthFlowType,
  CognitoIdentityProviderClient,
  MessageActionType,
  UserNotFoundException,
} from "@aws-sdk/client-cognito-identity-provider";
import type {
  CognitoAuthResult,
  CognitoTokens,
} from "./cognitoAuthResult.js";
import { createCognitoClient, required } from "./cognitoAuth.js";
import type { TestUser } from "./loadTestUsers.js";
import { randomPassword } from "./randomPassword.js";
import { getSecretHash } from "./secretHash.js";

export class CognitoLoginManager {
  readonly runId = randomUUID();
  private readonly authResults: CognitoAuthResult[] = [];
  private readonly createdUsernames: string[] = [];
  private readonly credentials = new Map<
    string,
    { username: string; password: string }
  >();

  constructor(
    private client: CognitoIdentityProviderClient,
    private userPoolId: string,
    private clientId: string,
    private clientSecret: string
  ) {}

  static fromEnv(): CognitoLoginManager {
    return new CognitoLoginManager(
      createCognitoClient(),
      required("COGNITO_USER_POOL_ID"),
      required("COGNITO_CLIENT_ID"),
      required("COGNITO_CLIENT_SECRET")
    );
  }

  getAuthResult(key: string): CognitoAuthResult {
    const result = this.authResults.find((auth) => auth.key === key);
    if (!result) {
      throw new Error(`No auth result for user key "${key}"`);
    }
    return result;
  }

  getCredentials(key: string): { username: string; password: string } {
    const creds = this.credentials.get(key);
    if (!creds) {
      throw new Error(`No credentials for user key "${key}"`);
    }
    return creds;
  }

  async setupUsers(users: TestUser[]): Promise<readonly CognitoAuthResult[]> {
    for (const user of users) {
      // This pool requires Username to be an email; uniqueness comes from +runId.
      const email = `${user.emailPrefix}+${this.runId}@gmail.com`;
      const password = randomPassword();
      const cognitoUsername = await this.signupUser(email, email, password);
      this.credentials.set(user.key, {
        username: cognitoUsername,
        password,
      });
      const tokens = await this.login(cognitoUsername, password);
      const auth: CognitoAuthResult = {
        key: user.key,
        email,
        username: cognitoUsername,
        ...tokens,
      };
      this.authResults.push(auth);
    }
    return [...this.authResults];
  }

  private async signupUser(
    username: string,
    email: string,
    password: string
  ): Promise<string> {
    const created = await this.client.send(
      new AdminCreateUserCommand({
        UserPoolId: this.userPoolId,
        Username: username,
        MessageAction: MessageActionType.SUPPRESS,
        UserAttributes: [
          { Name: "email", Value: email },
          { Name: "email_verified", Value: "true" },
        ],
      }),
    );
    username = created.User?.Username ?? username;
    this.createdUsernames.push(username);

    await this.client.send(
      new AdminSetUserPasswordCommand({
        UserPoolId: this.userPoolId,
        Username: username,
        Password: password,
        Permanent: true,
      })
    );

    return username;
  }

  async login(
    username: string,
    password: string,
  ): Promise<CognitoTokens> {
    const result = await this.client.send(
      new AdminInitiateAuthCommand({
        UserPoolId: this.userPoolId,
        ClientId: this.clientId,
        AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
        AuthParameters: {
          USERNAME: username,
          PASSWORD: password,
          SECRET_HASH: getSecretHash(username, this.clientId, this.clientSecret),
        },
      })
    );

    const auth = result.AuthenticationResult;
    if (!auth?.AccessToken || !auth.IdToken) {
      throw new Error(`AdminInitiateAuth returned no tokens for ${username}`);
    }

    return {
      accessToken: auth.AccessToken,
      idToken: auth.IdToken,
      ...(auth.RefreshToken ? { refreshToken: auth.RefreshToken } : {}),
    };
  }

  /**
   * Best-effort delete of users created this run. One failure does not skip the rest;
   * already-deleted users (UserNotFound) are ignored. Throws after all attempts if
   * any other delete failed.
   */
  async cleanup(): Promise<void> {
    const usernames = [
      ...new Set([
        ...this.createdUsernames,
        ...this.authResults.map((auth) => auth.username),
      ]),
    ];

    const results = await Promise.allSettled(
      usernames.map(async (username) => {
        try {
          await this.client.send(
            new AdminDeleteUserCommand({
              UserPoolId: this.userPoolId,
              Username: username,
            }),
          );
        } catch (error) {
          if (error instanceof UserNotFoundException) {
            return;
          }
          throw error;
        }
      }),
    );

    const failures = results.flatMap((result, i) => {
      if (result.status !== "rejected") {
        return [];
      }
      const username = usernames[i]!;
      const reason =
        result.reason instanceof Error
          ? result.reason.message
          : String(result.reason);
      console.warn(`cleanup: failed to delete Cognito user ${username}: ${reason}`);
      return [`${username}: ${reason}`];
    });

    if (failures.length > 0) {
      throw new Error(
        `cleanup: ${failures.length}/${usernames.length} user delete(s) failed:\n${failures.join("\n")}`,
      );
    }
  }
}
