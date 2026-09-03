import { randomUUID } from "node:crypto";
import {
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminInitiateAuthCommand,
  AdminSetUserPasswordCommand,
  AuthFlowType,
  CognitoIdentityProviderClient,
  MessageActionType,
  UsernameExistsException,
} from "@aws-sdk/client-cognito-identity-provider";
import { CognitoAuthResult } from "./cognitoAuthResult.js";
import { createCognitoClient, required } from "./cognitoAuth.js";
import type { TestUser } from "./loadTestUsers.js";
import { randomPassword } from "./randomPassword.js";
import { getSecretHash } from "./secretHash.js";

export class CognitoLoginManager {
  readonly authResults: CognitoAuthResult[] = [];
  readonly runId = randomUUID().slice(0, 8);
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

  async setupUsers(users: TestUser[]): Promise<CognitoAuthResult[]> {
    for (const user of users) {
      // This pool requires Username to be an email; uniqueness comes from +runId.
      const email = `${user.emailPrefix}+${this.runId}@gmail.com`;
      const password = randomPassword();
      const cognitoUsername = await this.signupUser(email, email, password);
      this.createdUsernames.push(cognitoUsername);
      this.credentials.set(user.key, {
        username: cognitoUsername,
        password,
      });
      const auth = await this.loginUser(cognitoUsername, password, {
        key: user.key,
        email,
      });
      this.authResults.push(auth);
    }
    return this.authResults;
  }

  async signupUser(
    username: string,
    email: string,
    password: string
  ): Promise<string> {
    try {
      const created = await this.client.send(
        new AdminCreateUserCommand({
          UserPoolId: this.userPoolId,
          Username: username,
          MessageAction: MessageActionType.SUPPRESS,
          UserAttributes: [
            { Name: "email", Value: email },
            { Name: "email_verified", Value: "true" },
          ],
        })
      );
      username = created.User?.Username ?? username;
    } catch (error) {
      if (!(error instanceof UsernameExistsException)) {
        throw error;
      }
    }

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

  async loginUser(
    username: string,
    password: string,
    meta: { key: string; email: string }
  ): Promise<CognitoAuthResult> {
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

    return new CognitoAuthResult(
      meta.key,
      username,
      meta.email,
      auth.AccessToken,
      auth.IdToken,
      auth.RefreshToken
    );
  }

  async cleanup(): Promise<void> {
    const usernames = new Set([
      ...this.createdUsernames,
      ...this.authResults.map((auth) => auth.username),
    ]);
    for (const username of usernames) {
      await this.client.send(
        new AdminDeleteUserCommand({
          UserPoolId: this.userPoolId,
          Username: username,
        })
      );
    }
  }
}
