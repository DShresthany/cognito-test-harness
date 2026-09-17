import { CognitoIdentityProviderClient } from "@aws-sdk/client-cognito-identity-provider";
import { requireAuthenticated } from "./authenticationOutcome.js";
import type {
  CognitoAuthResult,
  CognitoTokens,
} from "./cognitoAuthResult.js";
import { createCognitoClient, required } from "./cognitoAuth.js";
import {
  CognitoAdminAuthDriver,
  type ConfidentialAdminAuthProfile,
} from "./cognitoAdminAuthDriver.js";
import {
  CognitoUserFixtureManager,
  createCognitoFixtureCommands,
} from "./cognitoUserFixtureManager.js";
import type { TestUser } from "./loadTestUsers.js";

export class CognitoLoginManager {
  readonly runId: string;
  private readonly authResults: CognitoAuthResult[] = [];
  private readonly credentials = new Map<
    string,
    { username: string; password: string }
  >();
  private readonly fixtures: CognitoUserFixtureManager;
  private readonly driver: CognitoAdminAuthDriver;

  constructor(
    client: CognitoIdentityProviderClient,
    userPoolId: string,
    clientId: string,
    clientSecret: string,
  ) {
    this.fixtures = new CognitoUserFixtureManager(
      createCognitoFixtureCommands(client, userPoolId),
    );
    this.runId = this.fixtures.runId;
    const profile: ConfidentialAdminAuthProfile = {
      id: "admin-confidential",
      userPoolId,
      clientId,
      clientSecret,
    };
    this.driver = new CognitoAdminAuthDriver(client, profile);
  }

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
      const persona = await this.fixtures.provision(user, {
        kind: "permanent-password",
      });
      this.credentials.set(user.key, {
        username: persona.username,
        password: persona.password,
      });
      const tokens = await this.login(persona.username, persona.password);
      const auth: CognitoAuthResult = {
        key: user.key,
        email: persona.email,
        username: persona.username,
        ...tokens,
      };
      this.authResults.push(auth);
    }
    return [...this.authResults];
  }

  async login(
    username: string,
    password: string,
  ): Promise<CognitoTokens> {
    const tokens = requireAuthenticated(
      await this.driver.authenticatePassword(username, password),
    );
    return {
      accessToken: tokens.accessToken,
      idToken: tokens.idToken,
      ...(tokens.refreshToken ? { refreshToken: tokens.refreshToken } : {}),
    };
  }

  /**
   * Best-effort delete of users created this run. Delegates to the fixture manager
   * so authentication code does not delete users.
   */
  async cleanup(): Promise<void> {
    await this.fixtures.cleanup();
  }
}
