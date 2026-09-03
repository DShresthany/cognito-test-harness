import {
    AdminCreateUserCommand,
    AdminSetUserPasswordCommand,
    ListUsersCommand,
    MessageActionType,
  } from "@aws-sdk/client-cognito-identity-provider";
  import { createCognitoClient } from "./cognitoAuth.js";
  import type { TestUser } from "./loadTestUsers.js";
  
  function required(name: string): string {
    const value = process.env[name];
    if (!value) throw new Error(`Missing required env: ${name}`);
    return value;
  }
  
  async function findUsernameByEmail(email: string): Promise<string | undefined> {
    const client = createCognitoClient();
    const result = await client.send(
      new ListUsersCommand({
        UserPoolId: required("COGNITO_USER_POOL_ID"),
        Filter: `email = "${email}"`,
        Limit: 1,
      })
    );
    return result.Users?.[0]?.Username;
  }
  
  export async function provisionUser(user: TestUser): Promise<string> {
    const client = createCognitoClient();
    const userPoolId = required("COGNITO_USER_POOL_ID");
  
    let username = await findUsernameByEmail(user.email);
  
    if (!username) {
      const created = await client.send(
        new AdminCreateUserCommand({
          UserPoolId: userPoolId,
          Username: user.email,
          MessageAction: MessageActionType.SUPPRESS,
          UserAttributes: [
            { Name: "email", Value: user.email },
            { Name: "email_verified", Value: "true" },
          ],
        })
      );
      username = created.User?.Username;
      if (!username) {
        throw new Error(`AdminCreateUser did not return Username for ${user.email}`);
      }
    }
  
    await client.send(
      new AdminSetUserPasswordCommand({
        UserPoolId: userPoolId,
        Username: username,
        Password: user.password,
        Permanent: true,
      })
    );
  
    return username;
  }