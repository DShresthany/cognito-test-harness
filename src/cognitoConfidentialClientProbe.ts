import {
  CognitoAdminAuthDriver,
  type ConfidentialAdminAuthProfile,
  type CognitoCommandSender,
} from "./cognitoAdminAuthDriver.js";

type Credentials = {
  username: string;
  password: string;
};

export function attemptLoginWithInvalidSecretHash(
  sender: CognitoCommandSender,
  profile: ConfidentialAdminAuthProfile,
  credentials: Credentials,
) {
  const driver = new CognitoAdminAuthDriver(sender, {
    ...profile,
    clientSecret: `${profile.clientSecret}-wrong`,
  });
  return driver.authenticatePassword(credentials.username, credentials.password);
}
