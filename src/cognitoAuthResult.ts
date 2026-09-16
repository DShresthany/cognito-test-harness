export type CognitoTokens = {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
};

export type CognitoAuthResult = CognitoTokens & {
  key: string;
  username: string;
  email: string;
};
