export class CognitoAuthResult {
  constructor(
    public readonly key: string,
    public readonly username: string,
    public readonly email: string,
    public readonly accessToken: string,
    public readonly idToken: string,
    public readonly refreshToken?: string
  ) {}
}
