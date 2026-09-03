import { CognitoJwtVerifier } from "aws-jwt-verify";
import { required } from "./cognitoAuth.js";

export function createAccessTokenVerifier() {
  return CognitoJwtVerifier.create({
    userPoolId: required("COGNITO_USER_POOL_ID"),
    tokenUse: "access",
    clientId: required("COGNITO_CLIENT_ID"),
  });
}
