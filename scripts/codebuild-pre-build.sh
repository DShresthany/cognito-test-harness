#!/usr/bin/env bash
# CodeBuild pre_build: optional main deploy + write Cognito env for Vitest (.env).
set -euo pipefail

export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
CDK_DEFAULT_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
export CDK_DEFAULT_ACCOUNT
export CDK_DEFAULT_REGION="${AWS_REGION}"
STACK_NAME="${STACK_NAME:-CognitoHarnessStack}"
SRC_DIR="${CODEBUILD_SRC_DIR:-.}"

echo "Account=${CDK_DEFAULT_ACCOUNT} Region=${AWS_REGION}"
echo "Webhook event=${CODEBUILD_WEBHOOK_EVENT:-none} head=${CODEBUILD_WEBHOOK_HEAD_REF:-none}"

if [ "${CODEBUILD_WEBHOOK_EVENT:-}" = "PUSH" ] && \
   [ "${CODEBUILD_WEBHOOK_HEAD_REF:-}" = "refs/heads/main" ]; then
  BEFORE="${CODEBUILD_WEBHOOK_PREV_COMMIT:-}"
  AFTER="${CODEBUILD_RESOLVED_SOURCE_VERSION:-}"
  if [ -n "${BEFORE}" ] && [ -n "${AFTER}" ] && \
     git diff --name-only "${BEFORE}" "${AFTER}" | grep -q '^infra/'; then
    echo "infra/ changed on main - deploying stack"
    npm run infra:deploy
  else
    echo "No infra/ deploy needed on this main push"
  fi
else
  echo "Skipping deploy (not a main PUSH)"
fi

stack_out() {
  aws cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='${1}'].OutputValue | [0]" \
    --output text
}

COGNITO_USER_POOL_ID="$(stack_out UserPoolId)"
COGNITO_CLIENT_ID="$(stack_out UserPoolClientId)"
COGNITO_CLIENT_SECRET="$(stack_out UserPoolClientSecret)"
REGION_FROM_STACK="$(stack_out Region)"
export COGNITO_USER_POOL_ID COGNITO_CLIENT_ID COGNITO_CLIENT_SECRET

if [ -n "${REGION_FROM_STACK}" ] && [ "${REGION_FROM_STACK}" != "None" ]; then
  export AWS_REGION="${REGION_FROM_STACK}"
fi

for var in COGNITO_USER_POOL_ID COGNITO_CLIENT_ID COGNITO_CLIENT_SECRET AWS_REGION; do
  eval "val=\${$var}"
  if [ -z "${val}" ] || [ "${val}" = "None" ] || [ "${val}" = "null" ]; then
    echo "Missing stack output mapped to ${var}"
    exit 1
  fi
done
echo "Loaded Cognito config from ${STACK_NAME} outputs"

# Child-process exports do not persist across buildspec commands; dotenv reads .env.
umask 077
cat > "${SRC_DIR}/.env" <<EOF
AWS_REGION=${AWS_REGION}
COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID}
COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID}
COGNITO_CLIENT_SECRET=${COGNITO_CLIENT_SECRET}
EOF
echo "Wrote Cognito env to ${SRC_DIR}/.env"
