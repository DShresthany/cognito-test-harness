#!/usr/bin/env bash
# CodeBuild pre_build: optional main deploy + load Cognito env from Secrets Manager (.env).
set -euo pipefail

export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
CDK_DEFAULT_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
export CDK_DEFAULT_ACCOUNT
export CDK_DEFAULT_REGION="${AWS_REGION}"
STACK_NAME="${STACK_NAME:-CognitoHarnessStack}"
COGNITO_CONFIG_SECRET_NAME="${COGNITO_CONFIG_SECRET_NAME:-cognito-test-harness/cognito}"
SRC_DIR="${CODEBUILD_SRC_DIR:-.}"

echo "Account=${CDK_DEFAULT_ACCOUNT} Region=${AWS_REGION}"
echo "Webhook event=${CODEBUILD_WEBHOOK_EVENT:-none} head=${CODEBUILD_WEBHOOK_HEAD_REF:-none}"

stack_out() {
  aws cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='${1}'].OutputValue | [0]" \
    --output text
}

if [ "${CODEBUILD_WEBHOOK_EVENT:-}" = "PUSH" ] && \
   [ "${CODEBUILD_WEBHOOK_HEAD_REF:-}" = "refs/heads/main" ]; then
  BEFORE="${CODEBUILD_WEBHOOK_PREV_COMMIT:-}"
  AFTER="${CODEBUILD_RESOLVED_SOURCE_VERSION:-}"
  if [ -n "${BEFORE}" ] && [ -n "${AFTER}" ] && \
     git diff --name-only "${BEFORE}" "${AFTER}" | grep -q '^infra/'; then
    # Keep the real SNS inbox from the live stack (buildspec ALERT_EMAIL is synth-only).
    LIVE_ALERT="$(stack_out AlertEmail || true)"
    if [ -n "${LIVE_ALERT}" ] && [ "${LIVE_ALERT}" != "None" ] && [ "${LIVE_ALERT}" != "null" ]; then
      export ALERT_EMAIL="${LIVE_ALERT}"
      echo "Using AlertEmail from stack outputs for deploy"
    else
      echo "WARN: no AlertEmail stack output; deploy will use buildspec ALERT_EMAIL placeholder"
    fi
    echo "infra/ changed on main - deploying stack"
    npm run infra:deploy
  else
    echo "No infra/ deploy needed on this main push"
  fi
else
  echo "Skipping deploy (not a main PUSH)"
fi

echo "Loading Cognito config from Secrets Manager (${COGNITO_CONFIG_SECRET_NAME})"
SECRET_JSON="$(aws secretsmanager get-secret-value \
  --secret-id "${COGNITO_CONFIG_SECRET_NAME}" \
  --query SecretString \
  --output text)"

COGNITO_USER_POOL_ID="$(jq -r '.userPoolId // empty' <<<"${SECRET_JSON}")"
COGNITO_CLIENT_ID="$(jq -r '.clientId // empty' <<<"${SECRET_JSON}")"
COGNITO_CLIENT_SECRET="$(jq -r '.clientSecret // empty' <<<"${SECRET_JSON}")"
REGION_FROM_SECRET="$(jq -r '.region // empty' <<<"${SECRET_JSON}")"
unset SECRET_JSON

export COGNITO_USER_POOL_ID COGNITO_CLIENT_ID COGNITO_CLIENT_SECRET

if [ -n "${REGION_FROM_SECRET}" ]; then
  export AWS_REGION="${REGION_FROM_SECRET}"
fi

for var in COGNITO_USER_POOL_ID COGNITO_CLIENT_ID COGNITO_CLIENT_SECRET AWS_REGION; do
  eval "val=\${$var}"
  if [ -z "${val}" ]; then
    echo "Missing ${var} in secret ${COGNITO_CONFIG_SECRET_NAME}"
    exit 1
  fi
done
echo "Loaded Cognito config from Secrets Manager (secret values not logged)"

# Child-process exports do not persist across buildspec commands; dotenv reads .env.
umask 077
cat > "${SRC_DIR}/.env" <<EOF
AWS_REGION=${AWS_REGION}
COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID}
COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID}
COGNITO_CLIENT_SECRET=${COGNITO_CLIENT_SECRET}
EOF
echo "Wrote Cognito env to ${SRC_DIR}/.env"
