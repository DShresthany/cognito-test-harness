#!/usr/bin/env bash
# CodeBuild pre_build: optional main deploy + materialize Cognito config from Secrets Manager.
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

if [ "${CODEBUILD_WEBHOOK_EVENT:-}" = "PUSH" ] && \
   [ "${CODEBUILD_WEBHOOK_HEAD_REF:-}" = "refs/heads/main" ]; then
  BEFORE="${CODEBUILD_WEBHOOK_PREV_COMMIT:-}"
  AFTER="${CODEBUILD_RESOLVED_SOURCE_VERSION:-}"
  if [ -n "${BEFORE}" ] && [ -n "${AFTER}" ] && \
     git diff --name-only "${BEFORE}" "${AFTER}" | grep -q '^infra/'; then
    # Alert inbox comes from SSM (/cognito-test-harness/alert-email) at deploy time.
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

umask 077
export COGNITO_CONFIG_PATH="${SRC_DIR}/.cognito/config.json"
export COGNITO_ENV_PATH="${SRC_DIR}/.env"
printf '%s' "${SECRET_JSON}" | npx --yes tsx "${SRC_DIR}/scripts/materialize-cognito-config.ts"
unset SECRET_JSON
echo "Materialized Cognito config (secret values not logged)"
