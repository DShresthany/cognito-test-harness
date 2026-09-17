#!/usr/bin/env bash
# Pull Cognito harness config from Secrets Manager into owner-only .cognito/config.json.
# Bootstrap .env keeps AWS_PROFILE / AWS_REGION / COGNITO_CONFIG_PATH only.
# Never commit .env or .cognito/. Does not print secret values.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COGNITO_CONFIG_SECRET_NAME="${COGNITO_CONFIG_SECRET_NAME:-cognito-test-harness/cognito}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
ENV_FILE="${ROOT}/.env"
CONFIG_PATH="${COGNITO_CONFIG_PATH:-${ROOT}/.cognito/config.json}"

if [ -z "${AWS_PROFILE:-}" ] && [ -f "${ENV_FILE}" ]; then
  EXISTING_PROFILE="$(grep -E '^AWS_PROFILE=' "${ENV_FILE}" 2>/dev/null | head -1 || true)"
  if [ -n "${EXISTING_PROFILE}" ]; then
    export AWS_PROFILE="${EXISTING_PROFILE#AWS_PROFILE=}"
  fi
fi

echo "Fetching ${COGNITO_CONFIG_SECRET_NAME} (region=${AWS_REGION})"
SECRET_JSON="$(aws secretsmanager get-secret-value \
  --secret-id "${COGNITO_CONFIG_SECRET_NAME}" \
  --region "${AWS_REGION}" \
  --query SecretString \
  --output text)"

umask 077
export COGNITO_CONFIG_PATH="${CONFIG_PATH}"
export COGNITO_ENV_PATH="${ENV_FILE}"
printf '%s' "${SECRET_JSON}" | npx --yes tsx "${ROOT}/scripts/materialize-cognito-config.ts"
unset SECRET_JSON
