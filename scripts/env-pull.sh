#!/usr/bin/env bash
# Pull Cognito harness config from Secrets Manager into .env (local DX).
# Never commit .env. Does not print secret values.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COGNITO_CONFIG_SECRET_NAME="${COGNITO_CONFIG_SECRET_NAME:-cognito-test-harness/cognito}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
ENV_FILE="${ROOT}/.env"

echo "Fetching ${COGNITO_CONFIG_SECRET_NAME} (region=${AWS_REGION})"
SECRET_JSON="$(aws secretsmanager get-secret-value \
  --secret-id "${COGNITO_CONFIG_SECRET_NAME}" \
  --region "${AWS_REGION}" \
  --query SecretString \
  --output text)"

COGNITO_USER_POOL_ID="$(jq -r '.userPoolId // empty' <<<"${SECRET_JSON}")"
COGNITO_CLIENT_ID="$(jq -r '.clientId // empty' <<<"${SECRET_JSON}")"
COGNITO_CLIENT_SECRET="$(jq -r '.clientSecret // empty' <<<"${SECRET_JSON}")"
REGION_FROM_SECRET="$(jq -r '.region // empty' <<<"${SECRET_JSON}")"
unset SECRET_JSON

if [ -n "${REGION_FROM_SECRET}" ]; then
  AWS_REGION="${REGION_FROM_SECRET}"
fi

for var in COGNITO_USER_POOL_ID COGNITO_CLIENT_ID COGNITO_CLIENT_SECRET AWS_REGION; do
  eval "val=\${$var}"
  if [ -z "${val}" ]; then
    echo "Missing ${var} in secret ${COGNITO_CONFIG_SECRET_NAME}"
    exit 1
  fi
done

PROFILE_LINE=""
if [ -n "${AWS_PROFILE:-}" ]; then
  PROFILE_LINE="AWS_PROFILE=${AWS_PROFILE}"
elif [ -f "${ENV_FILE}" ]; then
  EXISTING_PROFILE="$(grep -E '^AWS_PROFILE=' "${ENV_FILE}" 2>/dev/null | head -1 || true)"
  if [ -n "${EXISTING_PROFILE}" ]; then
    PROFILE_LINE="${EXISTING_PROFILE}"
  fi
fi

umask 077
{
  if [ -n "${PROFILE_LINE}" ]; then
    printf '%s\n' "${PROFILE_LINE}"
  fi
  cat <<EOF
AWS_REGION=${AWS_REGION}
COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID}
COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID}
COGNITO_CLIENT_SECRET=${COGNITO_CLIENT_SECRET}
EOF
} > "${ENV_FILE}"

echo "Wrote ${ENV_FILE} (secret values not logged)"
