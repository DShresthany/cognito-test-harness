#!/usr/bin/env bash
# Ordered PR / CodeBuild gate. Classifies failures; never labels them flaky.
# Live Cognito runs only after static, infra, and preflight succeed.
# Once live starts (or anytime after secret materialization), secret files are removed on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FAILED_PHASE=""
LIVE_STARTED=0

classify_and_exit() {
  local phase="$1"
  local category
  category="$(npx --yes tsx scripts/classify-ci-failure.ts "${phase}")"
  echo "BUILD_FAILURE_CATEGORY=${category} phase=${phase}"
  echo "Build remains red (not flaky)."
  exit 1
}

run_phase() {
  local phase="$1"
  shift
  echo "=== CI gate phase: ${phase} ==="
  if ! "$@"; then
    FAILED_PHASE="${phase}"
    classify_and_exit "${phase}"
  fi
}

cleanup_secret_files() {
  echo "=== CI gate phase: cleanup-secret-files ==="
  local config_path="${COGNITO_CONFIG_PATH:-${ROOT}/.cognito/config.json}"
  local env_path="${COGNITO_ENV_PATH:-${ROOT}/.env}"
  rm -f "${config_path}" "${env_path}"
  # Best-effort remove empty .cognito dir
  rmdir "${ROOT}/.cognito" 2>/dev/null || true
  echo "Removed materialized Cognito secret files (if present)"
}

on_exit() {
  local code=$?
  if [ "${LIVE_STARTED}" -eq 1 ] || [ -n "${COGNITO_CONFIG_PATH:-}" ] || [ -f "${ROOT}/.cognito/config.json" ]; then
    if ! cleanup_secret_files; then
      echo "BUILD_FAILURE_CATEGORY=cleanup phase=cleanup-secret-files"
      echo "Build remains red (not flaky)."
      exit 1
    fi
  fi
  exit "${code}"
}

trap on_exit EXIT

run_phase "typecheck" npm run typecheck
run_phase "unit" npm run test:unit
run_phase "http" npm run test:http
run_phase "infra-typecheck-and-assertions" npm run infra:test
run_phase "synth" npm run infra:synth
run_phase "validate-manifest-and-preflight" npm run preflight

LIVE_STARTED=1
run_phase "live-cognito" npm run test:live:cognito

echo "CI gate completed successfully"
