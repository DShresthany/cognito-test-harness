#!/usr/bin/env bash
# Ordered PR / CodeBuild gate. Stops at the first failing step.
# Live Cognito runs last, only after static, infra, and preflight pass.
# Secret-file cleanup lives in buildspec.yml so local runs keep their credentials.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== typecheck ===";  npm run typecheck
echo "=== unit ===";       npm run test:unit
echo "=== http ===";       npm run test:http
echo "=== infra test ==="; npm run infra:test
echo "=== synth ===";      npm run infra:synth
echo "=== preflight ===";  npm run preflight
echo "=== live ===";       npm run test:live:cognito

echo "CI gate completed successfully"
