#!/usr/bin/env bash
# Build the prompt-guard ONNX sidecar Docker image and push it to ECR.
#
# Usage:
#   ./services/prompt_guard/scripts/create_docker_sidecar.sh <VERSION>

set -euo pipefail

VERSION="${1:?Usage: create_docker_sidecar.sh <VERSION>}"
AWS_REGION="${AWS_DEFAULT_REGION:-us-west-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_REPO="palisade-prompt-guard-sidecar"

echo "=== Building palisade-prompt-guard-sidecar ==="
echo "  Version:  ${VERSION}"
echo "  Registry: ${ECR_REGISTRY}"
echo "  Repo:     ${ECR_REPO}"

# Ensure the ECR repository exists (idempotent).
aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${AWS_REGION}" > /dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${ECR_REPO}" --region "${AWS_REGION}" > /dev/null

# Login to ECR.
aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin "${ECR_REGISTRY}"

# Build from repo root.
docker build \
  -f services/prompt_guard/deploy/Dockerfile.sidecar \
  -t "${ECR_REGISTRY}/${ECR_REPO}:${VERSION}" \
  -t "${ECR_REGISTRY}/${ECR_REPO}:latest" \
  .

# Push both tags.
docker push "${ECR_REGISTRY}/${ECR_REPO}:${VERSION}"
docker push "${ECR_REGISTRY}/${ECR_REPO}:latest"

echo "=== Pushed ==="
echo "  ${ECR_REGISTRY}/${ECR_REPO}:${VERSION}"
echo "  ${ECR_REGISTRY}/${ECR_REPO}:latest"
