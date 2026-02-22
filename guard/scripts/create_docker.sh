#!/usr/bin/env bash
# Build the guard Docker image and push it to ECR.
#
# Usage:
#   ./guard/scripts/create_docker.sh <VERSION>
#
# Example:
#   ./guard/scripts/create_docker.sh 0.1.0
#
# Requires:
#   - AWS CLI configured (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION)
#   - Docker running
#   - AWS_ACCOUNT_ID set (or auto-detected via STS)

set -euo pipefail

VERSION="${1:?Usage: create_docker.sh <VERSION>}"
AWS_REGION="${AWS_DEFAULT_REGION:-us-west-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_REPO="palisade-guard"

echo "=== Building palisade-guard ==="
echo "  Version:  ${VERSION}"
echo "  Registry: ${ECR_REGISTRY}"
echo "  Repo:     ${ECR_REPO}"

# Ensure the ECR repository exists (idempotent).
aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${AWS_REGION}" > /dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${ECR_REPO}" --region "${AWS_REGION}" > /dev/null

# Login to ECR.
aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin "${ECR_REGISTRY}"

# Build from repo root (Dockerfile needs guard/ and proto/ directories).
docker build \
  -f guard/deploy/Dockerfile \
  -t "${ECR_REGISTRY}/${ECR_REPO}:${VERSION}" \
  -t "${ECR_REGISTRY}/${ECR_REPO}:latest" \
  .

# Push both tags.
docker push "${ECR_REGISTRY}/${ECR_REPO}:${VERSION}"
docker push "${ECR_REGISTRY}/${ECR_REPO}:latest"

echo "=== Pushed ==="
echo "  ${ECR_REGISTRY}/${ECR_REPO}:${VERSION}"
echo "  ${ECR_REGISTRY}/${ECR_REPO}:latest"
