#!/usr/bin/env bash
# Build the prompt-guard Docker image and push it to ECR.
#
# Usage:
#   ./services/prompt_guard/scripts/create_docker.sh <VERSION>
#
# Example:
#   ./services/prompt_guard/scripts/create_docker.sh 0.1.0
#
# Requires:
#   - AWS CLI configured (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION)
#   - Docker running
#   - AWS_ACCOUNT_ID set (or auto-detected via STS)
#   - HF_TOKEN set (HuggingFace token for model download during build)

set -euo pipefail

VERSION="${1:?Usage: create_docker.sh <VERSION>}"
AWS_REGION="${AWS_DEFAULT_REGION:-us-west-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_REPO="palisade-prompt-guard"

echo "=== Building palisade-prompt-guard ==="
echo "  Version:  ${VERSION}"
echo "  Registry: ${ECR_REGISTRY}"
echo "  Repo:     ${ECR_REPO}"

# Ensure the ECR repository exists (idempotent).
aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${AWS_REGION}" > /dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${ECR_REPO}" --region "${AWS_REGION}" > /dev/null

# Login to ECR.
aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin "${ECR_REGISTRY}"

# Validate HF_TOKEN is set (required for gated model download).
: "${HF_TOKEN:?HF_TOKEN is required}"

# Build from repo root (Dockerfile needs services/prompt_guard/ and proto/ directories).
# HF_TOKEN is mounted as a secret so it never appears in any image layer.
docker build \
  -f services/prompt_guard/deploy/Dockerfile \
  --secret id=hf_token,env=HF_TOKEN \
  -t "${ECR_REGISTRY}/${ECR_REPO}:${VERSION}" \
  -t "${ECR_REGISTRY}/${ECR_REPO}:latest" \
  .

# Push both tags.
docker push "${ECR_REGISTRY}/${ECR_REPO}:${VERSION}"
docker push "${ECR_REGISTRY}/${ECR_REPO}:latest"

echo "=== Pushed ==="
echo "  ${ECR_REGISTRY}/${ECR_REPO}:${VERSION}"
echo "  ${ECR_REGISTRY}/${ECR_REPO}:latest"
