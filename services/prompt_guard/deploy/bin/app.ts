#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { PromptGuardStack } from "../lib/prompt-guard-stack";

const app = new cdk.App();

// The VERSION env var is set by the deploy workflow:
//   VERSION="0.1.0" npx cdk deploy palisade-prompt-guard-dev
// It matches the Docker image tag pushed to ECR.
const imageTag = process.env.VERSION || "latest";

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT || process.env.AWS_ACCOUNT_ID,
  region: "us-west-1",
};

const vpcId = process.env.VPC_ID || "vpc-0455335f7f14d1a44";

new PromptGuardStack(app, "palisade-prompt-guard-dev", {
  env,
  envName: "dev",
  imageTag,
  vpcId,
});

new PromptGuardStack(app, "palisade-prompt-guard-prod", {
  env,
  envName: "prod",
  imageTag,
  vpcId,
});

app.synth();
