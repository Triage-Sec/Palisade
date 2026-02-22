#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { GuardStack } from "../lib/guard-stack";

const app = new cdk.App();

// The VERSION env var is set by the deploy workflow:
//   VERSION="0.1.0" npx cdk deploy palisade-guard-dev
// It matches the Docker image tag pushed to ECR.
const imageTag = process.env.VERSION || "latest";

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT || process.env.AWS_ACCOUNT_ID,
  region: "us-west-1",
};

// -------------------------------------------------------------------
// TODO: Replace this VPC ID with your actual VPC ID.
//
// Find it with:  aws ec2 describe-vpcs --region us-west-1 \
//                  --query 'Vpcs[*].{Id:VpcId,Name:Tags[?Key==`Name`].Value|[0]}'
//
// If the backend already runs in an ECS cluster, use the same VPC.
// -------------------------------------------------------------------
const vpcId = process.env.VPC_ID || "vpc-0455335f7f14d1a44";

new GuardStack(app, "palisade-guard-dev", {
  env,
  envName: "dev",
  imageTag,
  vpcId,
});

new GuardStack(app, "palisade-guard-prod", {
  env,
  envName: "prod",
  imageTag,
  vpcId,
});

app.synth();
