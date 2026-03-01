#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { TriageGuardStack } from "../lib/triage-guard-stack";

const app = new cdk.App();

// VERSION env var is set by the deploy workflow:
//   VERSION="0.1.0" npx cdk deploy palisade-triage-guard-dev
const imageTag = process.env.VERSION || "latest";

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT || process.env.AWS_ACCOUNT_ID,
  region: "us-west-1",
};

const vpcId = process.env.VPC_ID || "vpc-0455335f7f14d1a44";

new TriageGuardStack(app, "palisade-triage-guard-dev", {
  env,
  envName: "dev",
  imageTag,
  vpcId,
});

new TriageGuardStack(app, "palisade-triage-guard-prod", {
  env,
  envName: "prod",
  imageTag,
  vpcId,
});

app.synth();
