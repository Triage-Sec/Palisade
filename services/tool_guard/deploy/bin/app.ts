#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { ToolGuardStack } from "../lib/tool-guard-stack";

const app = new cdk.App();

const imageTag = process.env.VERSION || "latest";

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT || process.env.AWS_ACCOUNT_ID,
  region: "us-west-1",
};

const vpcId = process.env.VPC_ID || "vpc-0455335f7f14d1a44";

new ToolGuardStack(app, "palisade-tool-guard-dev", {
  env,
  envName: "dev",
  imageTag,
  vpcId,
});

new ToolGuardStack(app, "palisade-tool-guard-prod", {
  env,
  envName: "prod",
  imageTag,
  vpcId,
});

app.synth();
