import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface GuardStackProps extends cdk.StackProps {
  /** "dev" or "prod" */
  envName: string;

  /** Docker image tag to deploy (e.g. "0.1.0" from the git tag) */
  imageTag: string;

  /** VPC ID to deploy into (shared with backend) */
  vpcId: string;
}

export class GuardStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: GuardStackProps) {
    super(scope, id, props);

    const { envName, imageTag, vpcId } = props;

    // ---------------------------------------------------------------
    // VPC — look up the existing VPC shared with the backend.
    // This avoids creating a duplicate VPC.
    // ---------------------------------------------------------------
    const vpc = ec2.Vpc.fromLookup(this, "Vpc", { vpcId });

    // ---------------------------------------------------------------
    // ECR Repositories — look up existing repos.
    // Created by scripts/create_docker.sh on first push.
    // ---------------------------------------------------------------
    const repo = ecr.Repository.fromRepositoryName(
      this,
      "Repo",
      "palisade-guard"
    );

    // ---------------------------------------------------------------
    // ECS Cluster — one cluster per environment for the guard service.
    // ---------------------------------------------------------------
    const cluster = new ecs.Cluster(this, "Cluster", {
      vpc,
      clusterName: `palisade-guard-${envName}`,
    });

    // ---------------------------------------------------------------
    // CloudWatch Log Group — structured JSON logs from zap.
    // 30-day retention keeps costs low.
    // ---------------------------------------------------------------
    const logGroup = new logs.LogGroup(this, "LogGroup", {
      logGroupName: `/ecs/palisade-guard-${envName}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ---------------------------------------------------------------
    // Task Definition — Fargate task with guard only.
    // ML inference is handled by the dedicated GPU instance (prompt-guard NLB).
    // ---------------------------------------------------------------
    const taskDef = new ecs.FargateTaskDefinition(this, "TaskDef", {
      cpu: 512, // 0.5 vCPU
      memoryLimitMiB: 1024, // 1 GB
    });

    const clickhouseDsn = process.env.CLICKHOUSE_DSN || "";
    const promptGuardEndpoint = process.env.PROMPT_GUARD_ENDPOINT || "";

    // Guard container — the main gRPC server
    taskDef.addContainer("guard", {
      image: ecs.ContainerImage.fromEcrRepository(repo, imageTag),
      essential: true,
      portMappings: [
        {
          containerPort: 50051,
          protocol: ecs.Protocol.TCP,
        },
      ],
      logging: ecs.LogDrivers.awsLogs({
        logGroup,
        streamPrefix: "guard",
      }),
      environment: {
        GUARD_PORT: "50051",
        GUARD_LOG_LEVEL: envName === "prod" ? "info" : "debug",
        GUARD_DETECTOR_TIMEOUT_MS: "100",
        GUARD_BLOCK_THRESHOLD: "0.8",
        GUARD_FLAG_THRESHOLD: "0.0",
        CLICKHOUSE_DSN: clickhouseDsn,
        PROMPT_GUARD_ENDPOINT: promptGuardEndpoint,
      },
    });

    // ---------------------------------------------------------------
    // Security Group — allow inbound gRPC traffic on port 50051.
    // ---------------------------------------------------------------
    const sg = new ec2.SecurityGroup(this, "GuardSg", {
      vpc,
      description: "Allow inbound gRPC traffic to guard service",
      allowAllOutbound: true,
    });
    sg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(50051),
      "gRPC from anywhere"
    );

    // ---------------------------------------------------------------
    // Fargate Service — 2 tasks minimum for high availability.
    // Circuit breaker auto-rolls back if new tasks crash.
    // ---------------------------------------------------------------
    const service = new ecs.FargateService(this, "Service", {
      cluster,
      serviceName: `palisade-guard-${envName}`,
      taskDefinition: taskDef,
      desiredCount: 2,
      assignPublicIp: true,
      // Place tasks in public subnets so they can reach ClickHouse Cloud
      // (external internet). Private subnets would need a NAT Gateway ($$$).
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      securityGroups: [sg],
      circuitBreaker: { enable: true, rollback: true },
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
    });

    // ---------------------------------------------------------------
    // Auto-scaling — scale 2→10 tasks based on CPU utilization.
    // 70% target keeps headroom for traffic spikes.
    // ---------------------------------------------------------------
    const scaling = service.autoScaleTaskCount({
      minCapacity: 2,
      maxCapacity: 10,
    });
    scaling.scaleOnCpuUtilization("CpuScaling", {
      targetUtilizationPercent: 70,
      scaleInCooldown: cdk.Duration.seconds(60),
      scaleOutCooldown: cdk.Duration.seconds(30),
    });

    // ---------------------------------------------------------------
    // NLB — Network Load Balancer for gRPC.
    //
    // WHY NLB (not ALB):
    // ALB terminates HTTP/2 and re-opens HTTP/1.1 to backends,
    // which breaks gRPC. NLB does TCP passthrough, so the HTTP/2
    // connection goes end-to-end from SDK → guard service.
    // ---------------------------------------------------------------
    const nlb = new elbv2.NetworkLoadBalancer(this, "NLB", {
      vpc,
      loadBalancerName: `guard-${envName}`,
      internetFacing: true,
      crossZoneEnabled: true,
    });

    const listener = nlb.addListener("GrpcListener", {
      port: 50051,
      protocol: elbv2.Protocol.TCP,
    });

    listener.addTargets("GuardTargets", {
      port: 50051,
      protocol: elbv2.Protocol.TCP,
      targets: [service],
      healthCheck: {
        protocol: elbv2.Protocol.TCP,
        interval: cdk.Duration.seconds(10),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 2,
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    // ---------------------------------------------------------------
    // Outputs — these are printed after `cdk deploy` and stored in
    // CloudFormation. You'll need the NLB DNS to configure SDKs.
    // ---------------------------------------------------------------
    new cdk.CfnOutput(this, "NlbDnsName", {
      value: nlb.loadBalancerDnsName,
      description:
        "NLB DNS name — use this as the gRPC target in SDKs (host:50051)",
    });

    new cdk.CfnOutput(this, "EcrRepoUri", {
      value: repo.repositoryUri,
      description: "ECR repository URI for Docker images",
    });

    new cdk.CfnOutput(this, "EcsServiceName", {
      value: service.serviceName,
      description: "ECS service name for manual operations",
    });

    new cdk.CfnOutput(this, "LogGroupName", {
      value: logGroup.logGroupName,
      description:
        "CloudWatch log group — view with: aws logs tail /ecs/palisade-guard-" +
        envName,
    });
  }
}
