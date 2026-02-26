import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface ToolGuardStackProps extends cdk.StackProps {
  /** "dev" or "prod" */
  envName: string;

  /** Docker image tag to deploy (e.g. "0.1.0" from the git tag) */
  imageTag: string;

  /** VPC ID to deploy into (shared with backend) */
  vpcId: string;
}

export class ToolGuardStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ToolGuardStackProps) {
    super(scope, id, props);

    const { envName, imageTag, vpcId } = props;

    // ---------------------------------------------------------------
    // VPC — look up the existing VPC shared with the backend.
    // ---------------------------------------------------------------
    const vpc = ec2.Vpc.fromLookup(this, "Vpc", { vpcId });

    // ---------------------------------------------------------------
    // ECR Repository — look up existing repo.
    // Created by scripts/create_docker.sh on first push.
    // ---------------------------------------------------------------
    const repo = ecr.Repository.fromRepositoryName(
      this,
      "Repo",
      "palisade-tool-guard"
    );

    // ---------------------------------------------------------------
    // ECS Cluster
    // ---------------------------------------------------------------
    const cluster = new ecs.Cluster(this, "Cluster", {
      vpc,
      clusterName: `palisade-tool-guard-${envName}`,
    });

    // ---------------------------------------------------------------
    // CloudWatch Log Group
    // ---------------------------------------------------------------
    const logGroup = new logs.LogGroup(this, "LogGroup", {
      logGroupName: `/ecs/palisade-tool-guard-${envName}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ---------------------------------------------------------------
    // Task Definition — Fargate
    // ---------------------------------------------------------------
    const taskDef = new ecs.FargateTaskDefinition(this, "TaskDef", {
      cpu: 512, // 0.5 vCPU
      memoryLimitMiB: 1024, // 1 GB
    });

    const clickhouseDsn = process.env.CLICKHOUSE_DSN || "";
    const postgresDsn = process.env.POSTGRES_DSN || "";

    taskDef.addContainer("tool-guard", {
      image: ecs.ContainerImage.fromEcrRepository(repo, imageTag),
      essential: true,
      portMappings: [
        {
          containerPort: 50053,
          protocol: ecs.Protocol.TCP,
        },
      ],
      logging: ecs.LogDrivers.awsLogs({
        logGroup,
        streamPrefix: "tool-guard",
      }),
      environment: {
        TOOL_GUARD_PORT: "50053",
        TOOL_GUARD_LOG_LEVEL: envName === "prod" ? "info" : "debug",
        TOOL_GUARD_EVAL_TIMEOUT_MS: "25",
        TOOL_GUARD_UNSAFE_THRESHOLD: "0.8",
        CLICKHOUSE_DSN: clickhouseDsn,
        POSTGRES_DSN: postgresDsn,
      },
    });

    // ---------------------------------------------------------------
    // Security Group — allow inbound gRPC traffic on port 50053.
    // ---------------------------------------------------------------
    const sg = new ec2.SecurityGroup(this, "ToolGuardSg", {
      vpc,
      description: "Allow inbound gRPC traffic to tool guard service",
      allowAllOutbound: true,
    });
    sg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(50053),
      "gRPC from anywhere"
    );

    // ---------------------------------------------------------------
    // Fargate Service
    // ---------------------------------------------------------------
    const service = new ecs.FargateService(this, "Service", {
      cluster,
      serviceName: `palisade-tool-guard-${envName}`,
      taskDefinition: taskDef,
      desiredCount: 2,
      assignPublicIp: true,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      securityGroups: [sg],
      circuitBreaker: { enable: true, rollback: true },
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
    });

    // ---------------------------------------------------------------
    // Auto-scaling — scale 2→10 tasks based on CPU utilization.
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
    // NLB — Network Load Balancer for gRPC (TCP passthrough for HTTP/2).
    // ---------------------------------------------------------------
    const nlb = new elbv2.NetworkLoadBalancer(this, "NLB", {
      vpc,
      loadBalancerName: `tool-guard-${envName}`,
      internetFacing: true,
      crossZoneEnabled: true,
    });

    const listener = nlb.addListener("GrpcListener", {
      port: 50053,
      protocol: elbv2.Protocol.TCP,
    });

    listener.addTargets("ToolGuardTargets", {
      port: 50053,
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
    // Outputs
    // ---------------------------------------------------------------
    new cdk.CfnOutput(this, "NlbDnsName", {
      value: nlb.loadBalancerDnsName,
      description:
        "NLB DNS name — use this as the gRPC target for tool guard (host:50053)",
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
        "CloudWatch log group — view with: aws logs tail /ecs/palisade-tool-guard-" +
        envName,
    });
  }
}
