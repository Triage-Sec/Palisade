import * as cdk from "aws-cdk-lib";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface PromptGuardStackProps extends cdk.StackProps {
  /** "dev" or "prod" */
  envName: string;

  /** Docker image tag to deploy (e.g. "0.1.0" from the git tag) */
  imageTag: string;

  /** VPC ID to deploy into (shared with backend) */
  vpcId: string;
}

export class PromptGuardStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: PromptGuardStackProps) {
    super(scope, id, props);

    const { envName, imageTag, vpcId } = props;

    // ---------------------------------------------------------------
    // VPC — look up the existing VPC shared with the backend.
    // ---------------------------------------------------------------
    const vpc = ec2.Vpc.fromLookup(this, "Vpc", { vpcId });

    // ---------------------------------------------------------------
    // ECR Repository — look up the existing repo.
    // The repo is created by scripts/create_docker.sh on first push.
    // ---------------------------------------------------------------
    const repo = ecr.Repository.fromRepositoryName(
      this,
      "Repo",
      "palisade-prompt-guard"
    );

    // ---------------------------------------------------------------
    // ECS Cluster — one cluster per environment.
    // ---------------------------------------------------------------
    const cluster = new ecs.Cluster(this, "Cluster", {
      vpc,
      clusterName: `palisade-prompt-guard-${envName}`,
    });

    // ---------------------------------------------------------------
    // CloudWatch Log Group — structured JSON logs from structlog.
    // ---------------------------------------------------------------
    const logGroup = new logs.LogGroup(this, "LogGroup", {
      logGroupName: `/ecs/palisade-prompt-guard-${envName}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ---------------------------------------------------------------
    // Auto Scaling Group — g4dn.xlarge for T4 GPU.
    //
    // WHY EC2 (not Fargate):
    // Fargate does not support GPU instances. We need a T4 GPU for
    // fast ML inference (<15ms per classification).
    // ---------------------------------------------------------------
    const asg = new autoscaling.AutoScalingGroup(this, "Asg", {
      vpc,
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.G4DN,
        ec2.InstanceSize.XLARGE
      ),
      machineImage: ecs.EcsOptimizedImage.amazonLinux2(
        ecs.AmiHardwareType.GPU
      ),
      minCapacity: 1,
      maxCapacity: 2,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      associatePublicIpAddress: true,
    });

    const capacityProvider = new ecs.AsgCapacityProvider(
      this,
      "AsgCapacityProvider",
      {
        autoScalingGroup: asg,
        enableManagedScaling: true,
        enableManagedTerminationProtection: false,
      }
    );
    cluster.addAsgCapacityProvider(capacityProvider);

    // ---------------------------------------------------------------
    // EC2 Task Definition — 4 vCPU / 14 GB + 1 GPU.
    // ---------------------------------------------------------------
    const taskDef = new ecs.Ec2TaskDefinition(this, "TaskDef", {
      networkMode: ecs.NetworkMode.HOST,
    });

    taskDef.addContainer("prompt-guard", {
      image: ecs.ContainerImage.fromEcrRepository(repo, imageTag),
      memoryReservationMiB: 14336, // 14 GB
      gpuCount: 1,
      portMappings: [
        {
          containerPort: 50052,
          hostPort: 50052,
          protocol: ecs.Protocol.TCP,
        },
      ],
      logging: ecs.LogDrivers.awsLogs({
        logGroup,
        streamPrefix: "prompt-guard",
      }),
      environment: {
        PROMPT_GUARD_PORT: "50052",
        PROMPT_GUARD_LOG_LEVEL: envName === "prod" ? "info" : "debug",
        PROMPT_GUARD_MAX_WORKERS: "4",
        PROMPT_GUARD_MODEL_NAME:
          "qualifire/prompt-injection-jailbreak-sentinel-v2",
        // NVIDIA runtime is auto-configured by the ECS GPU-optimized AMI.
      },
    });

    // ---------------------------------------------------------------
    // ECS Service — EC2 launch type with GPU capacity provider.
    // ---------------------------------------------------------------
    const service = new ecs.Ec2Service(this, "Service", {
      cluster,
      serviceName: `palisade-prompt-guard-${envName}`,
      taskDefinition: taskDef,
      desiredCount: 1,
      capacityProviderStrategies: [
        {
          capacityProvider: capacityProvider.capacityProviderName,
          weight: 1,
        },
      ],
      circuitBreaker: { enable: true, rollback: true },
      minHealthyPercent: 0,
      maxHealthyPercent: 100,
    });

    // ---------------------------------------------------------------
    // Security Group — allow inbound gRPC on port 50052.
    // Only the guard service should call this (internal NLB).
    // ---------------------------------------------------------------
    asg.addSecurityGroup(
      new ec2.SecurityGroup(this, "PromptGuardSg", {
        vpc,
        description:
          "Allow inbound gRPC traffic to prompt guard service (internal)",
        allowAllOutbound: true,
      })
    );
    asg.connections.allowFromAnyIpv4(ec2.Port.tcp(50052), "gRPC internal");

    // ---------------------------------------------------------------
    // NLB — Internal Network Load Balancer.
    //
    // WHY Internal (not internet-facing):
    // Only the guard service calls prompt_guard over gRPC.
    // No external clients should reach the ML inference endpoint.
    // ---------------------------------------------------------------
    const nlb = new elbv2.NetworkLoadBalancer(this, "NLB", {
      vpc,
      loadBalancerName: `prompt-guard-${envName}`,
      internetFacing: false,
      crossZoneEnabled: true,
    });

    const listener = nlb.addListener("GrpcListener", {
      port: 50052,
      protocol: elbv2.Protocol.TCP,
    });

    listener.addTargets("PromptGuardTargets", {
      port: 50052,
      protocol: elbv2.Protocol.TCP,
      targets: [service],
      healthCheck: {
        protocol: elbv2.Protocol.TCP,
        interval: cdk.Duration.seconds(30),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    // ---------------------------------------------------------------
    // Outputs
    // ---------------------------------------------------------------
    new cdk.CfnOutput(this, "NlbDnsName", {
      value: nlb.loadBalancerDnsName,
      description:
        "Internal NLB DNS name — use as PROMPT_GUARD_ENDPOINT in guard service",
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
        "CloudWatch log group — view with: aws logs tail /ecs/palisade-prompt-guard-" +
        envName,
    });
  }
}
