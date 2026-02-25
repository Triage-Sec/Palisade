import * as cdk from "aws-cdk-lib";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as iam from "aws-cdk-lib/aws-iam";
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
    // Single GPU instance — g4dn.xlarge for T4 GPU.
    //
    // WHY EC2 (not Fargate):
    // Fargate does not support GPU instances. We need a T4 GPU for
    // fast ML inference (<15ms per classification).
    //
    // WHY Launch Template (not cluster.addCapacity):
    // AWS deprecated Launch Configurations. We use an explicit
    // LaunchTemplate + AutoScalingGroup + AsgCapacityProvider.
    // ---------------------------------------------------------------

    // IAM role for the EC2 instance — must include ECS container agent permissions.
    const instanceRole = new iam.Role(this, "InstanceRole", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          "service-role/AmazonEC2ContainerServiceforEC2Role"
        ),
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          "AmazonSSMManagedInstanceCore"
        ),
      ],
    });

    // Security group for the GPU instance.
    const gpuSg = new ec2.SecurityGroup(this, "GpuSg", {
      vpc,
      description: "Allow gRPC traffic to prompt guard GPU instance",
      allowAllOutbound: true,
    });
    gpuSg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(50052),
      "gRPC internal"
    );

    // Launch Template with GPU AMI — replaces deprecated Launch Configuration.
    const launchTemplate = new ec2.LaunchTemplate(this, "GpuLaunchTemplate", {
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.G4DN,
        ec2.InstanceSize.XLARGE
      ),
      machineImage: ecs.EcsOptimizedImage.amazonLinux2(
        ecs.AmiHardwareType.GPU
      ),
      role: instanceRole,
      securityGroup: gpuSg,
      associatePublicIpAddress: true,
      userData: ec2.UserData.forLinux(),
      blockDevices: [
        {
          deviceName: "/dev/xvda",
          volume: ec2.BlockDeviceVolume.ebs(50, {
            volumeType: ec2.EbsDeviceVolumeType.GP3,
          }),
        },
      ],
    });

    // Add ECS cluster membership + image cleanup to user data.
    launchTemplate.userData!.addCommands(
      `cat >> /etc/ecs/ecs.config <<EOF`,
      `ECS_CLUSTER=${cluster.clusterName}`,
      `ECS_IMAGE_CLEANUP_INTERVAL=10m`,
      `ECS_IMAGE_MINIMUM_CLEANUP_AGE=30m`,
      `ECS_NUM_IMAGES_DELETE_PER_CYCLE=5`,
      `EOF`
    );

    // AutoScalingGroup with min=max=1 for a single GPU instance.
    const asg = new autoscaling.AutoScalingGroup(this, "GpuAsg", {
      vpc,
      launchTemplate,
      minCapacity: 1,
      maxCapacity: 1,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
    });

    // Register ASG as a capacity provider for the ECS cluster.
    const capacityProvider = new ecs.AsgCapacityProvider(
      this,
      "GpuCapacityProvider",
      { autoScalingGroup: asg }
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
        PROMPT_GUARD_RUNTIME: "onnx",
        PROMPT_GUARD_ONNX_MODEL_PATH: "/app/model",
      },
    });

    // ---------------------------------------------------------------
    // ECS Service — runs on the single EC2 instance.
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
