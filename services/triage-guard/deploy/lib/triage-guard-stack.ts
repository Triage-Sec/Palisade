import * as cdk from "aws-cdk-lib";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface TriageGuardStackProps extends cdk.StackProps {
  /** "dev" or "prod" */
  envName: string;

  /** Docker image tag to deploy (e.g. "0.1.0" from the git tag) */
  imageTag: string;

  /** VPC ID to deploy into (shared with backend) */
  vpcId: string;
}

export class TriageGuardStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: TriageGuardStackProps) {
    super(scope, id, props);

    const { envName, imageTag, vpcId } = props;

    // ---------------------------------------------------------------
    // VPC — look up the existing VPC shared with the backend.
    // ---------------------------------------------------------------
    const vpc = ec2.Vpc.fromLookup(this, "Vpc", { vpcId });

    // ---------------------------------------------------------------
    // ECR Repository — look up the existing repo.
    // Created by scripts/create_docker.sh on first push.
    // ---------------------------------------------------------------
    const repo = ecr.Repository.fromRepositoryName(
      this,
      "Repo",
      "palisade-triage-guard"
    );

    // ---------------------------------------------------------------
    // ECS Cluster
    // ---------------------------------------------------------------
    const cluster = new ecs.Cluster(this, "Cluster", {
      vpc,
      clusterName: `palisade-triage-guard-${envName}`,
    });

    // ---------------------------------------------------------------
    // CloudWatch Log Group
    // ---------------------------------------------------------------
    const logGroup = new logs.LogGroup(this, "LogGroup", {
      logGroupName: `/ecs/palisade-triage-guard-${envName}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ---------------------------------------------------------------
    // Single GPU instance — g4dn.xlarge for T4 GPU.
    //
    // Both models (~1.2GB each) fit in T4 16GB VRAM.
    // Fargate does not support GPU instances.
    // ---------------------------------------------------------------

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

    const gpuSg = new ec2.SecurityGroup(this, "GpuSg", {
      vpc,
      description: "Allow HTTP traffic to triage guard GPU instance",
      allowAllOutbound: true,
    });
    gpuSg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(8080),
      "HTTP internal"
    );

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

    launchTemplate.userData!.addCommands(
      `cat >> /etc/ecs/ecs.config <<EOF`,
      `ECS_CLUSTER=${cluster.clusterName}`,
      `ECS_IMAGE_CLEANUP_INTERVAL=10m`,
      `ECS_IMAGE_MINIMUM_CLEANUP_AGE=30m`,
      `ECS_NUM_IMAGES_DELETE_PER_CYCLE=5`,
      `EOF`
    );

    const asg = new autoscaling.AutoScalingGroup(this, "GpuAsg", {
      vpc,
      launchTemplate,
      minCapacity: 1,
      maxCapacity: 1,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
    });

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

    taskDef.addContainer("triage-guard", {
      image: ecs.ContainerImage.fromEcrRepository(repo, imageTag),
      memoryReservationMiB: 14336, // 14 GB
      gpuCount: 1,
      portMappings: [
        {
          containerPort: 8080,
          hostPort: 8080,
          protocol: ecs.Protocol.TCP,
        },
      ],
      logging: ecs.LogDrivers.awsLogs({
        logGroup,
        streamPrefix: "triage-guard",
      }),
      environment: {
        TRIAGE_GUARD_PORT: "8080",
        TRIAGE_GUARD_LOG_LEVEL: envName === "prod" ? "info" : "debug",
        PROMPT_GUARD_MODEL_PATH: "/app/models/prompt_guard",
        TOOL_GUARD_CHECKPOINT_PATH: "/app/models/tool_guard",
      },
    });

    // ---------------------------------------------------------------
    // ECS Service
    // ---------------------------------------------------------------
    const service = new ecs.Ec2Service(this, "Service", {
      cluster,
      serviceName: `palisade-triage-guard-${envName}`,
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
    // Only the guard service calls triage-guard over HTTP.
    // ---------------------------------------------------------------
    const nlb = new elbv2.NetworkLoadBalancer(this, "NLB", {
      vpc,
      loadBalancerName: `triage-guard-${envName}`,
      internetFacing: false,
      crossZoneEnabled: true,
    });

    const listener = nlb.addListener("HttpListener", {
      port: 8080,
      protocol: elbv2.Protocol.TCP,
    });

    listener.addTargets("TriageGuardTargets", {
      port: 8080,
      protocol: elbv2.Protocol.TCP,
      targets: [service],
      healthCheck: {
        protocol: elbv2.Protocol.HTTP,
        path: "/health",
        port: "8080",
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
        "Internal NLB DNS name — use as TRIAGE_GUARD_ENDPOINT in guard service",
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
        "CloudWatch log group — view with: aws logs tail /ecs/palisade-triage-guard-" +
        envName,
    });
  }
}
