"""
Network Stack for AI Honeypot AgentCore Infrastructure
Provides VPC, subnets, and network isolation for honeypot system
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
    aws_logs as logs,
    Stack
)
from constructs import Construct


class NetworkStack(Stack):
    """Network infrastructure stack for AI Honeypot system"""
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create VPC with isolated subnets for honeypot infrastructure
        self.vpc = ec2.Vpc(
            self, "HoneypotVPC",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=3,
            nat_gateways=1,  # Minimal NAT for cost optimization
            subnet_configuration=[
                # Public subnets for NAT gateways and load balancers
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                # Private subnets for AgentCore Runtime and supporting services
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                ),
                # Isolated subnets for honeypot infrastructure (no internet access)
                ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24
                )
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True
        )
        
        # Create VPC Flow Logs for network monitoring
        self.flow_logs = ec2.FlowLog(
            self, "HoneypotVPCFlowLogs",
            resource_type=ec2.FlowLogResourceType.from_vpc(self.vpc),
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                logs.LogGroup(
                    self, "VPCFlowLogsGroup",
                    log_group_name="/aws/vpc/honeypot-flowlogs",
                    retention=logs.RetentionDays.ONE_MONTH,
                    removal_policy=cdk.RemovalPolicy.DESTROY
                )
            ),
            traffic_type=ec2.FlowLogTrafficType.ALL
        )
        
        # Create VPC Endpoints for AWS services (reduce NAT costs and improve security)
        self.s3_endpoint = self.vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )
        
        self.dynamodb_endpoint = self.vpc.add_gateway_endpoint(
            "DynamoDBEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )
        
        # Interface endpoints for other AWS services
        self.cloudwatch_endpoint = self.vpc.add_interface_endpoint(
            "CloudWatchEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )
        
        self.logs_endpoint = self.vpc.add_interface_endpoint(
            "LogsEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )
        
        self.sns_endpoint = self.vpc.add_interface_endpoint(
            "SNSEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SNS,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )
        
        # Network ACLs for additional security
        self.create_network_acls()
        
        # Output important network information
        cdk.CfnOutput(
            self, "VPCId",
            value=self.vpc.vpc_id,
            description="VPC ID for AI Honeypot infrastructure"
        )
        
        cdk.CfnOutput(
            self, "PrivateSubnetIds",
            value=",".join([subnet.subnet_id for subnet in self.vpc.private_subnets]),
            description="Private subnet IDs for AgentCore Runtime"
        )
        
        cdk.CfnOutput(
            self, "IsolatedSubnetIds",
            value=",".join([subnet.subnet_id for subnet in self.vpc.isolated_subnets]),
            description="Isolated subnet IDs for honeypot infrastructure"
        )
    
    def create_network_acls(self):
        """Create restrictive Network ACLs for honeypot isolation"""
        
        # Network ACL for isolated honeypot subnets
        honeypot_nacl = ec2.NetworkAcl(
            self, "HoneypotNetworkACL",
            vpc=self.vpc,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)
        )
        
        # Allow inbound traffic from private subnets only (AgentCore agents)
        honeypot_nacl.add_entry(
            "AllowInboundFromPrivate",
            rule_number=100,
            cidr=ec2.AclCidr.ipv4("10.0.1.0/24"),  # Private subnet CIDR
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW
        )
        
        # Allow outbound traffic to private subnets only
        honeypot_nacl.add_entry(
            "AllowOutboundToPrivate",
            rule_number=100,
            cidr=ec2.AclCidr.ipv4("10.0.1.0/24"),  # Private subnet CIDR
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW
        )
        
        # Deny all other traffic (explicit deny for security)
        honeypot_nacl.add_entry(
            "DenyAllOtherInbound",
            rule_number=200,
            cidr=ec2.AclCidr.any_ipv4(),
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.DENY
        )
        
        honeypot_nacl.add_entry(
            "DenyAllOtherOutbound",
            rule_number=200,
            cidr=ec2.AclCidr.any_ipv4(),
            traffic=ec2.AclTraffic.all_traffic(),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.DENY
        )