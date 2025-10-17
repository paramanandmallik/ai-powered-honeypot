#!/usr/bin/env python3
"""
AI Honeypot AgentCore Infrastructure CDK App
Main entry point for AWS CDK infrastructure deployment
"""

import aws_cdk as cdk
from constructs import Construct

from stacks.network_stack import NetworkStack
from stacks.database_stack import DatabaseStack
from stacks.storage_stack import StorageStack
from stacks.monitoring_stack import MonitoringStack
from stacks.security_stack import SecurityStack
from stacks.integration_stack import IntegrationStack


class HoneypotInfrastructureApp(cdk.App):
    """Main CDK application for AI Honeypot infrastructure"""
    
    def __init__(self):
        super().__init__()
        
        # Environment configuration
        env = cdk.Environment(
            account=self.node.try_get_context("account"),
            region=self.node.try_get_context("region") or "us-east-1"
        )
        
        # Stack configuration
        stack_props = {
            "env": env,
            "description": "AI Honeypot AgentCore Infrastructure",
            "tags": {
                "Project": "AI-Honeypot-AgentCore",
                "Environment": self.node.try_get_context("environment") or "dev",
                "Owner": "SecurityTeam",
                "CostCenter": "Security-Operations"
            }
        }
        
        # Create network foundation stack
        network_stack = NetworkStack(
            self, "HoneypotNetworkStack",
            **stack_props
        )
        
        # Create security stack (depends on network)
        security_stack = SecurityStack(
            self, "HoneypotSecurityStack",
            vpc=network_stack.vpc,
            **stack_props
        )
        
        # Create database stack (depends on network and security)
        database_stack = DatabaseStack(
            self, "HoneypotDatabaseStack",
            vpc=network_stack.vpc,
            security_groups=security_stack.database_security_groups,
            **stack_props
        )
        
        # Create storage stack
        storage_stack = StorageStack(
            self, "HoneypotStorageStack",
            **stack_props
        )
        
        # Create monitoring stack (depends on all other stacks)
        monitoring_stack = MonitoringStack(
            self, "HoneypotMonitoringStack",
            vpc=network_stack.vpc,
            database=database_stack.database,
            storage_buckets=storage_stack.buckets,
            **stack_props
        )
        
        # Create integration stack (SNS, Lambda, API Gateway)
        integration_stack = IntegrationStack(
            self, "HoneypotIntegrationStack",
            vpc=network_stack.vpc,
            database=database_stack.database,
            storage_buckets=storage_stack.buckets,
            **stack_props
        )
        
        # Set up dependencies
        security_stack.add_dependency(network_stack)
        database_stack.add_dependency(network_stack)
        database_stack.add_dependency(security_stack)
        monitoring_stack.add_dependency(network_stack)
        monitoring_stack.add_dependency(database_stack)
        monitoring_stack.add_dependency(storage_stack)
        integration_stack.add_dependency(network_stack)
        integration_stack.add_dependency(database_stack)
        integration_stack.add_dependency(storage_stack)


if __name__ == "__main__":
    app = HoneypotInfrastructureApp()
    app.synth()