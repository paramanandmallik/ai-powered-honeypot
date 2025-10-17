#!/usr/bin/env python3
"""
Deployment script for AI Honeypot AgentCore Infrastructure
Handles CDK deployment with proper environment configuration
"""

import os
import sys
import subprocess
import json
import argparse
import boto3
from pathlib import Path


class InfrastructureDeployer:
    """Handles deployment of AI Honeypot infrastructure using CDK"""
    
    def __init__(self, environment: str = "dev", region: str = "us-east-1"):
        self.environment = environment
        self.region = region
        self.account_id = self._get_account_id()
        self.cdk_dir = Path(__file__).parent / "cdk"
        
    def _get_account_id(self) -> str:
        """Get AWS account ID"""
        try:
            sts = boto3.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            print(f"Error getting AWS account ID: {e}")
            sys.exit(1)
    
    def setup_environment(self):
        """Set up CDK environment and install dependencies"""
        print(f"Setting up CDK environment for {self.environment}...")
        
        # Change to CDK directory
        os.chdir(self.cdk_dir)
        
        # Install Python dependencies
        print("Installing CDK dependencies...")
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], check=True)
        
        # Bootstrap CDK if needed
        print(f"Bootstrapping CDK for account {self.account_id} in region {self.region}...")
        subprocess.run([
            "cdk", "bootstrap", 
            f"aws://{self.account_id}/{self.region}",
            "--context", f"environment={self.environment}",
            "--context", f"account={self.account_id}",
            "--context", f"region={self.region}"
        ], check=True)
    
    def validate_stacks(self):
        """Validate CDK stacks before deployment"""
        print("Validating CDK stacks...")
        
        result = subprocess.run([
            "cdk", "synth",
            "--context", f"environment={self.environment}",
            "--context", f"account={self.account_id}",
            "--context", f"region={self.region}"
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"CDK validation failed: {result.stderr}")
            sys.exit(1)
        
        print("CDK stacks validated successfully")
    
    def deploy_stacks(self, stack_names: list = None):
        """Deploy CDK stacks"""
        if stack_names is None:
            stack_names = ["--all"]
        
        print(f"Deploying stacks: {stack_names}")
        
        cmd = [
            "cdk", "deploy"
        ] + stack_names + [
            "--require-approval", "never",
            "--context", f"environment={self.environment}",
            "--context", f"account={self.account_id}",
            "--context", f"region={self.region}",
            "--outputs-file", f"outputs-{self.environment}.json"
        ]
        
        result = subprocess.run(cmd, check=False)
        
        if result.returncode != 0:
            print("CDK deployment failed")
            sys.exit(1)
        
        print("CDK deployment completed successfully")
        
        # Load and display outputs
        self._display_outputs()
    
    def _display_outputs(self):
        """Display CDK stack outputs"""
        outputs_file = self.cdk_dir / f"outputs-{self.environment}.json"
        
        if outputs_file.exists():
            with open(outputs_file, 'r') as f:
                outputs = json.load(f)
            
            print("\n=== Deployment Outputs ===")
            for stack_name, stack_outputs in outputs.items():
                print(f"\n{stack_name}:")
                for key, value in stack_outputs.items():
                    print(f"  {key}: {value}")
        else:
            print("No outputs file found")
    
    def destroy_stacks(self, stack_names: list = None):
        """Destroy CDK stacks"""
        if stack_names is None:
            stack_names = ["--all"]
        
        print(f"Destroying stacks: {stack_names}")
        
        # Confirm destruction
        response = input("Are you sure you want to destroy the infrastructure? (yes/no): ")
        if response.lower() != "yes":
            print("Destruction cancelled")
            return
        
        cmd = [
            "cdk", "destroy"
        ] + stack_names + [
            "--force",
            "--context", f"environment={self.environment}",
            "--context", f"account={self.account_id}",
            "--context", f"region={self.region}"
        ]
        
        result = subprocess.run(cmd, check=False)
        
        if result.returncode != 0:
            print("CDK destruction failed")
            sys.exit(1)
        
        print("CDK destruction completed successfully")
    
    def list_stacks(self):
        """List available CDK stacks"""
        print("Available CDK stacks:")
        
        result = subprocess.run([
            "cdk", "list",
            "--context", f"environment={self.environment}",
            "--context", f"account={self.account_id}",
            "--context", f"region={self.region}"
        ], capture_output=True, text=True, check=True)
        
        print(result.stdout)
    
    def diff_stacks(self, stack_names: list = None):
        """Show differences between deployed and local stacks"""
        if stack_names is None:
            stack_names = ["--all"]
        
        print(f"Showing differences for stacks: {stack_names}")
        
        cmd = [
            "cdk", "diff"
        ] + stack_names + [
            "--context", f"environment={self.environment}",
            "--context", f"account={self.account_id}",
            "--context", f"region={self.region}"
        ]
        
        subprocess.run(cmd, check=False)


def main():
    """Main deployment script"""
    parser = argparse.ArgumentParser(description="Deploy AI Honeypot Infrastructure")
    parser.add_argument("--environment", "-e", default="dev", 
                       help="Deployment environment (dev, staging, prod)")
    parser.add_argument("--region", "-r", default="us-east-1",
                       help="AWS region for deployment")
    parser.add_argument("--action", "-a", required=True,
                       choices=["deploy", "destroy", "list", "diff", "validate"],
                       help="Action to perform")
    parser.add_argument("--stacks", "-s", nargs="*",
                       help="Specific stacks to deploy/destroy")
    
    args = parser.parse_args()
    
    # Validate environment
    if args.environment not in ["dev", "staging", "prod"]:
        print("Error: Environment must be one of: dev, staging, prod")
        sys.exit(1)
    
    # Create deployer
    deployer = InfrastructureDeployer(args.environment, args.region)
    
    try:
        if args.action == "deploy":
            deployer.setup_environment()
            deployer.validate_stacks()
            deployer.deploy_stacks(args.stacks)
        elif args.action == "destroy":
            deployer.destroy_stacks(args.stacks)
        elif args.action == "list":
            deployer.list_stacks()
        elif args.action == "diff":
            deployer.diff_stacks(args.stacks)
        elif args.action == "validate":
            deployer.setup_environment()
            deployer.validate_stacks()
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()