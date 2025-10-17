#!/usr/bin/env python3
"""
AWS CloudFormation Deployment Script for AI-Powered Honeypot Dashboard
Deploys the dashboard using the CloudFormation template
"""

import boto3
import json
import time
import sys
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

class CloudFormationDeployer:
    def __init__(self):
        self.stack_name = "honeypot-dashboard"
        self.template_file = "cloudformation-template.yaml"
        
        # Initialize AWS clients
        try:
            self.cf_client = boto3.client('cloudformation')
            self.sts_client = boto3.client('sts')
            
            # Get current AWS account info
            self.account_id = self.sts_client.get_caller_identity()['Account']
            self.region = boto3.Session().region_name or 'us-west-2'
            
        except NoCredentialsError:
            print("❌ AWS credentials not configured!")
            print("Please run: aws configure")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error initializing AWS clients: {e}")
            sys.exit(1)

    def check_prerequisites(self):
        """Check if AWS CLI is configured and accessible"""
        print("🔐 Checking AWS credentials...")
        
        try:
            identity = self.sts_client.get_caller_identity()
            print(f"✅ AWS Account: {identity['Account']}")
            print(f"✅ AWS Region: {self.region}")
            print(f"✅ AWS User/Role: {identity.get('Arn', 'Unknown')}")
            return True
        except Exception as e:
            print(f"❌ AWS credential check failed: {e}")
            return False

    def read_template(self):
        """Read the CloudFormation template"""
        try:
            with open(self.template_file, 'r') as f:
                return f.read()
        except FileNotFoundError:
            print(f"❌ Template file {self.template_file} not found!")
            return None
        except Exception as e:
            print(f"❌ Error reading template: {e}")
            return None

    def stack_exists(self):
        """Check if the CloudFormation stack already exists"""
        try:
            self.cf_client.describe_stacks(StackName=self.stack_name)
            return True
        except ClientError as e:
            if 'does not exist' in str(e):
                return False
            raise e

    def deploy_stack(self, template_body):
        """Deploy or update the CloudFormation stack"""
        parameters = [
            {
                'ParameterKey': 'DashboardName',
                'ParameterValue': 'honeypot-dashboard'
            }
        ]
        
        capabilities = ['CAPABILITY_IAM']
        
        try:
            if self.stack_exists():
                print(f"📦 Updating existing stack: {self.stack_name}")
                response = self.cf_client.update_stack(
                    StackName=self.stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=capabilities
                )
                operation = "UPDATE"
            else:
                print(f"🏗️ Creating new stack: {self.stack_name}")
                response = self.cf_client.create_stack(
                    StackName=self.stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=capabilities
                )
                operation = "CREATE"
            
            stack_id = response['StackId']
            print(f"✅ Stack {operation} initiated: {stack_id}")
            return operation
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ValidationError' and 'No updates are to be performed' in str(e):
                print("ℹ️ No changes detected in stack")
                return "NO_CHANGE"
            else:
                print(f"❌ Stack {operation.lower()} failed: {e}")
                return None

    def wait_for_completion(self, operation):
        """Wait for stack operation to complete"""
        if operation == "NO_CHANGE":
            return True
            
        print(f"⏳ Waiting for stack {operation.lower()} to complete...")
        
        if operation == "CREATE":
            waiter = self.cf_client.get_waiter('stack_create_complete')
        else:  # UPDATE
            waiter = self.cf_client.get_waiter('stack_update_complete')
        
        try:
            waiter.wait(
                StackName=self.stack_name,
                WaiterConfig={
                    'Delay': 10,
                    'MaxAttempts': 60  # 10 minutes max
                }
            )
            print(f"✅ Stack {operation.lower()} completed successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Stack {operation.lower()} failed: {e}")
            
            # Get stack events for debugging
            try:
                events = self.cf_client.describe_stack_events(StackName=self.stack_name)
                print("\n📋 Recent stack events:")
                for event in events['StackEvents'][:5]:  # Show last 5 events
                    timestamp = event['Timestamp'].strftime('%H:%M:%S')
                    resource = event.get('LogicalResourceId', 'Unknown')
                    status = event.get('ResourceStatus', 'Unknown')
                    reason = event.get('ResourceStatusReason', '')
                    print(f"  {timestamp} - {resource}: {status} {reason}")
            except:
                pass
                
            return False

    def get_stack_outputs(self):
        """Get stack outputs including the dashboard URL"""
        try:
            response = self.cf_client.describe_stacks(StackName=self.stack_name)
            stack = response['Stacks'][0]
            
            outputs = {}
            if 'Outputs' in stack:
                for output in stack['Outputs']:
                    outputs[output['OutputKey']] = output['OutputValue']
            
            return outputs
            
        except Exception as e:
            print(f"❌ Error getting stack outputs: {e}")
            return {}

    def deploy(self):
        """Main deployment function"""
        print("🚀 Starting AWS CloudFormation Deployment")
        print("=" * 50)
        
        # Check prerequisites
        if not self.check_prerequisites():
            return False
        
        # Read template
        template_body = self.read_template()
        if not template_body:
            return False
        
        print(f"\n📦 Deployment Configuration:")
        print(f"   Stack Name: {self.stack_name}")
        print(f"   Region: {self.region}")
        print(f"   Account: {self.account_id}")
        
        # Deploy stack
        operation = self.deploy_stack(template_body)
        if not operation:
            return False
        
        # Wait for completion
        if not self.wait_for_completion(operation):
            return False
        
        # Get outputs
        outputs = self.get_stack_outputs()
        
        print("\n🎉 Deployment Complete!")
        print("=" * 50)
        
        if 'DashboardUrl' in outputs:
            print(f"📊 Dashboard URL: {outputs['DashboardUrl']}")
        
        if 'LambdaFunctionArn' in outputs:
            print(f"⚡ Lambda Function: {outputs['LambdaFunctionArn']}")
        
        print(f"\n💡 You can now access your AI-Powered Honeypot Dashboard!")
        print(f"🔗 Direct link: {outputs.get('DashboardUrl', 'Check AWS Console')}")
        
        return True

def main():
    """Main function"""
    deployer = CloudFormationDeployer()
    
    try:
        success = deployer.deploy()
        if success:
            print(f"\n✅ Deployment successful at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            sys.exit(0)
        else:
            print(f"\n❌ Deployment failed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Deployment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()