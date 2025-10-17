#!/usr/bin/env python3
"""
Deployment script for Coordinator Agent to Amazon Bedrock AgentCore Runtime
This script packages and deploys the coordinator agent with all its dependencies.
"""

import os
import sys
import json
import zipfile
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CoordinatorAgentDeployer:
    """Deploys the Coordinator Agent to AgentCore Runtime"""
    
    def __init__(self, region: str = "us-west-2"):
        self.region = region
        self.agent_name = "ai-honeypot-coordinator-agent"
        self.agent_version = "1.0.0"
        
        # Initialize AWS clients
        try:
            self.bedrock_agent = boto3.client('bedrock-agent', region_name=region)
            self.bedrock_runtime = boto3.client('bedrock-agent-runtime', region_name=region)
            self.s3_client = boto3.client('s3', region_name=region)
            logger.info(f"Initialized AWS clients for region: {region}")
        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure your credentials.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            sys.exit(1)
    
    def create_agent_package(self) -> str:
        """Create deployment package for the coordinator agent"""
        try:
            logger.info("Creating agent deployment package...")
            
            package_path = "coordinator-agent-package.zip"
            
            with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add agent source code
                self._add_directory_to_zip(zipf, "agents/coordinator", "agents/coordinator")
                self._add_directory_to_zip(zipf, "agents/base_agent.py", "agents/base_agent.py")
                
                # Add configuration files
                self._add_directory_to_zip(zipf, "config", "config")
                
                # Add requirements
                if os.path.exists("requirements.txt"):
                    zipf.write("requirements.txt", "requirements.txt")
                
                # Add agent configuration
                zipf.write("deployment/agent-configs/coordinator-agent-complete.yaml", "agent.yaml")
                
                # Add main entry point
                self._create_agent_entry_point(zipf)
            
            logger.info(f"Created deployment package: {package_path}")
            return package_path
            
        except Exception as e:
            logger.error(f"Failed to create agent package: {e}")
            raise
    
    def _add_directory_to_zip(self, zipf: zipfile.ZipFile, source_path: str, archive_path: str):
        """Add directory or file to zip archive"""
        source = Path(source_path)
        
        if source.is_file():
            zipf.write(source, archive_path)
        elif source.is_dir():
            for file_path in source.rglob("*"):
                if file_path.is_file() and not file_path.name.startswith('.'):
                    relative_path = file_path.relative_to(source.parent)
                    zipf.write(file_path, str(relative_path))
    
    def _create_agent_entry_point(self, zipf: zipfile.ZipFile):
        """Create the main entry point for AgentCore Runtime"""
        entry_point_code = '''#!/usr/bin/env python3
"""
AgentCore Runtime entry point for Coordinator Agent
"""

import asyncio
import json
import logging
import os
from agents.coordinator.coordinator_agent import CoordinatorAgent

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global coordinator agent instance
coordinator_agent = None

async def initialize_agent():
    """Initialize the coordinator agent"""
    global coordinator_agent
    
    try:
        # Load configuration from environment
        config = {
            "auto_scaling_enabled": os.getenv("AUTO_SCALING_ENABLED", "true").lower() == "true",
            "max_concurrent_engagements": int(os.getenv("MAX_CONCURRENT_ENGAGEMENTS", "10")),
            "honeypot_timeout_minutes": int(os.getenv("HONEYPOT_TIMEOUT_MINUTES", "60")),
            "workflow_cleanup_interval": int(os.getenv("WORKFLOW_CLEANUP_INTERVAL", "3600")),
            "health_check_interval": int(os.getenv("HEALTH_CHECK_INTERVAL", "30"))
        }
        
        # Create and initialize coordinator agent
        coordinator_agent = CoordinatorAgent(config)
        await coordinator_agent.initialize()
        
        logger.info("Coordinator Agent initialized successfully")
        return coordinator_agent
        
    except Exception as e:
        logger.error(f"Failed to initialize coordinator agent: {e}")
        raise

def lambda_handler(event, context):
    """AWS Lambda handler for AgentCore Runtime"""
    try:
        # Initialize agent if not already done
        if coordinator_agent is None:
            asyncio.run(initialize_agent())
        
        # Extract input from event
        user_input = event.get("inputText", "")
        session_id = event.get("sessionId", "default")
        
        # Process with coordinator agent
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Create message for coordinator
            message = {
                "message_type": "user_request",
                "payload": {
                    "input": user_input,
                    "session_id": session_id,
                    "timestamp": event.get("timestamp")
                }
            }
            
            # Process message
            response = loop.run_until_complete(
                coordinator_agent.process_message(message)
            )
            
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "response": response,
                    "agent_id": coordinator_agent.agent_id,
                    "agent_type": "coordinator"
                })
            }
            
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e),
                "agent_type": "coordinator"
            })
        }

# For AgentCore Runtime direct invocation
async def agentcore_handler(payload):
    """Direct AgentCore Runtime handler"""
    try:
        # Initialize agent if needed
        if coordinator_agent is None:
            await initialize_agent()
        
        # Process the payload
        message = {
            "message_type": payload.get("message_type", "user_request"),
            "payload": payload
        }
        
        response = await coordinator_agent.process_message(message)
        
        return {
            "success": True,
            "response": response,
            "agent_id": coordinator_agent.agent_id,
            "agent_type": "coordinator"
        }
        
    except Exception as e:
        logger.error(f"Error in AgentCore handler: {e}")
        return {
            "success": False,
            "error": str(e),
            "agent_type": "coordinator"
        }

if __name__ == "__main__":
    # For local testing
    asyncio.run(initialize_agent())
    print("Coordinator Agent is running...")
'''
        
        zipf.writestr("main.py", entry_point_code)
    
    def upload_package_to_s3(self, package_path: str, bucket_name: str) -> str:
        """Upload agent package to S3"""
        try:
            key = f"agentcore/packages/{self.agent_name}-{self.agent_version}.zip"
            
            logger.info(f"Uploading package to S3: s3://{bucket_name}/{key}")
            
            self.s3_client.upload_file(package_path, bucket_name, key)
            
            s3_uri = f"s3://{bucket_name}/{key}"
            logger.info(f"Package uploaded successfully: {s3_uri}")
            
            return s3_uri
            
        except Exception as e:
            logger.error(f"Failed to upload package to S3: {e}")
            raise
    
    def create_bedrock_agent(self, package_s3_uri: str) -> Dict[str, Any]:
        """Create or update Bedrock Agent"""
        try:
            logger.info("Creating/updating Bedrock Agent...")
            
            # Agent configuration
            agent_config = {
                "agentName": self.agent_name,
                "description": "AI-powered coordinator agent for honeypot system orchestration",
                "foundationModel": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                "instruction": self._get_agent_instruction(),
                "agentResourceRoleArn": self._get_or_create_agent_role(),
                "customerEncryptionKeyArn": None,  # Use default encryption
                "tags": {
                    "System": "ai-honeypot",
                    "Component": "coordinator",
                    "Version": self.agent_version,
                    "Environment": os.getenv("ENVIRONMENT", "production")
                }
            }
            
            try:
                # Try to update existing agent
                response = self.bedrock_agent.update_agent(**agent_config)
                logger.info("Updated existing Bedrock Agent")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # Create new agent
                    response = self.bedrock_agent.create_agent(**agent_config)
                    logger.info("Created new Bedrock Agent")
                else:
                    raise
            
            agent_id = response['agent']['agentId']
            logger.info(f"Agent ID: {agent_id}")
            
            # Create agent version
            version_response = self.bedrock_agent.create_agent_version(
                agentId=agent_id,
                description=f"Version {self.agent_version} of coordinator agent"
            )
            
            agent_version = version_response['agentVersion']['version']
            logger.info(f"Created agent version: {agent_version}")
            
            return {
                "agent_id": agent_id,
                "agent_version": agent_version,
                "agent_arn": response['agent']['agentArn']
            }
            
        except Exception as e:
            logger.error(f"Failed to create Bedrock Agent: {e}")
            raise
    
    def _get_agent_instruction(self) -> str:
        """Get the system instruction for the agent"""
        return """You are the Coordinator Agent in an AI-powered honeypot security system. Your primary role is to orchestrate the entire system lifecycle and coordinate between all other agents.

Your responsibilities include:
1. Managing honeypot creation, configuration, and destruction workflows
2. Coordinating communication and workflows between Detection, Interaction, and Intelligence agents
3. Making resource allocation and auto-scaling decisions based on system load
4. Implementing emergency shutdown procedures and safety controls
5. Monitoring system health and performance metrics
6. Ensuring proper isolation and security controls are maintained

You have access to comprehensive tools for:
- Creating and managing honeypot instances
- Orchestrating multi-agent workflows
- Allocating and managing system resources
- Monitoring system health and performance
- Implementing emergency procedures
- Generating alerts and notifications

Always prioritize security and safety. When in doubt, err on the side of caution and implement appropriate safety measures.
Maintain detailed audit logs of all actions and decisions.
Respond to emergencies quickly and decisively.

When processing requests:
1. Analyze the request type and determine appropriate actions
2. Check system status and resource availability
3. Execute workflows in the correct sequence
4. Monitor progress and handle any errors
5. Provide clear status updates and results
6. Log all activities for audit purposes"""
    
    def _get_or_create_agent_role(self) -> str:
        """Get or create IAM role for the agent"""
        # This would typically create an IAM role with appropriate permissions
        # For now, return a placeholder - in production, this should be properly configured
        role_arn = os.getenv("BEDROCK_AGENT_ROLE_ARN")
        if not role_arn:
            logger.warning("BEDROCK_AGENT_ROLE_ARN not set. Using default role.")
            role_arn = f"arn:aws:iam::{self._get_account_id()}:role/BedrockAgentRole"
        
        return role_arn
    
    def _get_account_id(self) -> str:
        """Get AWS account ID"""
        try:
            sts = boto3.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception:
            return "123456789012"  # Placeholder
    
    def create_agent_alias(self, agent_id: str, agent_version: str) -> Dict[str, Any]:
        """Create agent alias for production use"""
        try:
            logger.info("Creating agent alias...")
            
            alias_response = self.bedrock_agent.create_agent_alias(
                agentId=agent_id,
                agentAliasName="production",
                description="Production alias for coordinator agent",
                agentVersion=agent_version,
                tags={
                    "Environment": "production",
                    "System": "ai-honeypot"
                }
            )
            
            alias_id = alias_response['agentAlias']['agentAliasId']
            logger.info(f"Created agent alias: {alias_id}")
            
            return {
                "alias_id": alias_id,
                "alias_arn": alias_response['agentAlias']['agentAliasArn']
            }
            
        except Exception as e:
            logger.error(f"Failed to create agent alias: {e}")
            raise
    
    def deploy(self, s3_bucket: str) -> Dict[str, Any]:
        """Deploy the coordinator agent to AgentCore Runtime"""
        try:
            logger.info("Starting Coordinator Agent deployment...")
            
            # Step 1: Create deployment package
            package_path = self.create_agent_package()
            
            # Step 2: Upload to S3
            package_s3_uri = self.upload_package_to_s3(package_path, s3_bucket)
            
            # Step 3: Create/update Bedrock Agent
            agent_info = self.create_bedrock_agent(package_s3_uri)
            
            # Step 4: Create agent alias
            alias_info = self.create_agent_alias(
                agent_info["agent_id"], 
                agent_info["agent_version"]
            )
            
            # Step 5: Clean up local package
            os.remove(package_path)
            
            deployment_result = {
                "status": "success",
                "agent_id": agent_info["agent_id"],
                "agent_version": agent_info["agent_version"],
                "agent_arn": agent_info["agent_arn"],
                "alias_id": alias_info["alias_id"],
                "alias_arn": alias_info["alias_arn"],
                "package_s3_uri": package_s3_uri,
                "region": self.region
            }
            
            logger.info("Coordinator Agent deployment completed successfully!")
            logger.info(f"Agent ARN: {agent_info['agent_arn']}")
            logger.info(f"Alias ARN: {alias_info['alias_arn']}")
            
            return deployment_result
            
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            raise


def main():
    """Main deployment function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Deploy Coordinator Agent to AgentCore Runtime")
    parser.add_argument("--region", default="us-west-2", help="AWS region")
    parser.add_argument("--s3-bucket", required=True, help="S3 bucket for deployment packages")
    parser.add_argument("--environment", default="production", help="Deployment environment")
    
    args = parser.parse_args()
    
    # Set environment variable
    os.environ["ENVIRONMENT"] = args.environment
    
    try:
        # Create deployer and deploy
        deployer = CoordinatorAgentDeployer(region=args.region)
        result = deployer.deploy(args.s3_bucket)
        
        # Save deployment info
        with open("coordinator_deployment_result.json", "w") as f:
            json.dump(result, f, indent=2)
        
        print("\n" + "="*60)
        print("COORDINATOR AGENT DEPLOYMENT SUCCESSFUL")
        print("="*60)
        print(f"Agent ID: {result['agent_id']}")
        print(f"Agent ARN: {result['agent_arn']}")
        print(f"Alias ARN: {result['alias_arn']}")
        print(f"Region: {result['region']}")
        print(f"Deployment info saved to: coordinator_deployment_result.json")
        print("="*60)
        
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()