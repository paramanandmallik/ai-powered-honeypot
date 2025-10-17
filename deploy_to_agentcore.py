#!/usr/bin/env python3
"""
Deploy AI Honeypot Detection Agent to Amazon Bedrock AgentCore Runtime
Following AWS official documentation patterns and best practices.
"""

import os
import sys
import logging
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_prerequisites():
    """Check all prerequisites are met before deployment"""
    logger.info("🔍 Checking prerequisites...")
    
    # Check Python version
    if sys.version_info < (3, 10):
        logger.error("❌ Python 3.10+ required")
        return False
    logger.info("✅ Python version check passed")
    
    # Check AWS CLI
    try:
        result = subprocess.run(['aws', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("✅ AWS CLI available")
        else:
            logger.warning("⚠️ AWS CLI not found - deployment may require manual steps")
    except FileNotFoundError:
        logger.warning("⚠️ AWS CLI not found - deployment may require manual steps")
    
    # Check required files
    required_files = ['agent.py', 'requirements.txt']
    for file in required_files:
        if not Path(file).exists():
            logger.error(f"❌ Required file missing: {file}")
            return False
        logger.info(f"✅ Found {file}")
    
    return True

def install_agentcore_toolkit():
    """Install the AgentCore starter toolkit"""
    logger.info("📦 Installing AgentCore starter toolkit...")
    
    try:
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', 
            'bedrock-agentcore-starter-toolkit'
        ], check=True)
        logger.info("✅ AgentCore starter toolkit installed")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to install toolkit: {e}")
        return False

def configure_agent():
    """Configure the agent for deployment"""
    logger.info("⚙️ Configuring agent for AgentCore Runtime...")
    
    try:
        # Configure the agent using the toolkit
        subprocess.run([
            'agentcore', 'configure', 
            '--entrypoint', 'agent.py'
        ], check=True)
        logger.info("✅ Agent configured successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to configure agent: {e}")
        return False
    except FileNotFoundError:
        logger.error("❌ agentcore command not found. Install bedrock-agentcore-starter-toolkit")
        return False

def test_local_deployment():
    """Test the agent locally before deploying to AWS"""
    logger.info("🧪 Testing agent locally...")
    
    try:
        # Test local deployment
        logger.info("Starting local test (this may take a moment)...")
        result = subprocess.run([
            'agentcore', 'launch', '--local'
        ], timeout=60, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("✅ Local test passed")
            return True
        else:
            logger.warning("⚠️ Local test had issues, but continuing...")
            logger.info(f"Output: {result.stdout}")
            logger.info(f"Error: {result.stderr}")
            return True  # Continue anyway
            
    except subprocess.TimeoutExpired:
        logger.warning("⚠️ Local test timed out, but continuing...")
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"⚠️ Local test failed: {e}, but continuing...")
        return True
    except FileNotFoundError:
        logger.error("❌ agentcore command not found")
        return False

def deploy_to_aws():
    """Deploy the agent to AWS AgentCore Runtime"""
    logger.info("🚀 Deploying to AWS AgentCore Runtime...")
    
    try:
        # Deploy to AWS
        result = subprocess.run([
            'agentcore', 'launch'
        ], check=True, capture_output=True, text=True)
        
        logger.info("✅ Deployment successful!")
        logger.info("📋 Deployment output:")
        logger.info(result.stdout)
        
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Deployment failed: {e}")
        logger.error(f"Error output: {e.stderr}")
        return False

def test_deployed_agent():
    """Test the deployed agent"""
    logger.info("🧪 Testing deployed agent...")
    
    try:
        # Test the deployed agent
        test_payload = '{"prompt": "Hello from deployed agent", "type": "health_check"}'
        result = subprocess.run([
            'agentcore', 'invoke', test_payload
        ], check=True, capture_output=True, text=True)
        
        logger.info("✅ Deployed agent test successful!")
        logger.info(f"Response: {result.stdout}")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Deployed agent test failed: {e}")
        return False

def main():
    """Main deployment function"""
    logger.info("🎯 Starting AI Honeypot Detection Agent deployment to AgentCore Runtime")
    logger.info("📚 Following AWS official documentation patterns")
    
    # Step 1: Check prerequisites
    if not check_prerequisites():
        logger.error("❌ Prerequisites not met. Please fix issues and try again.")
        sys.exit(1)
    
    # Step 2: Install toolkit
    if not install_agentcore_toolkit():
        logger.error("❌ Failed to install AgentCore toolkit")
        sys.exit(1)
    
    # Step 3: Configure agent
    if not configure_agent():
        logger.error("❌ Failed to configure agent")
        sys.exit(1)
    
    # Step 4: Test locally (optional but recommended)
    logger.info("🤔 Would you like to test locally first? (Recommended)")
    response = input("Test locally? (y/n): ").lower().strip()
    if response in ['y', 'yes', '']:
        if not test_local_deployment():
            logger.warning("⚠️ Local test had issues, but continuing...")
    
    # Step 5: Deploy to AWS
    logger.info("🤔 Ready to deploy to AWS AgentCore Runtime?")
    response = input("Deploy to AWS? (y/n): ").lower().strip()
    if response not in ['y', 'yes']:
        logger.info("🛑 Deployment cancelled by user")
        sys.exit(0)
    
    if not deploy_to_aws():
        logger.error("❌ Deployment failed")
        sys.exit(1)
    
    # Step 6: Test deployed agent
    logger.info("🤔 Would you like to test the deployed agent?")
    response = input("Test deployed agent? (y/n): ").lower().strip()
    if response in ['y', 'yes', '']:
        test_deployed_agent()
    
    logger.info("🎉 Deployment process completed!")
    logger.info("📖 For more information, see: https://docs.aws.amazon.com/bedrock-agentcore/")

if __name__ == "__main__":
    main()