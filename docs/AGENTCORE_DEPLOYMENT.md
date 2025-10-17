# AgentCore Runtime Deployment Guide

This guide explains how to deploy the AI Honeypot agents to Amazon Bedrock AgentCore Runtime using the Strands Agents framework.

## Architecture Overview

The AI Honeypot system is built using:
- **Strands Agents Framework**: For AI-powered agent implementation
- **Amazon Bedrock AgentCore Runtime**: For serverless agent deployment and scaling
- **Amazon Bedrock**: For AI model inference
- **Prometheus**: For metrics and monitoring

## Prerequisites

1. **AWS Account** with appropriate permissions for:
   - Amazon Bedrock AgentCore
   - Amazon Bedrock model access
   - ECR (for container deployment)

2. **Python 3.11+** installed locally

3. **Docker** (for containerized deployment)

4. **AgentCore CLI** (optional, for easier deployment)
   ```bash
   pip install bedrock-agentcore-starter-toolkit
   ```

## Local Development Setup

1. **Clone and setup the project:**
   ```bash
   git clone <repository-url>
   cd ai-honeypot-agentcore
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Test the agent locally:**
   ```bash
   python deployment/agentcore_deploy.py --test
   ```

## Deployment Options

### Option A: AgentCore Starter Toolkit (Recommended - AWS Official)

This approach uses the official AWS AgentCore starter toolkit for deployment.

1. **Install the starter toolkit:**
   ```bash
   pip install bedrock-agentcore-starter-toolkit
   ```

2. **Configure the agent:**
   ```bash
   agentcore configure -e agent.py
   ```

3. **Deploy to AWS:**
   ```bash
   agentcore launch
   ```

4. **Test the deployed agent:**
   ```bash
   agentcore invoke '{"prompt": "Analyze this potential threat", "type": "threat_analysis", "threat_data": {"source_ip": "192.168.1.100", "failed_attempts": 50}}'
   ```

### Option B: Custom Container Deployment

This approach gives you full control over the deployment.

1. **Build the Docker image:**
   ```bash
   # Setup Docker buildx for ARM64
   docker buildx create --use
   
   # Build the image
   docker buildx build --platform linux/arm64 -t ai-honeypot-detection:latest --load .
   ```

2. **Test locally:**
   ```bash
   docker run --platform linux/arm64 -p 8080:8080 \
     -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
     -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
     -e AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN" \
     -e AWS_REGION="$AWS_REGION" \
     ai-honeypot-detection:latest
   ```

3. **Push to ECR:**
   ```bash
   # Create ECR repository
   aws ecr create-repository --repository-name ai-honeypot-detection --region us-west-2
   
   # Login to ECR
   aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-west-2.amazonaws.com
   
   # Tag and push
   docker tag ai-honeypot-detection:latest <account-id>.dkr.ecr.us-west-2.amazonaws.com/ai-honeypot-detection:latest
   docker push <account-id>.dkr.ecr.us-west-2.amazonaws.com/ai-honeypot-detection:latest
   ```

4. **Deploy to AgentCore Runtime:**
   ```python
   import boto3
   
   client = boto3.client('bedrock-agentcore-control', region_name='us-west-2')
   
   response = client.create_agent_runtime(
       agentRuntimeName='ai-honeypot-detection',
       agentRuntimeArtifact={
           'containerConfiguration': {
               'containerUri': '<account-id>.dkr.ecr.us-west-2.amazonaws.com/ai-honeypot-detection:latest'
           }
       },
       networkConfiguration={"networkMode": "PUBLIC"},
       roleArn='arn:aws:iam::<account-id>:role/AgentRuntimeRole'
   )
   
   print(f"Agent Runtime ARN: {response['agentRuntimeArn']}")
   ```

## Agent Capabilities

The Detection Agent provides the following capabilities:

### 1. Threat Analysis
```python
payload = {
    "prompt": "Analyze this security event",
    "type": "threat_analysis",
    "threat_data": {
        "source_ip": "192.168.1.100",
        "destination_port": 22,
        "protocol": "SSH",
        "failed_attempts": 50,
        "timestamp": "2024-01-15T10:30:00Z"
    }
}
```

### 2. Health Monitoring
```python
payload = {
    "prompt": "Check agent health",
    "type": "health_check"
}
```

### 3. General AI Processing
```python
payload = {
    "prompt": "What are the indicators of a brute force attack?",
    "context": {
        "system_type": "SSH honeypot",
        "recent_activity": "Multiple failed login attempts"
    }
}
```

## Monitoring and Observability

### Metrics
The agent exposes Prometheus metrics on port 9000:
- `agent_messages_processed_total`: Total messages processed
- `agent_message_processing_seconds`: Processing time histogram
- `agent_health_status`: Agent health status (1=healthy, 0=unhealthy)
- `agent_active_sessions`: Number of active sessions

### Logs
Structured logs are available through CloudWatch when deployed to AgentCore Runtime.

### Health Checks
The agent provides health check endpoints:
- `/ping`: Basic health check
- `/health`: Detailed health information

## Configuration

### Environment Variables
- `BEDROCK_MODEL_ID`: Bedrock model to use (default: anthropic.claude-3-haiku-20240307-v1:0)
- `THREAT_THRESHOLD`: Threat detection threshold (default: 0.7)
- `CONFIDENCE_THRESHOLD`: Confidence threshold for alerts (default: 0.6)
- `AWS_REGION`: AWS region for Bedrock access
- `DETECTION_METRICS_PORT`: Port for Prometheus metrics (default: 9000)

### Agent Configuration
```python
config = {
    "threat_threshold": 0.8,
    "confidence_threshold": 0.7,
    "model_id": "anthropic.claude-3-sonnet-20240229-v1:0"
}
```

## Troubleshooting

### Common Issues

1. **Model Access Denied**
   - Ensure your AWS role has Bedrock model access permissions
   - Check that the model is available in your region

2. **Container Build Failures**
   - Ensure Docker buildx is configured for ARM64
   - Check that all dependencies are compatible with ARM64

3. **Agent Runtime Creation Fails**
   - Verify ECR image URI is correct
   - Check IAM role permissions
   - Ensure network configuration is appropriate

### Debug Mode
Enable debug logging by setting:
```bash
export LOG_LEVEL=DEBUG
```

### Local Testing
Always test locally before deploying:
```bash
python deployment/agentcore_deploy.py --test
```

## Security Considerations

1. **IAM Roles**: Use least-privilege IAM roles
2. **Network Security**: Configure appropriate VPC and security groups
3. **Data Protection**: All data is processed in isolated AgentCore Runtime sessions
4. **Monitoring**: Enable CloudWatch logging and monitoring

## Next Steps

1. Deploy additional agent types (Coordinator, Interaction, Intelligence)
2. Set up agent-to-agent communication workflows
3. Configure monitoring and alerting
4. Implement CI/CD pipelines for automated deployment

For more information, see the [Strands Agents Documentation](https://strandsagents.com/latest/) and [AgentCore Runtime Documentation](https://docs.aws.amazon.com/bedrock-agentcore/).