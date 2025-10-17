# AgentCore Runtime Deployment Guide

This guide provides comprehensive instructions for deploying the AI-Powered Honeypot System agents to Amazon Bedrock AgentCore Runtime.

## Overview

The AI-Powered Honeypot System consists of four specialized AI agents that work together to create dynamic, intelligent honeypots:

- **Detection Agent**: Analyzes threats and makes engagement decisions
- **Coordinator Agent**: Orchestrates honeypot lifecycle and agent coordination  
- **Interaction Agent**: Handles real-time attacker interactions
- **Intelligence Agent**: Extracts and analyzes intelligence from sessions

## Prerequisites

### 1. AgentCore Starter Toolkit Installation

```bash
# Install Amazon Bedrock AgentCore starter toolkit
pip install bedrock-agentcore-starter-toolkit

# Also install required dependencies
pip install bedrock-agentcore strands-agents

# Verify installation
agentcore --help
```

### 2. AWS Credentials Configuration

```bash
# Configure AWS credentials
aws configure

# Verify credentials
aws sts get-caller-identity
```

### 3. Required Permissions

Ensure your AWS credentials have the following permissions:
- `bedrock:*` - For AgentCore Runtime operations
- `iam:PassRole` - For agent execution roles
- `logs:*` - For CloudWatch logging
- `s3:*` - For artifact storage (if required)

## Deployment Process

### Step 1: Package Agents

The agents have been pre-packaged for AgentCore Runtime deployment:

```bash
# Run the packaging script (already completed)
python deployment/agentcore_deployment_manager.py
```

**Packaged Agents:**
- `build/agentcore/ai-honeypot-detection-agent-deployment-package.zip`
- `build/agentcore/ai-honeypot-coordinator-agent-deployment-package.zip`
- `build/agentcore/ai-honeypot-interaction-agent-deployment-package.zip`
- `build/agentcore/ai-honeypot-intelligence-agent-deployment-package.zip`

### Step 2: Deploy to AgentCore Runtime

#### Option A: Automated Deployment (Recommended)

```bash
# Run the automated deployment script
python deployment/scripts/deploy_agents_to_agentcore.py
```

#### Option B: Manual Deployment

Deploy each agent individually using the AgentCore starter toolkit:

```bash
# Set your AWS region
export AWS_REGION=us-east-1

# Extract and deploy Detection Agent
cd build/agentcore
unzip ai-honeypot-detection-agent-deployment-package.zip -d detection-agent-temp
cd detection-agent-temp
agentcore configure -e main.py -r $AWS_REGION
agentcore launch
cd ../..

# Extract and deploy Coordinator Agent  
unzip ai-honeypot-coordinator-agent-deployment-package.zip -d coordinator-agent-temp
cd coordinator-agent-temp
agentcore configure -e main.py -r $AWS_REGION
agentcore launch
cd ../..

# Extract and deploy Interaction Agent
unzip ai-honeypot-interaction-agent-deployment-package.zip -d interaction-agent-temp
cd interaction-agent-temp
agentcore configure -e main.py -r $AWS_REGION
agentcore launch
cd ../..

# Extract and deploy Intelligence Agent
unzip ai-honeypot-intelligence-agent-deployment-package.zip -d intelligence-agent-temp
cd intelligence-agent-temp
agentcore configure -e main.py -r $AWS_REGION
agentcore launch
cd ../..
```

### Step 3: Verify Deployment

```bash
# Test each deployed agent
cd build/agentcore/detection-agent-temp
agentcore invoke '{"prompt": "Health check test"}'

cd ../coordinator-agent-temp  
agentcore invoke '{"prompt": "System status check"}'

cd ../interaction-agent-temp
agentcore invoke '{"prompt": "Interaction test"}'

cd ../intelligence-agent-temp
agentcore invoke '{"prompt": "Analysis test"}'
```

### Step 4: Configure Agent Workflows

Agent-to-agent communication in AgentCore Runtime is handled through the runtime's built-in messaging system. Each agent is deployed independently and can be invoked using the AWS SDK:

```python
import boto3
import json

# Initialize the AgentCore client
client = boto3.client('bedrock-agentcore', region_name='us-east-1')

# Invoke an agent
response = client.invoke_agent_runtime(
    agentRuntimeArn='arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime/your-agent-id',
    runtimeSessionId='session-123',
    payload=json.dumps({"prompt": "Your message here"}).encode(),
    qualifier="DEFAULT"
)
```

### Step 5: Validate Deployment

```bash
# Run comprehensive validation
python deployment/scripts/validate_agentcore_deployment.py
```

## Agent Configuration

### Detection Agent Configuration

```yaml
# deployment/agent-configs/detection-agent.yaml
spec:
  scaling:
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
  
  environment:
    - name: DETECTION_CONFIDENCE_THRESHOLD
      value: "0.75"
    - name: MITRE_ATTACK_MAPPING
      value: "true"
```

### Coordinator Agent Configuration

```yaml
# deployment/agent-configs/coordinator-agent.yaml
spec:
  scaling:
    minReplicas: 1
    maxReplicas: 3
    targetCPUUtilizationPercentage: 80
  
  environment:
    - name: MAX_CONCURRENT_HONEYPOTS
      value: "50"
    - name: HONEYPOT_TIMEOUT_MINUTES
      value: "60"
```

### Interaction Agent Configuration

```yaml
# deployment/agent-configs/interaction-agent.yaml
spec:
  scaling:
    minReplicas: 3
    maxReplicas: 20
    targetCPUUtilizationPercentage: 70
  
  environment:
    - name: MAX_CONCURRENT_SESSIONS
      value: "10"
    - name: SESSION_TIMEOUT_MINUTES
      value: "30"
```

### Intelligence Agent Configuration

```yaml
# deployment/agent-configs/intelligence-agent.yaml
spec:
  scaling:
    minReplicas: 2
    maxReplicas: 8
    targetCPUUtilizationPercentage: 75
  
  environment:
    - name: INTELLIGENCE_BATCH_SIZE
      value: "10"
    - name: ANALYSIS_TIMEOUT_SECONDS
      value: "300"
```

## Monitoring and Management

### Health Checks

All agents provide comprehensive health checks:

```bash
# Check overall system health
curl https://your-agentcore-endpoint/health

# Check individual agent health
curl https://your-agentcore-endpoint/agents/detection/health
curl https://your-agentcore-endpoint/agents/coordinator/health
curl https://your-agentcore-endpoint/agents/interaction/health
curl https://your-agentcore-endpoint/agents/intelligence/health
```

### Metrics

Agents expose Prometheus-compatible metrics:

```bash
# View agent metrics
curl https://your-agentcore-endpoint/agents/detection/metrics
```

**Key Metrics:**
- `agent_requests_total` - Total requests processed
- `agent_errors_total` - Total errors encountered
- `agent_response_time_seconds` - Response time distribution
- `threats_evaluated_total` - Threats evaluated (Detection Agent)
- `honeypots_active_total` - Active honeypots (Coordinator Agent)
- `sessions_analyzed_total` - Sessions analyzed (Intelligence Agent)

### Logging

Agents use structured logging with CloudWatch integration:

```bash
# View agent logs
agentcore logs --agent-type detection --region $AWS_REGION --tail
```

## Scaling Configuration

### Auto-Scaling Policies

Agents are configured with auto-scaling based on:
- CPU utilization
- Memory usage
- Request queue depth
- Custom metrics (threat volume, session count)

### Manual Scaling

```bash
# Scale specific agent
agentcore scale --agent-type interaction --replicas 5 --region $AWS_REGION
```

## Troubleshooting

### Common Issues

#### 1. Agent Deployment Fails

```bash
# Check deployment logs
agentcore logs --deployment-id <deployment-id> --region $AWS_REGION

# Common causes:
# - Insufficient IAM permissions
# - Invalid agent configuration
# - Resource limits exceeded
```

#### 2. Agent Health Check Failures

```bash
# Check agent status
agentcore status --agent-type <agent-type> --region $AWS_REGION

# Common causes:
# - Agent startup timeout
# - Configuration errors
# - Resource constraints
```

#### 3. Agent Communication Issues

```bash
# Test agent messaging
agentcore message send \
  --from detection \
  --to coordinator \
  --type test_message \
  --payload '{"test": true}' \
  --region $AWS_REGION
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Update agent configuration
agentcore configure \
  --agent-type <agent-type> \
  --env LOG_LEVEL=DEBUG \
  --region $AWS_REGION
```

## Security Considerations

### Network Isolation

- Agents run in isolated VPC subnets
- No direct internet access (egress through NAT Gateway)
- Security groups restrict inter-agent communication

### Data Protection

- All synthetic data is tagged and tracked
- Real data detection and automatic quarantine
- Encrypted storage for session data and intelligence

### Access Control

- IAM roles with least-privilege access
- Multi-factor authentication for management interfaces
- Audit logging for all administrative actions

## Performance Optimization

### Resource Allocation

**Detection Agent:**
- CPU: 250m-500m
- Memory: 512Mi-1Gi
- Optimized for: Low latency threat analysis

**Coordinator Agent:**
- CPU: 500m-1000m
- Memory: 1Gi-2Gi
- Optimized for: Orchestration and resource management

**Interaction Agent:**
- CPU: 500m-1000m
- Memory: 1Gi-2Gi
- Optimized for: High concurrency and session handling

**Intelligence Agent:**
- CPU: 500m-1000m
- Memory: 1Gi-2Gi
- Optimized for: Batch processing and analysis

### Performance Tuning

```bash
# Adjust scaling thresholds
agentcore configure scaling \
  --agent-type interaction \
  --min-replicas 5 \
  --max-replicas 25 \
  --cpu-threshold 60 \
  --region $AWS_REGION
```

## Backup and Recovery

### Configuration Backup

```bash
# Export agent configurations
agentcore export --all --output backup/agent-configs-$(date +%Y%m%d).json --region $AWS_REGION
```

### Data Backup

- Session data: Automatically archived to S3
- Intelligence reports: Stored in RDS with automated backups
- Agent state: Managed by AgentCore Runtime

### Disaster Recovery

1. **Agent Recovery**: AgentCore Runtime automatically restarts failed agents
2. **Data Recovery**: Restore from S3/RDS backups
3. **Full System Recovery**: Redeploy agents using saved configurations

## Maintenance

### Updates and Rollouts

```bash
# Rolling update of agents
agentcore update \
  --package new-agent-package.zip \
  --agent-type detection \
  --strategy rolling \
  --region $AWS_REGION
```

### Maintenance Windows

- Schedule maintenance during low-threat periods
- Use blue-green deployments for zero-downtime updates
- Monitor system health during and after updates

## Support and Documentation

### Additional Resources

- [AgentCore Runtime Documentation](https://docs.aws.amazon.com/agentcore/)
- [Strands Agents Framework](https://github.com/amazon/strands-agents)
- [AI Honeypot System Architecture](../ARCHITECTURE.md)

### Getting Help

1. Check agent logs and metrics
2. Run validation scripts
3. Review troubleshooting guide
4. Contact support with deployment details

## Appendix

### Environment Variables Reference

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AWS_REGION` | AWS region for deployment | `us-east-1` | Yes |
| `LOG_LEVEL` | Logging level | `INFO` | No |
| `USE_MOCK_AI` | Use mock AI for testing | `false` | No |
| `BEDROCK_MODEL_ID` | Bedrock model identifier | `anthropic.claude-3-haiku-20240307-v1:0` | No |
| `DETECTION_CONFIDENCE_THRESHOLD` | Threat detection threshold | `0.75` | No |
| `MAX_CONCURRENT_HONEYPOTS` | Maximum concurrent honeypots | `50` | No |
| `SESSION_TIMEOUT_MINUTES` | Session timeout | `30` | No |

### Agent Capabilities Matrix

| Agent | Threat Analysis | Honeypot Management | Attacker Interaction | Intelligence Extraction |
|-------|----------------|-------------------|-------------------|----------------------|
| Detection | ✅ | ❌ | ❌ | ❌ |
| Coordinator | ❌ | ✅ | ❌ | ❌ |
| Interaction | ❌ | ❌ | ✅ | ❌ |
| Intelligence | ❌ | ❌ | ❌ | ✅ |

### Workflow Definitions

```json
{
  "workflows": [
    {
      "name": "threat-detection-to-engagement",
      "trigger": {"agent": "detection", "event": "engagement_decision"},
      "steps": [
        {"agent": "coordinator", "action": "create_honeypot"},
        {"agent": "interaction", "action": "initialize_session"}
      ]
    },
    {
      "name": "session-completion-to-analysis", 
      "trigger": {"agent": "interaction", "event": "session_completed"},
      "steps": [
        {"agent": "intelligence", "action": "analyze_session"},
        {"agent": "coordinator", "action": "cleanup_honeypot"}
      ]
    }
  ]
}
```