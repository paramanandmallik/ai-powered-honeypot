# Deployment and Maintenance Guide

## Overview

This guide covers the deployment procedures, maintenance tasks, and operational procedures for the AI-Powered Honeypot System on Amazon AgentCore Runtime.

## Deployment Architecture

### Environment Overview

The system supports multiple deployment environments:

- **Development**: Local Docker environment with mock AgentCore
- **Staging**: AgentCore Runtime with limited AWS resources
- **Production**: Full AgentCore Runtime deployment with complete AWS infrastructure

### Prerequisites

#### System Requirements
- Amazon AgentCore Runtime access
- AWS Account with appropriate permissions
- Docker and Docker Compose (for local development)
- Python 3.9+ with pip
- AWS CLI configured
- AgentCore CLI tools

#### Required AWS Services
- Amazon Bedrock AgentCore Runtime
- Amazon RDS (PostgreSQL)
- Amazon S3
- Amazon VPC
- Amazon CloudWatch
- Amazon SNS
- AWS Lambda

## Local Development Deployment

### Setup Development Environment

```bash
# Clone repository
git clone <repository-url>
cd ai-honeypot-agentcore

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env with your configuration

# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# Initialize database
python scripts/initialize_system.py

# Run local validation
python run_local_validation.py
```

### Development Environment Components

```yaml
# docker-compose.dev.yml
version: '3.8'
services:
  mock-agentcore:
    build:
      context: .
      dockerfile: deployment/docker/Dockerfile.mock-agentcore
    ports:
      - "8080:8080"
    environment:
      - LOG_LEVEL=DEBUG
      
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: honeypot_dev
      POSTGRES_USER: honeypot
      POSTGRES_PASSWORD: dev_password
    ports:
      - "5432:5432"
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
      
  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"
      
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - ./deployment/grafana:/etc/grafana/provisioning
```

## AgentCore Runtime Deployment

### Agent Preparation

#### 1. Build Agent Packages

```bash
# Build all agent packages
python deployment/scripts/build_agent_packages.py

# Validate agent configurations
python deployment/scripts/validate_agent_configs.py

# Test agent packages locally
python deployment/scripts/test_agent_packages.py
```

#### 2. Agent Configuration Files

**Detection Agent Configuration**
```yaml
# deployment/agent-configs/detection-agent.yaml
apiVersion: agentcore.aws.amazon.com/v1
kind: Agent
metadata:
  name: detection-agent
  namespace: honeypot-system
spec:
  image: honeypot-system/detection-agent:latest
  replicas: 2
  resources:
    requests:
      memory: "512Mi"
      cpu: "250m"
    limits:
      memory: "1Gi"
      cpu: "500m"
  environment:
    - name: AGENT_ID
      value: "detection-agent"
    - name: LOG_LEVEL
      value: "INFO"
    - name: THREAT_THRESHOLD
      value: "0.75"
  healthCheck:
    path: "/health"
    port: 8080
    initialDelaySeconds: 30
    periodSeconds: 10
  scaling:
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
```

### Deployment Process

#### 1. Deploy AWS Infrastructure

```bash
# Deploy AWS infrastructure using CDK
cd infrastructure/cdk
npm install
cdk bootstrap
cdk deploy --all

# Verify infrastructure deployment
python ../validate_deployment.py
```

#### 2. Deploy Agents to AgentCore Runtime

```python
# deployment/scripts/deploy_to_agentcore.py
import asyncio
from agentcore_runtime import AgentCoreClient

async def deploy_honeypot_system():
    client = AgentCoreClient()
    
    # Deploy agents in dependency order
    deployment_order = [
        "coordinator-agent",
        "detection-agent", 
        "interaction-agent",
        "intelligence-agent"
    ]
    
    deployed_agents = []
    
    try:
        for agent_name in deployment_order:
            print(f"Deploying {agent_name}...")
            
            # Deploy agent
            config_path = f"deployment/agent-configs/{agent_name}.yaml"
            deployment = await client.deploy_agent_from_config(config_path)
            
            # Wait for deployment to be ready
            await client.wait_for_deployment_ready(
                deployment.id, 
                timeout=300,
                check_interval=10
            )
            
            # Verify agent health
            health = await client.check_agent_health(agent_name)
            if health.status != "healthy":
                raise Exception(f"Agent {agent_name} failed health check: {health}")
                
            deployed_agents.append(agent_name)
            print(f"✓ {agent_name} deployed successfully")
            
        # Configure agent communication
        await configure_agent_messaging(client, deployed_agents)
        
        # Run system integration tests
        await run_integration_tests(client)
        
        print("🎉 Honeypot system deployed successfully!")
        
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        # Rollback deployed agents
        await rollback_deployment(client, deployed_agents)
        raise

async def configure_agent_messaging(client, agents):
    """Configure message routing between agents"""
    
    message_routes = [
        ("detection-agent", "coordinator-agent", "threat_detected"),
        ("coordinator-agent", "interaction-agent", "engagement_approved"),
        ("interaction-agent", "intelligence-agent", "session_completed"),
        ("intelligence-agent", "coordinator-agent", "intelligence_extracted")
    ]
    
    for source, target, message_type in message_routes:
        await client.configure_message_route(
            source_agent=source,
            target_agent=target,
            message_type=message_type,
            routing_policy="round_robin"
        )

if __name__ == "__main__":
    asyncio.run(deploy_honeypot_system())
```

#### 3. Deployment Verification

```python
# deployment/scripts/verify_deployment.py
import asyncio
from agentcore_runtime import AgentCoreClient

async def verify_deployment():
    client = AgentCoreClient()
    
    # Check all agents are running
    agents = ["detection-agent", "coordinator-agent", "interaction-agent", "intelligence-agent"]
    
    for agent_name in agents:
        # Check agent status
        status = await client.get_agent_status(agent_name)
        assert status.state == "running", f"Agent {agent_name} not running: {status.state}"
        
        # Check agent health
        health = await client.check_agent_health(agent_name)
        assert health.status == "healthy", f"Agent {agent_name} unhealthy: {health}"
        
        # Check agent metrics
        metrics = await client.get_agent_metrics(agent_name)
        assert metrics.error_rate < 0.1, f"High error rate for {agent_name}: {metrics.error_rate}"
        
        print(f"✓ {agent_name} verified successfully")
    
    # Test end-to-end workflow
    await test_threat_detection_workflow(client)
    
    print("🎉 Deployment verification completed successfully!")

async def test_threat_detection_workflow(client):
    """Test complete threat detection to intelligence workflow"""
    
    # Send test threat to detection agent
    test_threat = {
        "source_ip": "192.168.1.100",
        "attack_type": "ssh_brute_force",
        "confidence": 0.89
    }
    
    result = await client.send_message(
        target_agent="detection-agent",
        message_type="test_threat",
        payload=test_threat
    )
    
    # Wait for workflow completion
    await asyncio.sleep(10)
    
    # Verify engagement was created
    coordinator_state = await client.get_agent_state("coordinator-agent")
    assert len(coordinator_state.active_engagements) > 0, "No engagement created"
    
    print("✓ End-to-end workflow test passed")
```

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily Tasks
```bash
#!/bin/bash
# scripts/daily_maintenance.sh

echo "Starting daily maintenance tasks..."

# Check agent health
python scripts/check_agent_health.py

# Rotate logs
python scripts/rotate_logs.py

# Clean up old session data
python scripts/cleanup_old_sessions.py --days 7

# Update threat intelligence feeds
python scripts/update_threat_feeds.py

# Generate daily reports
python scripts/generate_daily_report.py

echo "Daily maintenance completed"
```

#### Weekly Tasks
```bash
#!/bin/bash
# scripts/weekly_maintenance.sh

echo "Starting weekly maintenance tasks..."

# Update AI models
python scripts/update_ai_models.py

# Optimize database
python scripts/optimize_database.py

# Security scan
python scripts/security_scan.py

# Performance analysis
python scripts/performance_analysis.py

# Backup configuration
python scripts/backup_configuration.py

echo "Weekly maintenance completed"
```

### Monitoring and Alerting

#### Health Monitoring
```python
# scripts/health_monitor.py
import asyncio
import json
from datetime import datetime
from agentcore_runtime import AgentCoreClient

class HealthMonitor:
    def __init__(self):
        self.client = AgentCoreClient()
        self.alert_thresholds = {
            "error_rate": 0.1,
            "response_time_p95": 2000,  # ms
            "memory_usage": 0.8,  # 80%
            "cpu_usage": 0.7   # 70%
        }
    
    async def monitor_system_health(self):
        """Continuous health monitoring"""
        
        while True:
            try:
                health_report = await self.generate_health_report()
                
                # Check for alerts
                alerts = self.check_alert_conditions(health_report)
                
                if alerts:
                    await self.send_alerts(alerts)
                
                # Log health status
                self.log_health_status(health_report)
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                print(f"Health monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def generate_health_report(self):
        """Generate comprehensive health report"""
        
        agents = ["detection-agent", "coordinator-agent", "interaction-agent", "intelligence-agent"]
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "agents": {},
            "system": {}
        }
        
        for agent_name in agents:
            try:
                # Get agent health
                health = await self.client.check_agent_health(agent_name)
                
                # Get agent metrics
                metrics = await self.client.get_agent_metrics(agent_name)
                
                report["agents"][agent_name] = {
                    "status": health.status,
                    "error_rate": metrics.error_rate,
                    "response_time_p95": metrics.response_time_p95,
                    "memory_usage": metrics.memory_usage_percent / 100,
                    "cpu_usage": metrics.cpu_usage_percent / 100,
                    "active_sessions": metrics.active_sessions
                }
                
            except Exception as e:
                report["agents"][agent_name] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # Get system-level metrics
        report["system"] = await self.get_system_metrics()
        
        return report
    
    def check_alert_conditions(self, health_report):
        """Check if any metrics exceed alert thresholds"""
        
        alerts = []
        
        for agent_name, agent_data in health_report["agents"].items():
            if agent_data.get("status") != "healthy":
                alerts.append({
                    "severity": "critical",
                    "agent": agent_name,
                    "message": f"Agent {agent_name} is unhealthy: {agent_data.get('status')}"
                })
            
            for metric, threshold in self.alert_thresholds.items():
                if metric in agent_data and agent_data[metric] > threshold:
                    alerts.append({
                        "severity": "warning",
                        "agent": agent_name,
                        "metric": metric,
                        "value": agent_data[metric],
                        "threshold": threshold,
                        "message": f"Agent {agent_name} {metric} ({agent_data[metric]}) exceeds threshold ({threshold})"
                    })
        
        return alerts
```

### Backup and Recovery

#### Configuration Backup
```python
# scripts/backup_configuration.py
import json
import boto3
from datetime import datetime
from agentcore_runtime import AgentCoreClient

async def backup_system_configuration():
    """Backup all system configuration to S3"""
    
    client = AgentCoreClient()
    s3_client = boto3.client('s3')
    
    backup_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "agents": {},
        "workflows": {},
        "configurations": {}
    }
    
    # Backup agent configurations
    agents = ["detection-agent", "coordinator-agent", "interaction-agent", "intelligence-agent"]
    
    for agent_name in agents:
        config = await client.get_agent_configuration(agent_name)
        backup_data["agents"][agent_name] = config
    
    # Backup workflow definitions
    workflows = await client.list_workflows()
    for workflow in workflows:
        workflow_def = await client.get_workflow_definition(workflow.id)
        backup_data["workflows"][workflow.id] = workflow_def
    
    # Backup system configurations
    system_config = await client.get_system_configuration()
    backup_data["configurations"]["system"] = system_config
    
    # Upload to S3
    backup_key = f"backups/configuration/{datetime.utcnow().strftime('%Y/%m/%d')}/config-backup.json"
    
    s3_client.put_object(
        Bucket="honeypot-system-backups",
        Key=backup_key,
        Body=json.dumps(backup_data, indent=2),
        ServerSideEncryption="AES256"
    )
    
    print(f"Configuration backup completed: s3://honeypot-system-backups/{backup_key}")
```

### Troubleshooting Guide

#### Common Issues and Solutions

**Agent Not Starting**
```bash
# Check agent logs
agentcore logs detection-agent --tail 100

# Check agent configuration
agentcore describe agent detection-agent

# Restart agent
agentcore restart agent detection-agent

# Check resource constraints
agentcore get agent detection-agent -o yaml
```

**High Error Rates**
```python
# scripts/diagnose_errors.py
async def diagnose_high_error_rate(agent_name: str):
    client = AgentCoreClient()
    
    # Get recent error logs
    logs = await client.get_agent_logs(
        agent_name, 
        level="ERROR", 
        since="1h"
    )
    
    # Analyze error patterns
    error_patterns = {}
    for log_entry in logs:
        error_type = log_entry.get("error_type", "unknown")
        error_patterns[error_type] = error_patterns.get(error_type, 0) + 1
    
    # Generate recommendations
    recommendations = []
    
    if "timeout" in error_patterns:
        recommendations.append("Consider increasing timeout values")
    
    if "memory" in error_patterns:
        recommendations.append("Increase memory allocation for agent")
    
    if "connection" in error_patterns:
        recommendations.append("Check network connectivity and dependencies")
    
    return {
        "error_patterns": error_patterns,
        "recommendations": recommendations
    }
```

This deployment and maintenance guide provides comprehensive procedures for operating the honeypot system in production environments.