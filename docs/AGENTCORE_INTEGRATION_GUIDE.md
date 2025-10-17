# AgentCore Runtime Integration Guide

## Overview

This guide provides detailed information on how the AI-Powered Honeypot System integrates with Amazon AgentCore Runtime, including agent development patterns, deployment procedures, and runtime management.

## AgentCore Runtime Fundamentals

### Agent Architecture

All agents in the honeypot system follow the AgentCore Runtime agent pattern:

```python
from agentcore_runtime import Agent, Message, State

class HoneypotAgent(Agent):
    def __init__(self, agent_id: str, config: dict):
        super().__init__(agent_id, config)
        self.state = State()
        
    async def handle_message(self, message: Message) -> None:
        """Process incoming messages from other agents"""
        pass
        
    async def execute_workflow(self, workflow_id: str, params: dict) -> dict:
        """Execute AgentCore workflows"""
        pass
        
    async def health_check(self) -> dict:
        """AgentCore health monitoring"""
        return {"status": "healthy", "metrics": self.get_metrics()}
```

### Message Bus Integration

#### Message Types and Routing

The system uses AgentCore's native message bus for inter-agent communication:

**Threat Detection Messages**
```python
# Detection Agent → Coordinator Agent
{
    "message_type": "threat_detected",
    "source_agent": "detection-agent-001",
    "target_agent": "coordinator-agent",
    "payload": {
        "threat_id": "uuid",
        "confidence_score": 0.85,
        "threat_type": "ssh_brute_force",
        "indicators": ["192.168.1.100", "admin:password"],
        "engagement_recommendation": True
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "correlation_id": "uuid"
}
```

**Engagement Decision Messages**
```python
# Coordinator Agent → Interaction Agent
{
    "message_type": "engagement_approved",
    "source_agent": "coordinator-agent",
    "target_agent": "interaction-agent-*",
    "payload": {
        "engagement_id": "uuid",
        "honeypot_type": "ssh",
        "target_profile": {
            "ip_address": "192.168.1.100",
            "attack_vector": "ssh_brute_force",
            "persona": "linux_admin"
        },
        "synthetic_data_set": "corporate_linux_server",
        "duration_limit": 3600
    },
    "timestamp": "2024-01-15T10:30:15Z",
    "correlation_id": "uuid"
}
```

**Intelligence Extraction Messages**
```python
# Interaction Agent → Intelligence Agent
{
    "message_type": "session_completed",
    "source_agent": "interaction-agent-003",
    "target_agent": "intelligence-agent-*",
    "payload": {
        "session_id": "uuid",
        "engagement_id": "uuid",
        "duration": 1847,
        "interaction_count": 23,
        "transcript_location": "s3://honeypot-sessions/uuid/transcript.json",
        "synthetic_data_used": ["uuid1", "uuid2", "uuid3"],
        "attacker_profile": {
            "ip_address": "192.168.1.100",
            "user_agent": "ssh_client_2.0",
            "techniques_observed": ["T1110", "T1083", "T1057"]
        }
    },
    "timestamp": "2024-01-15T11:00:47Z",
    "correlation_id": "uuid"
}
```

#### Message Handling Patterns

**Asynchronous Message Processing**
```python
class DetectionAgent(Agent):
    async def handle_message(self, message: Message) -> None:
        if message.type == "threat_feed_update":
            await self.process_threat_feed(message.payload)
        elif message.type == "manual_trigger":
            await self.evaluate_manual_threat(message.payload)
        elif message.type == "health_check":
            await self.respond_health_status(message)
            
    async def process_threat_feed(self, threat_data: dict) -> None:
        # AI-powered threat analysis
        confidence = await self.ai_threat_analyzer.analyze(threat_data)
        
        if confidence > 0.75:
            engagement_message = Message(
                type="threat_detected",
                target="coordinator-agent",
                payload={
                    "confidence_score": confidence,
                    "threat_data": threat_data,
                    "engagement_recommendation": True
                }
            )
            await self.send_message(engagement_message)
```

**Message Correlation and State Management**
```python
class CoordinatorAgent(Agent):
    def __init__(self, agent_id: str, config: dict):
        super().__init__(agent_id, config)
        self.active_engagements = {}
        self.honeypot_inventory = {}
        
    async def handle_message(self, message: Message) -> None:
        correlation_id = message.correlation_id
        
        if message.type == "threat_detected":
            engagement_id = await self.create_engagement(message.payload)
            self.active_engagements[engagement_id] = {
                "correlation_id": correlation_id,
                "status": "approved",
                "created_at": datetime.utcnow()
            }
            
        elif message.type == "session_completed":
            engagement_id = message.payload["engagement_id"]
            await self.cleanup_engagement(engagement_id)
            del self.active_engagements[engagement_id]
```

### Workflow Integration

#### AgentCore Workflow Definitions

**Threat Detection Workflow**
```yaml
# threat-detection-workflow.yaml
name: threat_detection_workflow
version: "1.0"
agents:
  - detection-agent
  - coordinator-agent
  
steps:
  - name: analyze_threat
    agent: detection-agent
    action: analyze_threat_data
    inputs:
      - threat_feed_data
    outputs:
      - confidence_score
      - threat_classification
      
  - name: make_engagement_decision
    agent: detection-agent
    action: evaluate_engagement
    condition: confidence_score > 0.75
    inputs:
      - confidence_score
      - threat_classification
    outputs:
      - engagement_decision
      
  - name: create_honeypot
    agent: coordinator-agent
    action: provision_honeypot
    condition: engagement_decision == true
    inputs:
      - threat_classification
      - engagement_parameters
    outputs:
      - honeypot_id
      - honeypot_endpoint
```

**Engagement Workflow**
```yaml
# engagement-workflow.yaml
name: engagement_workflow
version: "1.0"
agents:
  - coordinator-agent
  - interaction-agent
  - intelligence-agent
  
steps:
  - name: setup_honeypot
    agent: coordinator-agent
    action: create_honeypot_environment
    timeout: 30s
    
  - name: engage_attacker
    agent: interaction-agent
    action: handle_attacker_interaction
    timeout: 3600s
    parallel: true
    
  - name: extract_intelligence
    agent: intelligence-agent
    action: analyze_session_data
    depends_on: engage_attacker
    timeout: 300s
    
  - name: cleanup
    agent: coordinator-agent
    action: destroy_honeypot
    depends_on: extract_intelligence
```

#### Workflow Execution

```python
class CoordinatorAgent(Agent):
    async def execute_workflow(self, workflow_id: str, params: dict) -> dict:
        if workflow_id == "engagement_workflow":
            return await self.execute_engagement_workflow(params)
        elif workflow_id == "cleanup_workflow":
            return await self.execute_cleanup_workflow(params)
            
    async def execute_engagement_workflow(self, params: dict) -> dict:
        try:
            # Step 1: Setup honeypot
            honeypot_id = await self.create_honeypot(params["threat_type"])
            
            # Step 2: Notify interaction agent
            await self.send_workflow_message(
                "interaction-agent",
                "start_engagement",
                {"honeypot_id": honeypot_id, "params": params}
            )
            
            # Step 3: Monitor engagement
            session_data = await self.monitor_engagement(honeypot_id)
            
            # Step 4: Trigger intelligence extraction
            await self.send_workflow_message(
                "intelligence-agent",
                "extract_intelligence",
                {"session_data": session_data}
            )
            
            return {"status": "completed", "honeypot_id": honeypot_id}
            
        except Exception as e:
            await self.handle_workflow_error(workflow_id, e)
            return {"status": "failed", "error": str(e)}
```

### State Management

#### Agent State Synchronization

```python
class AgentState:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.state_data = {}
        self.last_updated = datetime.utcnow()
        
    async def update_state(self, key: str, value: any) -> None:
        self.state_data[key] = value
        self.last_updated = datetime.utcnow()
        
        # Sync with AgentCore state manager
        await self.sync_to_agentcore()
        
    async def sync_to_agentcore(self) -> None:
        state_message = {
            "agent_id": self.agent_id,
            "state_data": self.state_data,
            "timestamp": self.last_updated.isoformat()
        }
        await AgentCoreStateManager.update_agent_state(state_message)
```

#### Distributed State Coordination

```python
class CoordinatorAgent(Agent):
    async def coordinate_agent_states(self) -> None:
        """Ensure all agents have consistent state"""
        
        # Get current state from all agents
        agent_states = await self.get_all_agent_states()
        
        # Detect state inconsistencies
        inconsistencies = self.detect_state_conflicts(agent_states)
        
        if inconsistencies:
            # Resolve conflicts using coordinator as source of truth
            await self.resolve_state_conflicts(inconsistencies)
            
        # Broadcast updated state to all agents
        await self.broadcast_state_update(agent_states)
```

### Auto-Scaling Configuration

#### Scaling Policies

**Detection Agent Scaling**
```yaml
# detection-agent-scaling.yaml
agent: detection-agent
scaling_policy:
  min_instances: 2
  max_instances: 10
  target_metrics:
    - metric: message_queue_depth
      threshold: 100
      scale_up_cooldown: 300s
      scale_down_cooldown: 600s
    - metric: cpu_utilization
      threshold: 70
      scale_up_cooldown: 180s
```

**Interaction Agent Scaling**
```yaml
# interaction-agent-scaling.yaml
agent: interaction-agent
scaling_policy:
  min_instances: 3
  max_instances: 20
  target_metrics:
    - metric: concurrent_sessions
      threshold: 5
      scale_up_cooldown: 60s
      scale_down_cooldown: 300s
    - metric: response_time_p95
      threshold: 2000ms
      scale_up_cooldown: 120s
```

#### Scaling Implementation

```python
class AgentScalingManager:
    def __init__(self, agentcore_client):
        self.agentcore = agentcore_client
        
    async def handle_scaling_event(self, agent_type: str, action: str) -> None:
        if action == "scale_up":
            await self.scale_up_agent(agent_type)
        elif action == "scale_down":
            await self.scale_down_agent(agent_type)
            
    async def scale_up_agent(self, agent_type: str) -> None:
        current_instances = await self.agentcore.get_agent_instances(agent_type)
        max_instances = self.get_max_instances(agent_type)
        
        if len(current_instances) < max_instances:
            new_instance = await self.agentcore.create_agent_instance(
                agent_type=agent_type,
                config=self.get_agent_config(agent_type)
            )
            
            # Wait for instance to be ready
            await self.wait_for_agent_ready(new_instance.id)
            
            # Update load balancer
            await self.update_load_balancer(agent_type, new_instance)
```

### Health Monitoring and Metrics

#### Agent Health Checks

```python
class HoneypotAgent(Agent):
    async def health_check(self) -> dict:
        """AgentCore health monitoring implementation"""
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                "memory_usage": self.get_memory_usage(),
                "cpu_usage": self.get_cpu_usage(),
                "message_queue_size": self.get_queue_size(),
                "active_sessions": self.get_active_sessions(),
                "error_rate": self.get_error_rate()
            },
            "dependencies": {
                "database": await self.check_database_connection(),
                "message_bus": await self.check_message_bus(),
                "external_apis": await self.check_external_apis()
            }
        }
        
        # Determine overall health status
        if any(dep["status"] == "unhealthy" for dep in health_status["dependencies"].values()):
            health_status["status"] = "degraded"
            
        if health_status["metrics"]["error_rate"] > 0.1:
            health_status["status"] = "unhealthy"
            
        return health_status
```

#### Custom Metrics Collection

```python
class AgentMetricsCollector:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.metrics = {}
        
    async def collect_metrics(self) -> dict:
        """Collect agent-specific metrics for AgentCore"""
        
        return {
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                # Performance metrics
                "requests_per_second": self.calculate_rps(),
                "average_response_time": self.calculate_avg_response_time(),
                "error_rate": self.calculate_error_rate(),
                
                # Business metrics
                "threats_detected": self.get_threats_detected(),
                "engagements_active": self.get_active_engagements(),
                "intelligence_reports_generated": self.get_reports_generated(),
                
                # Resource metrics
                "memory_usage_mb": self.get_memory_usage(),
                "cpu_usage_percent": self.get_cpu_usage(),
                "disk_usage_mb": self.get_disk_usage()
            }
        }
```

### Deployment and Configuration

#### Agent Configuration

```yaml
# detection-agent.yaml
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
    - name: AI_MODEL_ENDPOINT
      valueFrom:
        secretKeyRef:
          name: ai-model-config
          key: endpoint
  healthCheck:
    path: "/health"
    port: 8080
    initialDelaySeconds: 30
    periodSeconds: 10
  scaling:
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
```

#### Deployment Scripts

```python
# deploy_agents.py
import asyncio
from agentcore_runtime import AgentCoreClient

async def deploy_honeypot_agents():
    client = AgentCoreClient()
    
    # Deploy agents in dependency order
    agents = [
        ("coordinator-agent", "coordinator-agent.yaml"),
        ("detection-agent", "detection-agent.yaml"),
        ("interaction-agent", "interaction-agent.yaml"),
        ("intelligence-agent", "intelligence-agent.yaml")
    ]
    
    for agent_name, config_file in agents:
        print(f"Deploying {agent_name}...")
        
        # Deploy agent
        deployment = await client.deploy_agent(config_file)
        
        # Wait for deployment to be ready
        await client.wait_for_deployment(deployment.id, timeout=300)
        
        # Verify agent health
        health = await client.check_agent_health(agent_name)
        if health["status"] != "healthy":
            raise Exception(f"Agent {agent_name} failed health check")
            
        print(f"✓ {agent_name} deployed successfully")
    
    print("All agents deployed successfully!")

if __name__ == "__main__":
    asyncio.run(deploy_honeypot_agents())
```

This integration guide provides the foundation for developing, deploying, and managing AI agents on AgentCore Runtime within the honeypot system architecture.