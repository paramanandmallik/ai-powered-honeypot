"""
Mock AgentCore Runtime for Local Development
Simulates the AgentCore Runtime platform for testing AI agents locally.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from uuid import uuid4

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Pydantic models for API
class AgentRegistration(BaseModel):
    agent_id: str
    agent_name: str
    agent_type: str
    capabilities: List[str]
    endpoints: Dict[str, str]

class Message(BaseModel):
    message_id: str = None
    from_agent: str
    to_agent: str
    message_type: str
    payload: Dict[str, Any]
    timestamp: datetime = None

class WorkflowDefinition(BaseModel):
    workflow_id: str
    name: str
    steps: List[Dict[str, Any]]
    triggers: List[str]

class AgentState(BaseModel):
    agent_id: str
    state: Dict[str, Any]
    last_updated: datetime = None

# Mock AgentCore Runtime
class MockAgentCoreRuntime:
    def __init__(self):
        self.agents: Dict[str, AgentRegistration] = {}
        self.messages: List[Message] = []
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self.agent_states: Dict[str, AgentState] = {}
        self.redis_client: Optional[redis.Redis] = None
        
    async def initialize(self):
        """Initialize the mock runtime"""
        try:
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            self.redis_client = redis.from_url(redis_url)
            await self.redis_client.ping()
            logger.info("Connected to Redis for message queuing")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Using in-memory storage.")
            self.redis_client = None
    
    async def register_agent(self, registration: AgentRegistration) -> Dict[str, Any]:
        """Register a new agent with the runtime"""
        self.agents[registration.agent_id] = registration
        
        # Store in Redis if available
        if self.redis_client:
            await self.redis_client.hset(
                "agents", 
                registration.agent_id, 
                registration.model_dump_json()
            )
        
        logger.info(f"Agent registered: {registration.agent_name} ({registration.agent_id})")
        
        return {
            "status": "registered",
            "agent_id": registration.agent_id,
            "runtime_endpoint": "http://localhost:8000",
            "message_queue": f"agent.{registration.agent_id}.messages"
        }
    
    async def send_message(self, message: Message) -> Dict[str, Any]:
        """Send a message between agents"""
        if not message.message_id:
            message.message_id = str(uuid4())
        if not message.timestamp:
            message.timestamp = datetime.utcnow()
        
        # Validate agents exist
        if message.from_agent not in self.agents:
            raise HTTPException(status_code=404, detail=f"Source agent {message.from_agent} not found")
        if message.to_agent not in self.agents:
            raise HTTPException(status_code=404, detail=f"Target agent {message.to_agent} not found")
        
        # Store message
        self.messages.append(message)
        
        # Queue message in Redis if available
        if self.redis_client:
            queue_name = f"agent.{message.to_agent}.messages"
            await self.redis_client.lpush(queue_name, message.model_dump_json())
        
        logger.info(f"Message sent: {message.from_agent} -> {message.to_agent} ({message.message_type})")
        
        return {
            "status": "sent",
            "message_id": message.message_id,
            "queued_at": message.timestamp
        }
    
    async def get_messages(self, agent_id: str, limit: int = 10) -> List[Message]:
        """Get messages for an agent"""
        if self.redis_client:
            # Get from Redis queue
            queue_name = f"agent.{agent_id}.messages"
            messages = await self.redis_client.lrange(queue_name, 0, limit - 1)
            return [Message.model_validate_json(msg) for msg in messages]
        else:
            # Get from in-memory storage
            return [msg for msg in self.messages if msg.to_agent == agent_id][-limit:]
    
    async def update_agent_state(self, agent_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """Update agent state"""
        agent_state = AgentState(
            agent_id=agent_id,
            state=state,
            last_updated=datetime.utcnow()
        )
        
        self.agent_states[agent_id] = agent_state
        
        # Store in Redis if available
        if self.redis_client:
            await self.redis_client.hset(
                "agent_states",
                agent_id,
                agent_state.model_dump_json()
            )
        
        return {"status": "updated", "agent_id": agent_id}
    
    async def get_agent_state(self, agent_id: str) -> Optional[AgentState]:
        """Get agent state"""
        if self.redis_client:
            state_data = await self.redis_client.hget("agent_states", agent_id)
            if state_data:
                return AgentState.model_validate_json(state_data)
        
        return self.agent_states.get(agent_id)
    
    async def create_workflow(self, workflow: WorkflowDefinition) -> Dict[str, Any]:
        """Create a new workflow"""
        self.workflows[workflow.workflow_id] = workflow
        
        if self.redis_client:
            await self.redis_client.hset(
                "workflows",
                workflow.workflow_id,
                workflow.model_dump_json()
            )
        
        logger.info(f"Workflow created: {workflow.name} ({workflow.workflow_id})")
        
        return {
            "status": "created",
            "workflow_id": workflow.workflow_id
        }
    
    async def trigger_workflow(self, workflow_id: str, trigger_data: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger a workflow execution"""
        if workflow_id not in self.workflows:
            raise HTTPException(status_code=404, detail=f"Workflow {workflow_id} not found")
        
        workflow = self.workflows[workflow_id]
        execution_id = str(uuid4())
        
        # Simulate workflow execution
        logger.info(f"Workflow triggered: {workflow.name} (execution: {execution_id})")
        
        # In a real implementation, this would execute the workflow steps
        # For now, we'll just return success
        
        return {
            "status": "triggered",
            "workflow_id": workflow_id,
            "execution_id": execution_id,
            "trigger_data": trigger_data
        }

# Initialize the mock runtime
runtime = MockAgentCoreRuntime()

# FastAPI app
app = FastAPI(
    title="Mock AgentCore Runtime",
    description="Mock AgentCore Runtime for local development",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize the runtime on startup"""
    await runtime.initialize()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "agents_registered": len(runtime.agents),
        "messages_processed": len(runtime.messages),
        "workflows_defined": len(runtime.workflows)
    }

@app.get("/")
async def root():
    """Root endpoint with runtime information"""
    return {
        "name": "Mock AgentCore Runtime",
        "version": "1.0.0",
        "status": "running",
        "agents": len(runtime.agents),
        "endpoints": {
            "health": "/health",
            "agents": "/agents",
            "messages": "/messages",
            "workflows": "/workflows",
            "metrics": "/metrics"
        }
    }

# Agent management endpoints
@app.post("/agents/register")
async def register_agent(registration: AgentRegistration):
    """Register a new agent"""
    return await runtime.register_agent(registration)

@app.get("/agents")
async def list_agents():
    """List all registered agents"""
    return {"agents": list(runtime.agents.values())}

@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get agent details"""
    if agent_id not in runtime.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    return runtime.agents[agent_id]

@app.delete("/agents/{agent_id}")
async def unregister_agent(agent_id: str):
    """Unregister an agent"""
    if agent_id not in runtime.agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    del runtime.agents[agent_id]
    if runtime.redis_client:
        await runtime.redis_client.hdel("agents", agent_id)
    
    return {"status": "unregistered", "agent_id": agent_id}

# Message handling endpoints
@app.post("/messages/send")
async def send_message(message: Message):
    """Send a message between agents"""
    return await runtime.send_message(message)

@app.get("/messages/{agent_id}")
async def get_messages(agent_id: str, limit: int = 10):
    """Get messages for an agent"""
    messages = await runtime.get_messages(agent_id, limit)
    return {"messages": messages}

@app.post("/messages/{agent_id}/ack/{message_id}")
async def acknowledge_message(agent_id: str, message_id: str):
    """Acknowledge a message (remove from queue)"""
    if runtime.redis_client:
        queue_name = f"agent.{agent_id}.messages"
        # In a real implementation, we'd remove the specific message
        # For now, just pop one message
        await runtime.redis_client.rpop(queue_name)
    
    return {"status": "acknowledged", "message_id": message_id}

# State management endpoints
@app.post("/state/{agent_id}")
async def update_state(agent_id: str, state: Dict[str, Any]):
    """Update agent state"""
    return await runtime.update_agent_state(agent_id, state)

@app.get("/state/{agent_id}")
async def get_state(agent_id: str):
    """Get agent state"""
    state = await runtime.get_agent_state(agent_id)
    if not state:
        raise HTTPException(status_code=404, detail="Agent state not found")
    return state

# Workflow management endpoints
@app.post("/workflows")
async def create_workflow(workflow: WorkflowDefinition):
    """Create a new workflow"""
    return await runtime.create_workflow(workflow)

@app.get("/workflows")
async def list_workflows():
    """List all workflows"""
    return {"workflows": list(runtime.workflows.values())}

@app.post("/workflows/{workflow_id}/trigger")
async def trigger_workflow(workflow_id: str, trigger_data: Dict[str, Any]):
    """Trigger a workflow"""
    return await runtime.trigger_workflow(workflow_id, trigger_data)

# Metrics endpoint
@app.get("/metrics")
async def get_metrics():
    """Get runtime metrics"""
    return {
        "agents_registered": len(runtime.agents),
        "messages_total": len(runtime.messages),
        "workflows_defined": len(runtime.workflows),
        "agent_states": len(runtime.agent_states),
        "uptime": "mock_uptime",
        "memory_usage": "mock_memory",
        "cpu_usage": "mock_cpu"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )