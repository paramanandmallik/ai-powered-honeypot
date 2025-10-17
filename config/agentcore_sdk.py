"""
AgentCore Runtime SDK Mock Implementation
Provides a mock implementation of the AgentCore Runtime SDK for local development.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from uuid import uuid4

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class AgentConfig(BaseModel):
    """Agent configuration"""
    agent_id: str
    agent_name: str
    agent_type: str
    capabilities: List[str]
    runtime_endpoint: str = "http://localhost:8000"

class Message(BaseModel):
    """Message between agents"""
    message_id: Optional[str] = None
    from_agent: str
    to_agent: str
    message_type: str
    payload: Dict[str, Any]
    timestamp: Optional[datetime] = None

class AgentCoreSDK:
    """Mock AgentCore Runtime SDK"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.runtime_endpoint = config.runtime_endpoint
        self.client = httpx.AsyncClient()
        self.message_handlers: Dict[str, Callable] = {}
        self.is_running = False
        self._message_polling_task: Optional[asyncio.Task] = None
        
    async def initialize(self) -> Dict[str, Any]:
        """Initialize the agent with AgentCore Runtime"""
        try:
            response = await self.client.post(
                f"{self.runtime_endpoint}/agents/register",
                json={
                    "agent_id": self.config.agent_id,
                    "agent_name": self.config.agent_name,
                    "agent_type": self.config.agent_type,
                    "capabilities": self.config.capabilities,
                    "endpoints": {
                        "health": f"/agents/{self.config.agent_id}/health",
                        "metrics": f"/agents/{self.config.agent_id}/metrics"
                    }
                }
            )
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Agent {self.config.agent_name} registered with AgentCore Runtime")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to register agent: {e}")
            raise
    
    async def start(self):
        """Start the agent and begin message polling"""
        await self.initialize()
        self.is_running = True
        
        # Start message polling
        self._message_polling_task = asyncio.create_task(self._poll_messages())
        logger.info(f"Agent {self.config.agent_name} started")
    
    async def stop(self):
        """Stop the agent"""
        self.is_running = False
        
        if self._message_polling_task:
            self._message_polling_task.cancel()
            try:
                await self._message_polling_task
            except asyncio.CancelledError:
                pass
        
        # Unregister from runtime
        try:
            await self.client.delete(f"{self.runtime_endpoint}/agents/{self.config.agent_id}")
        except Exception as e:
            logger.warning(f"Failed to unregister agent: {e}")
        
        await self.client.aclose()
        logger.info(f"Agent {self.config.agent_name} stopped")
    
    async def send_message(self, to_agent: str, message_type: str, payload: Dict[str, Any]) -> str:
        """Send a message to another agent"""
        message = Message(
            from_agent=self.config.agent_id,
            to_agent=to_agent,
            message_type=message_type,
            payload=payload
        )
        
        try:
            response = await self.client.post(
                f"{self.runtime_endpoint}/messages/send",
                json=message.model_dump()
            )
            response.raise_for_status()
            
            result = response.json()
            message_id = result.get("message_id")
            
            logger.debug(f"Message sent to {to_agent}: {message_type}")
            return message_id
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            raise
    
    async def broadcast_message(self, message_type: str, payload: Dict[str, Any]) -> List[str]:
        """Broadcast a message to all agents"""
        # Get list of agents
        try:
            response = await self.client.get(f"{self.runtime_endpoint}/agents")
            response.raise_for_status()
            agents = response.json()["agents"]
            
            message_ids = []
            for agent in agents:
                if agent["agent_id"] != self.config.agent_id:  # Don't send to self
                    message_id = await self.send_message(
                        agent["agent_id"], 
                        message_type, 
                        payload
                    )
                    message_ids.append(message_id)
            
            return message_ids
            
        except Exception as e:
            logger.error(f"Failed to broadcast message: {e}")
            raise
    
    def register_message_handler(self, message_type: str, handler: Callable):
        """Register a handler for a specific message type"""
        self.message_handlers[message_type] = handler
        logger.debug(f"Registered handler for message type: {message_type}")
    
    async def update_state(self, state: Dict[str, Any]):
        """Update agent state in the runtime"""
        try:
            response = await self.client.post(
                f"{self.runtime_endpoint}/state/{self.config.agent_id}",
                json=state
            )
            response.raise_for_status()
            
        except Exception as e:
            logger.error(f"Failed to update state: {e}")
            raise
    
    async def get_state(self) -> Optional[Dict[str, Any]]:
        """Get agent state from the runtime"""
        try:
            response = await self.client.get(
                f"{self.runtime_endpoint}/state/{self.config.agent_id}"
            )
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            state_data = response.json()
            return state_data.get("state")
            
        except Exception as e:
            logger.error(f"Failed to get state: {e}")
            return None
    
    async def _poll_messages(self):
        """Poll for messages from the runtime"""
        while self.is_running:
            try:
                response = await self.client.get(
                    f"{self.runtime_endpoint}/messages/{self.config.agent_id}",
                    params={"limit": 10}
                )
                response.raise_for_status()
                
                messages_data = response.json()
                messages = messages_data.get("messages", [])
                
                for message_data in messages:
                    message = Message.model_validate(message_data)
                    await self._handle_message(message)
                    
                    # Acknowledge message
                    await self.client.post(
                        f"{self.runtime_endpoint}/messages/{self.config.agent_id}/ack/{message.message_id}"
                    )
                
                # Wait before polling again
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error polling messages: {e}")
                await asyncio.sleep(5)  # Wait longer on error
    
    async def _handle_message(self, message: Message):
        """Handle an incoming message"""
        handler = self.message_handlers.get(message.message_type)
        
        if handler:
            try:
                await handler(message)
                logger.debug(f"Handled message: {message.message_type} from {message.from_agent}")
            except Exception as e:
                logger.error(f"Error handling message {message.message_type}: {e}")
        else:
            logger.warning(f"No handler for message type: {message.message_type}")

class WorkflowSDK:
    """Mock Workflow SDK for AgentCore Runtime"""
    
    def __init__(self, runtime_endpoint: str = "http://localhost:8000"):
        self.runtime_endpoint = runtime_endpoint
        self.client = httpx.AsyncClient()
    
    async def create_workflow(self, workflow_id: str, name: str, steps: List[Dict[str, Any]], triggers: List[str]) -> Dict[str, Any]:
        """Create a new workflow"""
        workflow_data = {
            "workflow_id": workflow_id,
            "name": name,
            "steps": steps,
            "triggers": triggers
        }
        
        try:
            response = await self.client.post(
                f"{self.runtime_endpoint}/workflows",
                json=workflow_data
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to create workflow: {e}")
            raise
    
    async def trigger_workflow(self, workflow_id: str, trigger_data: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger a workflow execution"""
        try:
            response = await self.client.post(
                f"{self.runtime_endpoint}/workflows/{workflow_id}/trigger",
                json=trigger_data
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to trigger workflow: {e}")
            raise
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

# Utility functions
async def create_agent_sdk(agent_id: str, agent_name: str, agent_type: str, capabilities: List[str]) -> AgentCoreSDK:
    """Create and initialize an AgentCore SDK instance"""
    config = AgentConfig(
        agent_id=agent_id,
        agent_name=agent_name,
        agent_type=agent_type,
        capabilities=capabilities
    )
    
    sdk = AgentCoreSDK(config)
    return sdk

def generate_agent_id(agent_type: str) -> str:
    """Generate a unique agent ID"""
    return f"{agent_type}-{str(uuid4())[:8]}"