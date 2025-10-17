"""
Enhanced Mock AgentCore Runtime for Local Development
Simulates the AgentCore Runtime environment for testing agents locally
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from message_bus import get_message_bus, MockMessageBus
from state_manager import get_state_manager, MockStateManager, AgentInfo, HoneypotInfo, EngagementSession, AgentStatus, HoneypotStatus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Mock AgentCore Runtime",
    description="Local development simulation of AgentCore Runtime",
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

# Pydantic models for API
class AgentRegistration(BaseModel):
    agent_id: str
    agent_type: str
    endpoint: str
    metadata: Dict[str, Any] = {}

class HoneypotRegistration(BaseModel):
    honeypot_id: str
    honeypot_type: str
    endpoint: str
    metadata: Dict[str, Any] = {}

class MessageRequest(BaseModel):
    exchange: str
    routing_key: str
    message_data: Dict[str, Any]
    message_type: str = "event"

class CommandRequest(BaseModel):
    target_agent: str
    command: str
    parameters: Dict[str, Any] = {}

class SessionRequest(BaseModel):
    session_id: str
    honeypot_id: str
    attacker_ip: str
    metadata: Dict[str, Any] = {}

# Global instances
message_bus: Optional[MockMessageBus] = None
state_manager: Optional[MockStateManager] = None

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global message_bus, state_manager
    
    try:
        # Initialize message bus and state manager
        message_bus = await get_message_bus()
        state_manager = await get_state_manager()
        
        # Start background tasks
        asyncio.create_task(cleanup_task())
        
        logger.info("Mock AgentCore Runtime started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start Mock AgentCore Runtime: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global message_bus, state_manager
    
    if message_bus:
        await message_bus.cleanup()
    
    logger.info("Mock AgentCore Runtime shut down")

async def cleanup_task():
    """Background task for periodic cleanup"""
    while True:
        try:
            await asyncio.sleep(300)  # Run every 5 minutes
            if state_manager:
                await state_manager.cleanup_expired_data()
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Mock AgentCore Runtime",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "features": [
            "Agent Management",
            "Message Bus",
            "State Management",
            "Honeypot Lifecycle",
            "Session Tracking"
        ]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        metrics = await state_manager.get_system_metrics() if state_manager else {}
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": metrics
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

# Agent Management Endpoints
@app.post("/agents/register")
async def register_agent(agent_data: AgentRegistration):
    """Register a new agent"""
    try:
        agent_info = AgentInfo(
            agent_id=agent_data.agent_id,
            agent_type=agent_data.agent_type,
            status=AgentStatus.STARTING,
            endpoint=agent_data.endpoint,
            last_heartbeat=datetime.utcnow(),
            metadata=agent_data.metadata
        )
        
        success = await state_manager.register_agent(agent_info)
        
        if success:
            # Notify other agents about new agent
            await message_bus.broadcast_notification(
                "agent_registered",
                {
                    "agent_id": agent_data.agent_id,
                    "agent_type": agent_data.agent_type,
                    "endpoint": agent_data.endpoint
                }
            )
            
            return {"status": "success", "agent_id": agent_data.agent_id}
        else:
            raise HTTPException(status_code=500, detail="Failed to register agent")
            
    except Exception as e:
        logger.error(f"Failed to register agent {agent_data.agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/agents")
async def list_agents():
    """List all registered agents"""
    try:
        agents = await state_manager.get_all_agents()
        return {
            "agents": [agent.to_dict() for agent in agents],
            "count": len(agents)
        }
    except Exception as e:
        logger.error(f"Failed to list agents: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get specific agent information"""
    try:
        agent_info = await state_manager.get_agent_info(agent_id)
        
        if not agent_info:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return agent_info.to_dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, heartbeat_data: dict):
    """Receive agent heartbeat"""
    try:
        status_str = heartbeat_data.get("status", "running")
        status = AgentStatus(status_str) if status_str in [s.value for s in AgentStatus] else AgentStatus.RUNNING
        
        success = await state_manager.update_agent_status(
            agent_id, 
            status, 
            heartbeat_data.get("metadata", {})
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return {"status": "acknowledged", "timestamp": datetime.utcnow().isoformat()}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process heartbeat for {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/agents/type/{agent_type}")
async def get_agents_by_type(agent_type: str):
    """Get agents by type"""
    try:
        agents = await state_manager.get_agents_by_type(agent_type)
        return {
            "agents": [agent.to_dict() for agent in agents],
            "count": len(agents),
            "agent_type": agent_type
        }
    except Exception as e:
        logger.error(f"Failed to get agents by type {agent_type}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Message Bus Endpoints
@app.post("/messages/publish")
async def publish_message(message_request: MessageRequest):
    """Publish a message to the message bus"""
    try:
        message_id = await message_bus.publish_message(
            message_request.exchange,
            message_request.routing_key,
            message_request.message_data,
            message_request.message_type
        )
        
        return {
            "status": "published",
            "message_id": message_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to publish message: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/messages/command")
async def send_command(command_request: CommandRequest):
    """Send a command to a specific agent"""
    try:
        message_id = await message_bus.send_command(
            command_request.target_agent,
            command_request.command,
            command_request.parameters
        )
        
        return {
            "status": "sent",
            "message_id": message_id,
            "target_agent": command_request.target_agent,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to send command: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/messages/history")
async def get_message_history(limit: int = 100):
    """Get recent message history"""
    try:
        messages = await message_bus.get_message_history(limit)
        return {
            "messages": messages,
            "count": len(messages)
        }
    except Exception as e:
        logger.error(f"Failed to get message history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Honeypot Management Endpoints
@app.post("/honeypots/register")
async def register_honeypot(honeypot_data: HoneypotRegistration):
    """Register a new honeypot"""
    try:
        honeypot_info = HoneypotInfo(
            honeypot_id=honeypot_data.honeypot_id,
            honeypot_type=honeypot_data.honeypot_type,
            status=HoneypotStatus.CREATING,
            endpoint=honeypot_data.endpoint,
            created_at=datetime.utcnow(),
            metadata=honeypot_data.metadata
        )
        
        success = await state_manager.register_honeypot(honeypot_info)
        
        if success:
            # Notify agents about new honeypot
            await message_bus.publish_message(
                "honeypot.lifecycle",
                f"honeypot.created.{honeypot_data.honeypot_type}",
                {
                    "honeypot_id": honeypot_data.honeypot_id,
                    "honeypot_type": honeypot_data.honeypot_type,
                    "endpoint": honeypot_data.endpoint,
                    "status": "creating"
                }
            )
            
            return {"status": "success", "honeypot_id": honeypot_data.honeypot_id}
        else:
            raise HTTPException(status_code=500, detail="Failed to register honeypot")
            
    except Exception as e:
        logger.error(f"Failed to register honeypot {honeypot_data.honeypot_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/honeypots")
async def list_honeypots():
    """List all honeypots"""
    try:
        active_honeypots = await state_manager.get_active_honeypots()
        return {
            "honeypots": [honeypot.to_dict() for honeypot in active_honeypots],
            "count": len(active_honeypots)
        }
    except Exception as e:
        logger.error(f"Failed to list honeypots: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/honeypots/{honeypot_id}")
async def get_honeypot(honeypot_id: str):
    """Get specific honeypot information"""
    try:
        honeypot_info = await state_manager.get_honeypot_info(honeypot_id)
        
        if not honeypot_info:
            raise HTTPException(status_code=404, detail="Honeypot not found")
        
        return honeypot_info.to_dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get honeypot {honeypot_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Session Management Endpoints
@app.post("/sessions/create")
async def create_session(session_request: SessionRequest):
    """Create a new engagement session"""
    try:
        session = EngagementSession(
            session_id=session_request.session_id,
            honeypot_id=session_request.honeypot_id,
            attacker_ip=session_request.attacker_ip,
            start_time=datetime.utcnow(),
            end_time=None,
            status="active",
            metadata=session_request.metadata
        )
        
        success = await state_manager.create_engagement_session(session)
        
        if success:
            # Notify agents about new session
            await message_bus.publish_message(
                "agent.events",
                "session.started",
                {
                    "session_id": session_request.session_id,
                    "honeypot_id": session_request.honeypot_id,
                    "attacker_ip": session_request.attacker_ip
                }
            )
            
            return {"status": "success", "session_id": session_request.session_id}
        else:
            raise HTTPException(status_code=500, detail="Failed to create session")
            
    except Exception as e:
        logger.error(f"Failed to create session {session_request.session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/sessions/{session_id}/end")
async def end_session(session_id: str):
    """End an engagement session"""
    try:
        success = await state_manager.end_engagement_session(session_id)
        
        if success:
            # Notify agents about ended session
            await message_bus.publish_message(
                "agent.events",
                "session.ended",
                {"session_id": session_id}
            )
            
            return {"status": "success", "session_id": session_id}
        else:
            raise HTTPException(status_code=404, detail="Session not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to end session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sessions/active")
async def get_active_sessions():
    """Get all active sessions"""
    try:
        sessions = await state_manager.get_active_sessions()
        return {
            "sessions": [session.to_dict() for session in sessions],
            "count": len(sessions)
        }
    except Exception as e:
        logger.error(f"Failed to get active sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# System Management Endpoints
@app.get("/system/metrics")
async def get_system_metrics():
    """Get system-wide metrics"""
    try:
        metrics = await state_manager.get_system_metrics()
        return metrics
    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/system/config/{config_key}")
async def set_system_config(config_key: str, config_data: dict):
    """Set system configuration"""
    try:
        success = await state_manager.set_system_config(config_key, config_data.get("value"))
        
        if success:
            return {"status": "success", "config_key": config_key}
        else:
            raise HTTPException(status_code=500, detail="Failed to set configuration")
            
    except Exception as e:
        logger.error(f"Failed to set system config {config_key}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/system/config/{config_key}")
async def get_system_config(config_key: str):
    """Get system configuration"""
    try:
        value = await state_manager.get_system_config(config_key)
        
        if value is not None:
            return {"config_key": config_key, "value": value}
        else:
            raise HTTPException(status_code=404, detail="Configuration not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get system config {config_key}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main_enhanced:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        reload=True
    )