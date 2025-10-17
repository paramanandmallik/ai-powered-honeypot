"""
Mock AgentCore Runtime State Manager for Local Development
Simulates AgentCore's state management and coordination
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import redis
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class AgentStatus(Enum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

class HoneypotStatus(Enum):
    CREATING = "creating"
    ACTIVE = "active"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    ERROR = "error"

@dataclass
class AgentInfo:
    agent_id: str
    agent_type: str
    status: AgentStatus
    endpoint: str
    last_heartbeat: datetime
    metadata: Dict[str, Any]
    
    def to_dict(self):
        data = asdict(self)
        data['status'] = self.status.value
        data['last_heartbeat'] = self.last_heartbeat.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        data['status'] = AgentStatus(data['status'])
        data['last_heartbeat'] = datetime.fromisoformat(data['last_heartbeat'])
        return cls(**data)

@dataclass
class HoneypotInfo:
    honeypot_id: str
    honeypot_type: str
    status: HoneypotStatus
    endpoint: str
    created_at: datetime
    metadata: Dict[str, Any]
    
    def to_dict(self):
        data = asdict(self)
        data['status'] = self.status.value
        data['created_at'] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        data['status'] = HoneypotStatus(data['status'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)

@dataclass
class EngagementSession:
    session_id: str
    honeypot_id: str
    attacker_ip: str
    start_time: datetime
    end_time: Optional[datetime]
    status: str
    metadata: Dict[str, Any]
    
    def to_dict(self):
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        data['end_time'] = self.end_time.isoformat() if self.end_time else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        data['start_time'] = datetime.fromisoformat(data['start_time'])
        data['end_time'] = datetime.fromisoformat(data['end_time']) if data['end_time'] else None
        return cls(**data)

class MockStateManager:
    """Mock implementation of AgentCore Runtime state management"""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis_client = None
        
    async def initialize(self):
        """Initialize state manager"""
        try:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            await asyncio.get_event_loop().run_in_executor(None, self.redis_client.ping)
            
            # Initialize system state
            await self._initialize_system_state()
            
            logger.info("Mock AgentCore state manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize state manager: {e}")
            raise
    
    async def _initialize_system_state(self):
        """Initialize system-wide state"""
        system_state = {
            "system_id": "mock-agentcore-dev",
            "started_at": datetime.utcnow().isoformat(),
            "version": "1.0.0-dev",
            "status": "running"
        }
        
        self.redis_client.set("system:state", json.dumps(system_state))
    
    # Agent Management
    async def register_agent(self, agent_info: AgentInfo) -> bool:
        """Register a new agent with the system"""
        try:
            agent_key = f"agent:{agent_info.agent_id}"
            agent_data = agent_info.to_dict()
            
            # Store agent info
            self.redis_client.set(agent_key, json.dumps(agent_data))
            
            # Add to agent list by type
            type_key = f"agents:by_type:{agent_info.agent_type}"
            self.redis_client.sadd(type_key, agent_info.agent_id)
            
            # Add to all agents list
            self.redis_client.sadd("agents:all", agent_info.agent_id)
            
            logger.info(f"Registered agent {agent_info.agent_id} of type {agent_info.agent_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register agent {agent_info.agent_id}: {e}")
            return False
    
    async def update_agent_status(self, agent_id: str, status: AgentStatus, 
                                metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update agent status and metadata"""
        try:
            agent_key = f"agent:{agent_id}"
            agent_data = self.redis_client.get(agent_key)
            
            if not agent_data:
                logger.warning(f"Agent {agent_id} not found for status update")
                return False
            
            agent_info = AgentInfo.from_dict(json.loads(agent_data))
            agent_info.status = status
            agent_info.last_heartbeat = datetime.utcnow()
            
            if metadata:
                agent_info.metadata.update(metadata)
            
            self.redis_client.set(agent_key, json.dumps(agent_info.to_dict()))
            
            logger.debug(f"Updated agent {agent_id} status to {status.value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update agent status for {agent_id}: {e}")
            return False
    
    async def get_agent_info(self, agent_id: str) -> Optional[AgentInfo]:
        """Get information about a specific agent"""
        try:
            agent_key = f"agent:{agent_id}"
            agent_data = self.redis_client.get(agent_key)
            
            if agent_data:
                return AgentInfo.from_dict(json.loads(agent_data))
            return None
            
        except Exception as e:
            logger.error(f"Failed to get agent info for {agent_id}: {e}")
            return None
    
    async def get_agents_by_type(self, agent_type: str) -> List[AgentInfo]:
        """Get all agents of a specific type"""
        try:
            type_key = f"agents:by_type:{agent_type}"
            agent_ids = self.redis_client.smembers(type_key)
            
            agents = []
            for agent_id in agent_ids:
                agent_info = await self.get_agent_info(agent_id)
                if agent_info:
                    agents.append(agent_info)
            
            return agents
            
        except Exception as e:
            logger.error(f"Failed to get agents by type {agent_type}: {e}")
            return []
    
    async def get_all_agents(self) -> List[AgentInfo]:
        """Get all registered agents"""
        try:
            agent_ids = self.redis_client.smembers("agents:all")
            
            agents = []
            for agent_id in agent_ids:
                agent_info = await self.get_agent_info(agent_id)
                if agent_info:
                    agents.append(agent_info)
            
            return agents
            
        except Exception as e:
            logger.error(f"Failed to get all agents: {e}")
            return []
    
    # Honeypot Management
    async def register_honeypot(self, honeypot_info: HoneypotInfo) -> bool:
        """Register a new honeypot"""
        try:
            honeypot_key = f"honeypot:{honeypot_info.honeypot_id}"
            honeypot_data = honeypot_info.to_dict()
            
            # Store honeypot info
            self.redis_client.set(honeypot_key, json.dumps(honeypot_data))
            
            # Add to honeypot list by type
            type_key = f"honeypots:by_type:{honeypot_info.honeypot_type}"
            self.redis_client.sadd(type_key, honeypot_info.honeypot_id)
            
            # Add to all honeypots list
            self.redis_client.sadd("honeypots:all", honeypot_info.honeypot_id)
            
            logger.info(f"Registered honeypot {honeypot_info.honeypot_id} of type {honeypot_info.honeypot_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register honeypot {honeypot_info.honeypot_id}: {e}")
            return False
    
    async def update_honeypot_status(self, honeypot_id: str, status: HoneypotStatus,
                                   metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update honeypot status and metadata"""
        try:
            honeypot_key = f"honeypot:{honeypot_id}"
            honeypot_data = self.redis_client.get(honeypot_key)
            
            if not honeypot_data:
                logger.warning(f"Honeypot {honeypot_id} not found for status update")
                return False
            
            honeypot_info = HoneypotInfo.from_dict(json.loads(honeypot_data))
            honeypot_info.status = status
            
            if metadata:
                honeypot_info.metadata.update(metadata)
            
            self.redis_client.set(honeypot_key, json.dumps(honeypot_info.to_dict()))
            
            logger.debug(f"Updated honeypot {honeypot_id} status to {status.value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update honeypot status for {honeypot_id}: {e}")
            return False
    
    async def get_honeypot_info(self, honeypot_id: str) -> Optional[HoneypotInfo]:
        """Get information about a specific honeypot"""
        try:
            honeypot_key = f"honeypot:{honeypot_id}"
            honeypot_data = self.redis_client.get(honeypot_key)
            
            if honeypot_data:
                return HoneypotInfo.from_dict(json.loads(honeypot_data))
            return None
            
        except Exception as e:
            logger.error(f"Failed to get honeypot info for {honeypot_id}: {e}")
            return None
    
    async def get_active_honeypots(self) -> List[HoneypotInfo]:
        """Get all active honeypots"""
        try:
            honeypot_ids = self.redis_client.smembers("honeypots:all")
            
            active_honeypots = []
            for honeypot_id in honeypot_ids:
                honeypot_info = await self.get_honeypot_info(honeypot_id)
                if honeypot_info and honeypot_info.status == HoneypotStatus.ACTIVE:
                    active_honeypots.append(honeypot_info)
            
            return active_honeypots
            
        except Exception as e:
            logger.error(f"Failed to get active honeypots: {e}")
            return []
    
    # Session Management
    async def create_engagement_session(self, session: EngagementSession) -> bool:
        """Create a new engagement session"""
        try:
            session_key = f"session:{session.session_id}"
            session_data = session.to_dict()
            
            # Store session info
            self.redis_client.set(session_key, json.dumps(session_data))
            
            # Add to active sessions
            self.redis_client.sadd("sessions:active", session.session_id)
            
            # Add to honeypot sessions
            honeypot_sessions_key = f"sessions:honeypot:{session.honeypot_id}"
            self.redis_client.sadd(honeypot_sessions_key, session.session_id)
            
            logger.info(f"Created engagement session {session.session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create engagement session {session.session_id}: {e}")
            return False
    
    async def end_engagement_session(self, session_id: str) -> bool:
        """End an engagement session"""
        try:
            session_key = f"session:{session_id}"
            session_data = self.redis_client.get(session_key)
            
            if not session_data:
                logger.warning(f"Session {session_id} not found")
                return False
            
            session = EngagementSession.from_dict(json.loads(session_data))
            session.end_time = datetime.utcnow()
            session.status = "completed"
            
            # Update session
            self.redis_client.set(session_key, json.dumps(session.to_dict()))
            
            # Remove from active sessions
            self.redis_client.srem("sessions:active", session_id)
            
            # Add to completed sessions
            self.redis_client.sadd("sessions:completed", session_id)
            
            logger.info(f"Ended engagement session {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to end engagement session {session_id}: {e}")
            return False
    
    async def get_active_sessions(self) -> List[EngagementSession]:
        """Get all active engagement sessions"""
        try:
            session_ids = self.redis_client.smembers("sessions:active")
            
            sessions = []
            for session_id in session_ids:
                session_key = f"session:{session_id}"
                session_data = self.redis_client.get(session_key)
                
                if session_data:
                    session = EngagementSession.from_dict(json.loads(session_data))
                    sessions.append(session)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get active sessions: {e}")
            return []
    
    # System State Management
    async def set_system_config(self, config_key: str, config_value: Any) -> bool:
        """Set system configuration value"""
        try:
            config_data = {
                "key": config_key,
                "value": config_value,
                "updated_at": datetime.utcnow().isoformat()
            }
            
            self.redis_client.set(f"config:{config_key}", json.dumps(config_data))
            return True
            
        except Exception as e:
            logger.error(f"Failed to set system config {config_key}: {e}")
            return False
    
    async def get_system_config(self, config_key: str) -> Optional[Any]:
        """Get system configuration value"""
        try:
            config_data = self.redis_client.get(f"config:{config_key}")
            
            if config_data:
                return json.loads(config_data)["value"]
            return None
            
        except Exception as e:
            logger.error(f"Failed to get system config {config_key}: {e}")
            return None
    
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get system-wide metrics"""
        try:
            metrics = {
                "agents": {
                    "total": len(self.redis_client.smembers("agents:all")),
                    "by_type": {}
                },
                "honeypots": {
                    "total": len(self.redis_client.smembers("honeypots:all")),
                    "active": len(await self.get_active_honeypots())
                },
                "sessions": {
                    "active": len(self.redis_client.smembers("sessions:active")),
                    "completed": len(self.redis_client.smembers("sessions:completed"))
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Get agent counts by type
            agent_types = ["detection", "coordinator", "interaction", "intelligence"]
            for agent_type in agent_types:
                type_key = f"agents:by_type:{agent_type}"
                metrics["agents"]["by_type"][agent_type] = len(self.redis_client.smembers(type_key))
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return {}
    
    async def cleanup_expired_data(self):
        """Cleanup expired data and stale entries"""
        try:
            current_time = datetime.utcnow()
            
            # Cleanup stale agents (no heartbeat for 10 minutes)
            agent_ids = self.redis_client.smembers("agents:all")
            for agent_id in agent_ids:
                agent_info = await self.get_agent_info(agent_id)
                if agent_info:
                    time_since_heartbeat = current_time - agent_info.last_heartbeat
                    if time_since_heartbeat > timedelta(minutes=10):
                        await self._remove_agent(agent_id)
                        logger.info(f"Removed stale agent {agent_id}")
            
            # Cleanup old completed sessions (older than 24 hours)
            session_ids = self.redis_client.smembers("sessions:completed")
            for session_id in session_ids:
                session_key = f"session:{session_id}"
                session_data = self.redis_client.get(session_key)
                
                if session_data:
                    session = EngagementSession.from_dict(json.loads(session_data))
                    if session.end_time:
                        time_since_end = current_time - session.end_time
                        if time_since_end > timedelta(hours=24):
                            self.redis_client.delete(session_key)
                            self.redis_client.srem("sessions:completed", session_id)
                            logger.debug(f"Cleaned up old session {session_id}")
            
            logger.debug("Completed cleanup of expired data")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    async def _remove_agent(self, agent_id: str):
        """Remove an agent from all tracking"""
        try:
            # Get agent info first
            agent_info = await self.get_agent_info(agent_id)
            
            if agent_info:
                # Remove from type list
                type_key = f"agents:by_type:{agent_info.agent_type}"
                self.redis_client.srem(type_key, agent_id)
            
            # Remove from all agents list
            self.redis_client.srem("agents:all", agent_id)
            
            # Remove agent data
            agent_key = f"agent:{agent_id}"
            self.redis_client.delete(agent_key)
            
        except Exception as e:
            logger.error(f"Failed to remove agent {agent_id}: {e}")

# Global state manager instance
state_manager = None

async def get_state_manager() -> MockStateManager:
    """Get or create global state manager instance"""
    global state_manager
    
    if state_manager is None:
        import os
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        
        state_manager = MockStateManager(redis_url)
        await state_manager.initialize()
    
    return state_manager