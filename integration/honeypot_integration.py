#!/usr/bin/env python3
"""
Honeypot Integration Module

Provides integration between the Coordinator Agent and all honeypot infrastructure
including Web Admin Portal, SSH, Database, File Share, and Email honeypots.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from honeypots.web_admin.web_admin_honeypot import WebAdminHoneypot
from honeypots.ssh.ssh_honeypot import SSHHoneypot
from honeypots.database.database_honeypot import DatabaseHoneypot
from honeypots.file_share.file_share_honeypot import FileShareHoneypot
from honeypots.email.email_honeypot import EmailHoneypot


class HoneypotType(Enum):
    """Honeypot types"""
    WEB_ADMIN = "web_admin"
    SSH = "ssh"
    DATABASE = "database"
    FILE_SHARE = "file_share"
    EMAIL = "email"


class HoneypotStatus(Enum):
    """Honeypot status levels"""
    CREATING = "creating"
    ACTIVE = "active"
    ENGAGED = "engaged"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    ERROR = "error"


@dataclass
class HoneypotInstance:
    """Honeypot instance tracking"""
    instance_id: str
    honeypot_type: HoneypotType
    status: HoneypotStatus
    creation_time: datetime
    last_activity: Optional[datetime]
    engagement_count: int
    config: Dict[str, Any]
    network_info: Dict[str, Any]
    session_data: List[Dict[str, Any]]
    destruction_time: Optional[datetime]
    error_details: Optional[str]


@dataclass
class EngagementSession:
    """Active engagement session tracking"""
    session_id: str
    honeypot_id: str
    honeypot_type: HoneypotType
    attacker_ip: str
    start_time: datetime
    last_activity: datetime
    interaction_count: int
    session_data: Dict[str, Any]
    is_active: bool


class HoneypotIntegration:
    """
    Manages integration with all honeypot infrastructure
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or self._get_default_config()
        
        # Honeypot instances
        self.honeypot_classes = {
            HoneypotType.WEB_ADMIN: WebAdminHoneypot,
            HoneypotType.SSH: SSHHoneypot,
            HoneypotType.DATABASE: DatabaseHoneypot,
            HoneypotType.FILE_SHARE: FileShareHoneypot,
            HoneypotType.EMAIL: EmailHoneypot
        }
        
        # Active honeypots
        self.active_honeypots: Dict[str, HoneypotInstance] = {}
        
        # Active engagement sessions
        self.active_sessions: Dict[str, EngagementSession] = {}
        
        # Integration metrics
        self.integration_metrics = {
            "total_honeypots_created": 0,
            "total_sessions_handled": 0,
            "active_honeypots": 0,
            "active_sessions": 0,
            "total_interactions": 0,
            "average_session_duration": 0.0,
            "honeypot_success_rate": 0.0,
            "last_cleanup": None
        }
        
        # Resource limits
        self.resource_limits = {
            "max_concurrent_honeypots": self.config.get("max_concurrent_honeypots", 20),
            "max_concurrent_sessions": self.config.get("max_concurrent_sessions", 50),
            "max_session_duration": self.config.get("max_session_duration", 3600),
            "honeypot_timeout": self.config.get("honeypot_timeout", 7200)
        }
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default honeypot integration configuration"""
        return {
            "max_concurrent_honeypots": 20,
            "max_concurrent_sessions": 50,
            "max_session_duration": 3600,
            "honeypot_timeout": 7200,
            "auto_cleanup_interval": 300,
            "network_isolation": True,
            "synthetic_data_only": True,
            "honeypot_configs": {
                "web_admin": {
                    "port_range": "8080-8090",
                    "ssl_enabled": True,
                    "fake_users": 50
                },
                "ssh": {
                    "port_range": "2220-2230",
                    "fake_filesystem": True,
                    "command_simulation": True
                },
                "database": {
                    "port_range": "3306,5432",
                    "fake_schemas": ["customers", "orders", "users"],
                    "fake_records": 1000
                },
                "file_share": {
                    "protocols": ["smb", "ftp"],
                    "fake_documents": 200,
                    "directory_structure": True
                },
                "email": {
                    "protocols": ["smtp", "imap"],
                    "fake_accounts": 30,
                    "fake_emails": 500
                }
            }
        }
    
    async def initialize(self) -> bool:
        """Initialize honeypot integration"""
        try:
            self.logger.info("Initializing honeypot integration...")
            
            # Validate honeypot classes
            await self._validate_honeypot_classes()
            
            # Initialize network isolation
            await self._initialize_network_isolation()
            
            # Start monitoring tasks
            await self._start_monitoring_tasks()
            
            self.logger.info("Honeypot integration initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Honeypot integration initialization failed: {e}")
            return False
    
    async def _validate_honeypot_classes(self):
        """Validate that all honeypot classes are available"""
        for honeypot_type, honeypot_class in self.honeypot_classes.items():
            try:
                # Test instantiation
                test_instance = honeypot_class(config={})
                if not hasattr(test_instance, 'start') or not hasattr(test_instance, 'stop'):
                    raise Exception(f"Honeypot class {honeypot_class} missing required methods")
                
                self.logger.info(f"Validated honeypot class: {honeypot_type.value}")
                
            except Exception as e:
                raise Exception(f"Honeypot class validation failed for {honeypot_type.value}: {e}")
    
    async def _initialize_network_isolation(self):
        """Initialize network isolation for honeypots"""
        if self.config.get("network_isolation", True):
            # This would typically set up network namespaces, VLANs, or containers
            # For now, we'll simulate the setup
            self.logger.info("Network isolation initialized for honeypots")
    
    async def _start_monitoring_tasks(self):
        """Start monitoring and cleanup tasks"""
        # Start honeypot monitoring
        asyncio.create_task(self._honeypot_monitoring_loop())
        
        # Start session monitoring
        asyncio.create_task(self._session_monitoring_loop())
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_loop())
    
    async def create_honeypot(self, honeypot_type: HoneypotType, 
                            engagement_config: Dict[str, Any]) -> Optional[str]:
        """
        Create a new honeypot instance
        
        Args:
            honeypot_type: Type of honeypot to create
            engagement_config: Configuration for the engagement
            
        Returns:
            Honeypot instance ID if successful, None otherwise
        """
        try:
            # Check resource limits
            if len(self.active_honeypots) >= self.resource_limits["max_concurrent_honeypots"]:
                self.logger.warning("Maximum concurrent honeypots reached")
                return None
            
            # Generate instance ID
            instance_id = str(uuid.uuid4())
            
            # Create honeypot configuration
            honeypot_config = self._create_honeypot_config(honeypot_type, engagement_config)
            
            # Create honeypot instance tracking
            honeypot_instance = HoneypotInstance(
                instance_id=instance_id,
                honeypot_type=honeypot_type,
                status=HoneypotStatus.CREATING,
                creation_time=datetime.utcnow(),
                last_activity=None,
                engagement_count=0,
                config=honeypot_config,
                network_info={},
                session_data=[],
                destruction_time=None,
                error_details=None
            )
            
            self.active_honeypots[instance_id] = honeypot_instance
            
            # Create and start honeypot
            honeypot_class = self.honeypot_classes[honeypot_type]
            honeypot = honeypot_class(config=honeypot_config)
            
            # Start honeypot
            network_info = await honeypot.start()
            honeypot_instance.network_info = network_info
            honeypot_instance.status = HoneypotStatus.ACTIVE
            
            # Store honeypot reference
            honeypot_instance.config["_honeypot_instance"] = honeypot
            
            self.integration_metrics["total_honeypots_created"] += 1
            self.integration_metrics["active_honeypots"] = len(self.active_honeypots)
            
            self.logger.info(f"Created {honeypot_type.value} honeypot: {instance_id}")
            return instance_id
            
        except Exception as e:
            self.logger.error(f"Failed to create {honeypot_type.value} honeypot: {e}")
            
            # Update instance status if it was created
            if instance_id in self.active_honeypots:
                self.active_honeypots[instance_id].status = HoneypotStatus.ERROR
                self.active_honeypots[instance_id].error_details = str(e)
            
            return None
    
    def _create_honeypot_config(self, honeypot_type: HoneypotType, 
                              engagement_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create honeypot-specific configuration"""
        base_config = self.config["honeypot_configs"].get(honeypot_type.value, {}).copy()
        
        # Add engagement-specific configuration
        base_config.update({
            "engagement_id": engagement_config.get("engagement_id"),
            "threat_level": engagement_config.get("threat_level", "medium"),
            "attacker_profile": engagement_config.get("attacker_profile", {}),
            "synthetic_data_only": self.config.get("synthetic_data_only", True),
            "network_isolation": self.config.get("network_isolation", True),
            "session_timeout": self.resource_limits["max_session_duration"],
            "logging_enabled": True,
            "real_data_detection": True
        })
        
        return base_config
    
    async def destroy_honeypot(self, instance_id: str, reason: str = "normal") -> bool:
        """
        Destroy a honeypot instance
        
        Args:
            instance_id: ID of honeypot to destroy
            reason: Reason for destruction
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if instance_id not in self.active_honeypots:
                self.logger.warning(f"Honeypot {instance_id} not found")
                return False
            
            honeypot_instance = self.active_honeypots[instance_id]
            honeypot_instance.status = HoneypotStatus.DESTROYING
            
            # Stop honeypot
            honeypot = honeypot_instance.config.get("_honeypot_instance")
            if honeypot:
                await honeypot.stop()
            
            # Archive session data
            await self._archive_honeypot_data(honeypot_instance)
            
            # Remove from active honeypots
            honeypot_instance.destruction_time = datetime.utcnow()
            honeypot_instance.status = HoneypotStatus.DESTROYED
            del self.active_honeypots[instance_id]
            
            self.integration_metrics["active_honeypots"] = len(self.active_honeypots)
            
            self.logger.info(f"Destroyed honeypot {instance_id} (reason: {reason})")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to destroy honeypot {instance_id}: {e}")
            
            # Update status to error
            if instance_id in self.active_honeypots:
                self.active_honeypots[instance_id].status = HoneypotStatus.ERROR
                self.active_honeypots[instance_id].error_details = str(e)
            
            return False
    
    async def start_engagement_session(self, honeypot_id: str, attacker_ip: str, 
                                     session_config: Dict[str, Any]) -> Optional[str]:
        """
        Start a new engagement session
        
        Args:
            honeypot_id: ID of honeypot for the session
            attacker_ip: IP address of attacker
            session_config: Session configuration
            
        Returns:
            Session ID if successful, None otherwise
        """
        try:
            # Check resource limits
            if len(self.active_sessions) >= self.resource_limits["max_concurrent_sessions"]:
                self.logger.warning("Maximum concurrent sessions reached")
                return None
            
            # Validate honeypot exists and is active
            if honeypot_id not in self.active_honeypots:
                self.logger.error(f"Honeypot {honeypot_id} not found")
                return None
            
            honeypot_instance = self.active_honeypots[honeypot_id]
            if honeypot_instance.status != HoneypotStatus.ACTIVE:
                self.logger.error(f"Honeypot {honeypot_id} not active")
                return None
            
            # Generate session ID
            session_id = str(uuid.uuid4())
            
            # Create engagement session
            session = EngagementSession(
                session_id=session_id,
                honeypot_id=honeypot_id,
                honeypot_type=honeypot_instance.honeypot_type,
                attacker_ip=attacker_ip,
                start_time=datetime.utcnow(),
                last_activity=datetime.utcnow(),
                interaction_count=0,
                session_data=session_config,
                is_active=True
            )
            
            self.active_sessions[session_id] = session
            
            # Update honeypot status
            honeypot_instance.status = HoneypotStatus.ENGAGED
            honeypot_instance.engagement_count += 1
            honeypot_instance.last_activity = datetime.utcnow()
            
            self.integration_metrics["total_sessions_handled"] += 1
            self.integration_metrics["active_sessions"] = len(self.active_sessions)
            
            self.logger.info(f"Started engagement session {session_id} on honeypot {honeypot_id}")
            return session_id
            
        except Exception as e:
            self.logger.error(f"Failed to start engagement session: {e}")
            return None
    
    async def end_engagement_session(self, session_id: str, reason: str = "normal") -> bool:
        """
        End an engagement session
        
        Args:
            session_id: ID of session to end
            reason: Reason for ending session
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if session_id not in self.active_sessions:
                self.logger.warning(f"Session {session_id} not found")
                return False
            
            session = self.active_sessions[session_id]
            session.is_active = False
            
            # Calculate session duration
            duration = (datetime.utcnow() - session.start_time).total_seconds()
            
            # Update metrics
            current_avg = self.integration_metrics["average_session_duration"]
            total_sessions = self.integration_metrics["total_sessions_handled"]
            self.integration_metrics["average_session_duration"] = (
                (current_avg * (total_sessions - 1) + duration) / total_sessions
            )
            
            # Archive session data
            await self._archive_session_data(session)
            
            # Update honeypot status
            honeypot_instance = self.active_honeypots.get(session.honeypot_id)
            if honeypot_instance:
                honeypot_instance.session_data.append({
                    "session_id": session_id,
                    "duration": duration,
                    "interaction_count": session.interaction_count,
                    "end_reason": reason
                })
                
                # Check if honeypot should return to active status
                active_sessions_for_honeypot = [
                    s for s in self.active_sessions.values()
                    if s.honeypot_id == session.honeypot_id and s.is_active
                ]
                
                if len(active_sessions_for_honeypot) == 1:  # This session is the last one
                    honeypot_instance.status = HoneypotStatus.ACTIVE
            
            # Remove from active sessions
            del self.active_sessions[session_id]
            self.integration_metrics["active_sessions"] = len(self.active_sessions)
            
            self.logger.info(f"Ended engagement session {session_id} (reason: {reason})")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to end engagement session {session_id}: {e}")
            return False
    
    async def record_interaction(self, session_id: str, interaction_data: Dict[str, Any]) -> bool:
        """
        Record an interaction in an engagement session
        
        Args:
            session_id: ID of session
            interaction_data: Interaction data to record
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if session_id not in self.active_sessions:
                self.logger.warning(f"Session {session_id} not found")
                return False
            
            session = self.active_sessions[session_id]
            
            # Update session activity
            session.last_activity = datetime.utcnow()
            session.interaction_count += 1
            
            # Store interaction data
            if "interactions" not in session.session_data:
                session.session_data["interactions"] = []
            
            interaction_data["timestamp"] = datetime.utcnow().isoformat()
            interaction_data["sequence_number"] = session.interaction_count
            session.session_data["interactions"].append(interaction_data)
            
            self.integration_metrics["total_interactions"] += 1
            
            # Update honeypot last activity
            honeypot_instance = self.active_honeypots.get(session.honeypot_id)
            if honeypot_instance:
                honeypot_instance.last_activity = datetime.utcnow()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to record interaction for session {session_id}: {e}")
            return False
    
    async def get_honeypot_status(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get status of specific honeypot"""
        if instance_id not in self.active_honeypots:
            return None
        
        honeypot_instance = self.active_honeypots[instance_id]
        
        # Get active sessions for this honeypot
        active_sessions = [
            s for s in self.active_sessions.values()
            if s.honeypot_id == instance_id and s.is_active
        ]
        
        return {
            "instance_id": instance_id,
            "type": honeypot_instance.honeypot_type.value,
            "status": honeypot_instance.status.value,
            "creation_time": honeypot_instance.creation_time.isoformat(),
            "last_activity": honeypot_instance.last_activity.isoformat() if honeypot_instance.last_activity else None,
            "engagement_count": honeypot_instance.engagement_count,
            "active_sessions": len(active_sessions),
            "network_info": honeypot_instance.network_info,
            "error_details": honeypot_instance.error_details
        }
    
    async def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get status of specific session"""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        
        return {
            "session_id": session_id,
            "honeypot_id": session.honeypot_id,
            "honeypot_type": session.honeypot_type.value,
            "attacker_ip": session.attacker_ip,
            "start_time": session.start_time.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "interaction_count": session.interaction_count,
            "duration": (datetime.utcnow() - session.start_time).total_seconds(),
            "is_active": session.is_active
        }
    
    async def get_integration_status(self) -> Dict[str, Any]:
        """Get comprehensive integration status"""
        return {
            "active_honeypots": len(self.active_honeypots),
            "active_sessions": len(self.active_sessions),
            "honeypot_types": {
                honeypot_type.value: len([
                    h for h in self.active_honeypots.values()
                    if h.honeypot_type == honeypot_type
                ])
                for honeypot_type in HoneypotType
            },
            "session_types": {
                honeypot_type.value: len([
                    s for s in self.active_sessions.values()
                    if s.honeypot_type == honeypot_type
                ])
                for honeypot_type in HoneypotType
            },
            "integration_metrics": self.integration_metrics.copy(),
            "resource_utilization": {
                "honeypot_capacity": f"{len(self.active_honeypots)}/{self.resource_limits['max_concurrent_honeypots']}",
                "session_capacity": f"{len(self.active_sessions)}/{self.resource_limits['max_concurrent_sessions']}"
            }
        }
    
    async def _archive_honeypot_data(self, honeypot_instance: HoneypotInstance):
        """Archive honeypot data for analysis"""
        try:
            archive_data = {
                "instance_id": honeypot_instance.instance_id,
                "type": honeypot_instance.honeypot_type.value,
                "creation_time": honeypot_instance.creation_time.isoformat(),
                "destruction_time": honeypot_instance.destruction_time.isoformat() if honeypot_instance.destruction_time else None,
                "engagement_count": honeypot_instance.engagement_count,
                "session_data": honeypot_instance.session_data,
                "network_info": honeypot_instance.network_info,
                "config": {k: v for k, v in honeypot_instance.config.items() if k != "_honeypot_instance"}
            }
            
            # This would typically store to S3 or database
            self.logger.info(f"Archived data for honeypot {honeypot_instance.instance_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to archive honeypot data: {e}")
    
    async def _archive_session_data(self, session: EngagementSession):
        """Archive session data for analysis"""
        try:
            archive_data = {
                "session_id": session.session_id,
                "honeypot_id": session.honeypot_id,
                "honeypot_type": session.honeypot_type.value,
                "attacker_ip": session.attacker_ip,
                "start_time": session.start_time.isoformat(),
                "duration": (datetime.utcnow() - session.start_time).total_seconds(),
                "interaction_count": session.interaction_count,
                "session_data": session.session_data
            }
            
            # This would typically store to S3 or database
            self.logger.info(f"Archived data for session {session.session_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to archive session data: {e}")
    
    async def _honeypot_monitoring_loop(self):
        """Monitor honeypot health and lifecycle"""
        while True:
            try:
                current_time = datetime.utcnow()
                timeout_threshold = timedelta(seconds=self.resource_limits["honeypot_timeout"])
                
                # Check for timed out honeypots
                timed_out_honeypots = []
                for instance_id, honeypot in self.active_honeypots.items():
                    if current_time - honeypot.creation_time > timeout_threshold:
                        timed_out_honeypots.append(instance_id)
                
                # Destroy timed out honeypots
                for instance_id in timed_out_honeypots:
                    await self.destroy_honeypot(instance_id, "timeout")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Honeypot monitoring failed: {e}")
                await asyncio.sleep(60)
    
    async def _session_monitoring_loop(self):
        """Monitor session health and lifecycle"""
        while True:
            try:
                current_time = datetime.utcnow()
                timeout_threshold = timedelta(seconds=self.resource_limits["max_session_duration"])
                
                # Check for timed out sessions
                timed_out_sessions = []
                for session_id, session in self.active_sessions.items():
                    if current_time - session.last_activity > timeout_threshold:
                        timed_out_sessions.append(session_id)
                
                # End timed out sessions
                for session_id in timed_out_sessions:
                    await self.end_engagement_session(session_id, "timeout")
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Session monitoring failed: {e}")
                await asyncio.sleep(30)
    
    async def _cleanup_loop(self):
        """Periodic cleanup of resources"""
        while True:
            try:
                cleanup_interval = self.config.get("auto_cleanup_interval", 300)
                
                # Update success rate
                total_honeypots = self.integration_metrics["total_honeypots_created"]
                if total_honeypots > 0:
                    successful_honeypots = total_honeypots - len([
                        h for h in self.active_honeypots.values()
                        if h.status == HoneypotStatus.ERROR
                    ])
                    self.integration_metrics["honeypot_success_rate"] = (
                        successful_honeypots / total_honeypots
                    ) * 100
                
                self.integration_metrics["last_cleanup"] = datetime.utcnow().isoformat()
                
                await asyncio.sleep(cleanup_interval)
                
            except Exception as e:
                self.logger.error(f"Cleanup loop failed: {e}")
                await asyncio.sleep(300)
    
    async def emergency_shutdown_all(self) -> bool:
        """Emergency shutdown of all honeypots and sessions"""
        try:
            self.logger.critical("Emergency shutdown of all honeypots initiated")
            
            # End all active sessions
            for session_id in list(self.active_sessions.keys()):
                await self.end_engagement_session(session_id, "emergency_shutdown")
            
            # Destroy all active honeypots
            for instance_id in list(self.active_honeypots.keys()):
                await self.destroy_honeypot(instance_id, "emergency_shutdown")
            
            self.logger.critical("Emergency shutdown completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Emergency shutdown failed: {e}")
            return False
    
    async def shutdown(self):
        """Graceful shutdown of honeypot integration"""
        self.logger.info("Starting graceful honeypot integration shutdown...")
        
        # End all sessions gracefully
        for session_id in list(self.active_sessions.keys()):
            await self.end_engagement_session(session_id, "system_shutdown")
        
        # Destroy all honeypots gracefully
        for instance_id in list(self.active_honeypots.keys()):
            await self.destroy_honeypot(instance_id, "system_shutdown")
        
        self.logger.info("Honeypot integration shutdown completed")


# Example usage and testing
if __name__ == "__main__":
    async def test_honeypot_integration():
        # Create honeypot integration
        honeypot_integration = HoneypotIntegration()
        
        # Initialize
        success = await honeypot_integration.initialize()
        if not success:
            print("Honeypot integration initialization failed")
            return
        
        # Create honeypots
        engagement_config = {
            "engagement_id": "test-engagement-123",
            "threat_level": "medium",
            "attacker_profile": {"skill_level": "intermediate"}
        }
        
        # Create different types of honeypots
        web_honeypot_id = await honeypot_integration.create_honeypot(
            HoneypotType.WEB_ADMIN, engagement_config
        )
        
        ssh_honeypot_id = await honeypot_integration.create_honeypot(
            HoneypotType.SSH, engagement_config
        )
        
        print(f"Created honeypots: {web_honeypot_id}, {ssh_honeypot_id}")
        
        # Start engagement sessions
        if web_honeypot_id:
            session_id = await honeypot_integration.start_engagement_session(
                web_honeypot_id, "192.168.1.100", {"user_agent": "test"}
            )
            print(f"Started session: {session_id}")
            
            # Record some interactions
            await honeypot_integration.record_interaction(session_id, {
                "type": "login_attempt",
                "username": "admin",
                "success": False
            })
        
        # Get status
        status = await honeypot_integration.get_integration_status()
        print(f"Integration status: {status}")
        
        # Cleanup
        await honeypot_integration.shutdown()
    
    asyncio.run(test_honeypot_integration())