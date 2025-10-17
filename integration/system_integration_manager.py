#!/usr/bin/env python3
"""
System Integration Manager for AI Honeypot AgentCore System

This module provides comprehensive integration between AgentCore Runtime agents,
AWS supporting services, honeypot infrastructure, and the management dashboard.
It implements the complete end-to-end data flow from detection to intelligence reporting.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from config.agentcore_sdk import AgentCoreSDK
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.detection.detection_agent import DetectionAgent
from agents.interaction.interaction_agent import InteractionAgent
from agents.intelligence.intelligence_agent import IntelligenceAgent
from management.dashboard import DashboardManager
from infrastructure.deploy_complete import AWSInfrastructureManager


class IntegrationStatus(Enum):
    """System integration status levels"""
    INITIALIZING = "initializing"
    CONNECTED = "connected"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass
class SystemHealth:
    """System health status tracking"""
    timestamp: datetime
    agentcore_status: str
    aws_services_status: str
    honeypot_status: str
    dashboard_status: str
    overall_status: IntegrationStatus
    active_sessions: int
    error_count: int
    performance_metrics: Dict[str, float]


@dataclass
class EndToEndFlow:
    """Complete end-to-end data flow tracking"""
    flow_id: str
    start_time: datetime
    threat_event: Dict[str, Any]
    engagement_decision: Optional[Dict[str, Any]]
    honeypot_session: Optional[Dict[str, Any]]
    intelligence_report: Optional[Dict[str, Any]]
    current_stage: str
    completion_time: Optional[datetime]
    success: bool
    error_details: Optional[str]


class SystemIntegrationManager:
    """
    Manages integration between all system components:
    - AgentCore Runtime agents
    - AWS supporting services
    - Honeypot infrastructure
    - Management dashboard
    """
    
    def __init__(self, config_path: str = "config/integration_config.json"):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        
        # Core components
        self.agentcore_sdk = None
        self.coordinator_agent = None
        self.detection_agent = None
        self.interaction_agent = None
        self.intelligence_agent = None
        self.dashboard_manager = None
        self.aws_infrastructure = None
        
        # Integration state
        self.system_health = SystemHealth(
            timestamp=datetime.utcnow(),
            agentcore_status="disconnected",
            aws_services_status="disconnected",
            honeypot_status="disconnected",
            dashboard_status="disconnected",
            overall_status=IntegrationStatus.INITIALIZING,
            active_sessions=0,
            error_count=0,
            performance_metrics={}
        )
        
        # Active flows tracking
        self.active_flows: Dict[str, EndToEndFlow] = {}
        self.completed_flows: List[EndToEndFlow] = []
        
        # Integration metrics
        self.integration_metrics = {
            "total_flows_processed": 0,
            "successful_flows": 0,
            "failed_flows": 0,
            "average_flow_duration": 0.0,
            "agent_response_times": {},
            "system_uptime": datetime.utcnow()
        }
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load integration configuration"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"Config file {config_path} not found, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default integration configuration"""
        return {
            "agentcore": {
                "endpoint": "https://agentcore.us-east-1.amazonaws.com",
                "region": "us-east-1",
                "timeout": 30,
                "retry_attempts": 3
            },
            "aws_services": {
                "region": "us-east-1",
                "s3_bucket": "ai-honeypot-data",
                "rds_endpoint": "ai-honeypot-db.cluster-xyz.us-east-1.rds.amazonaws.com",
                "sns_topic": "ai-honeypot-alerts"
            },
            "honeypots": {
                "max_concurrent_sessions": 10,
                "session_timeout": 3600,
                "auto_destroy_timeout": 3600
            },
            "dashboard": {
                "port": 8080,
                "host": "0.0.0.0",
                "auth_required": True
            },
            "integration": {
                "health_check_interval": 30,
                "flow_timeout": 1800,
                "max_active_flows": 50
            }
        }
    
    async def initialize_system(self) -> bool:
        """Initialize all system components and establish connections"""
        try:
            self.logger.info("Starting system integration initialization...")
            
            # Initialize AgentCore SDK
            await self._initialize_agentcore()
            
            # Initialize AWS infrastructure
            await self._initialize_aws_services()
            
            # Initialize agents
            await self._initialize_agents()
            
            # Initialize honeypot infrastructure
            await self._initialize_honeypots()
            
            # Initialize management dashboard
            await self._initialize_dashboard()
            
            # Establish inter-component connections
            await self._establish_connections()
            
            # Start monitoring and health checks
            await self._start_monitoring()
            
            self.system_health.overall_status = IntegrationStatus.CONNECTED
            self.logger.info("System integration initialization completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"System integration initialization failed: {e}")
            self.system_health.overall_status = IntegrationStatus.FAILED
            return False
    
    async def _initialize_agentcore(self):
        """Initialize AgentCore Runtime SDK and connection"""
        self.logger.info("Initializing AgentCore Runtime connection...")
        
        self.agentcore_sdk = AgentCoreSDK(
            endpoint=self.config["agentcore"]["endpoint"],
            region=self.config["agentcore"]["region"],
            timeout=self.config["agentcore"]["timeout"]
        )
        
        # Test connection
        health_status = await self.agentcore_sdk.check_health()
        if health_status["status"] == "healthy":
            self.system_health.agentcore_status = "connected"
            self.logger.info("AgentCore Runtime connection established")
        else:
            raise Exception(f"AgentCore health check failed: {health_status}")
    
    async def _initialize_aws_services(self):
        """Initialize AWS supporting services"""
        self.logger.info("Initializing AWS supporting services...")
        
        self.aws_infrastructure = AWSInfrastructureManager(
            region=self.config["aws_services"]["region"]
        )
        
        # Verify AWS services connectivity
        services_status = await self.aws_infrastructure.check_services_health()
        if all(status == "healthy" for status in services_status.values()):
            self.system_health.aws_services_status = "connected"
            self.logger.info("AWS services connection established")
        else:
            raise Exception(f"AWS services health check failed: {services_status}")
    
    async def _initialize_agents(self):
        """Initialize all AI agents"""
        self.logger.info("Initializing AI agents...")
        
        # Initialize Coordinator Agent (singleton)
        self.coordinator_agent = CoordinatorAgent(
            agentcore_sdk=self.agentcore_sdk,
            config=self.config
        )
        await self.coordinator_agent.initialize()
        
        # Initialize Detection Agent
        self.detection_agent = DetectionAgent(
            agentcore_sdk=self.agentcore_sdk,
            config=self.config
        )
        await self.detection_agent.initialize()
        
        # Initialize Interaction Agent
        self.interaction_agent = InteractionAgent(
            agentcore_sdk=self.agentcore_sdk,
            config=self.config
        )
        await self.interaction_agent.initialize()
        
        # Initialize Intelligence Agent
        self.intelligence_agent = IntelligenceAgent(
            agentcore_sdk=self.agentcore_sdk,
            config=self.config
        )
        await self.intelligence_agent.initialize()
        
        self.logger.info("All AI agents initialized successfully")
    
    async def _initialize_honeypots(self):
        """Initialize honeypot infrastructure"""
        self.logger.info("Initializing honeypot infrastructure...")
        
        # Honeypots are managed by the Coordinator Agent
        honeypot_status = await self.coordinator_agent.check_honeypot_infrastructure()
        if honeypot_status["status"] == "ready":
            self.system_health.honeypot_status = "connected"
            self.logger.info("Honeypot infrastructure ready")
        else:
            raise Exception(f"Honeypot infrastructure not ready: {honeypot_status}")
    
    async def _initialize_dashboard(self):
        """Initialize management dashboard"""
        self.logger.info("Initializing management dashboard...")
        
        self.dashboard_manager = DashboardManager(
            host=self.config["dashboard"]["host"],
            port=self.config["dashboard"]["port"],
            auth_required=self.config["dashboard"]["auth_required"]
        )
        
        await self.dashboard_manager.initialize()
        self.system_health.dashboard_status = "connected"
        self.logger.info("Management dashboard initialized")
    
    async def _establish_connections(self):
        """Establish connections between all components"""
        self.logger.info("Establishing inter-component connections...")
        
        # Connect agents to dashboard for monitoring
        await self.dashboard_manager.connect_agents({
            "coordinator": self.coordinator_agent,
            "detection": self.detection_agent,
            "interaction": self.interaction_agent,
            "intelligence": self.intelligence_agent
        })
        
        # Connect agents to AWS services
        await self._connect_agents_to_aws()
        
        # Set up message routing between agents
        await self._setup_agent_messaging()
        
        self.logger.info("Inter-component connections established")
    
    async def _connect_agents_to_aws(self):
        """Connect agents to AWS supporting services"""
        # Connect Intelligence Agent to RDS for report storage
        await self.intelligence_agent.connect_to_database(
            self.config["aws_services"]["rds_endpoint"]
        )
        
        # Connect all agents to S3 for data archiving
        for agent in [self.coordinator_agent, self.detection_agent, 
                     self.interaction_agent, self.intelligence_agent]:
            await agent.connect_to_s3(
                self.config["aws_services"]["s3_bucket"]
            )
        
        # Connect Coordinator Agent to SNS for alerting
        await self.coordinator_agent.connect_to_sns(
            self.config["aws_services"]["sns_topic"]
        )
    
    async def _setup_agent_messaging(self):
        """Set up message routing between agents"""
        # Detection Agent -> Coordinator Agent (engagement decisions)
        await self.agentcore_sdk.setup_message_route(
            source="detection-agent",
            destination="coordinator-agent",
            message_type="engagement_decision"
        )
        
        # Coordinator Agent -> Interaction Agent (session management)
        await self.agentcore_sdk.setup_message_route(
            source="coordinator-agent",
            destination="interaction-agent",
            message_type="session_control"
        )
        
        # Interaction Agent -> Intelligence Agent (session data)
        await self.agentcore_sdk.setup_message_route(
            source="interaction-agent",
            destination="intelligence-agent",
            message_type="session_data"
        )
        
        # Intelligence Agent -> Coordinator Agent (intelligence reports)
        await self.agentcore_sdk.setup_message_route(
            source="intelligence-agent",
            destination="coordinator-agent",
            message_type="intelligence_report"
        )
    
    async def _start_monitoring(self):
        """Start system monitoring and health checks"""
        # Start health check task
        asyncio.create_task(self._health_check_loop())
        
        # Start flow monitoring task
        asyncio.create_task(self._flow_monitoring_loop())
        
        # Start performance monitoring task
        asyncio.create_task(self._performance_monitoring_loop())
    
    async def process_end_to_end_flow(self, threat_event: Dict[str, Any]) -> str:
        """
        Process complete end-to-end flow from threat detection to intelligence reporting
        
        Args:
            threat_event: Initial threat event data
            
        Returns:
            Flow ID for tracking
        """
        flow_id = str(uuid.uuid4())
        
        # Create flow tracking object
        flow = EndToEndFlow(
            flow_id=flow_id,
            start_time=datetime.utcnow(),
            threat_event=threat_event,
            engagement_decision=None,
            honeypot_session=None,
            intelligence_report=None,
            current_stage="threat_detection",
            completion_time=None,
            success=False,
            error_details=None
        )
        
        self.active_flows[flow_id] = flow
        self.integration_metrics["total_flows_processed"] += 1
        
        try:
            # Stage 1: Threat Detection and Engagement Decision
            flow.current_stage = "threat_detection"
            engagement_decision = await self.detection_agent.process_threat_event(threat_event)
            flow.engagement_decision = engagement_decision
            
            if not engagement_decision.get("engage", False):
                flow.current_stage = "completed_no_engagement"
                flow.completion_time = datetime.utcnow()
                flow.success = True
                self._complete_flow(flow)
                return flow_id
            
            # Stage 2: Honeypot Creation and Session Management
            flow.current_stage = "honeypot_creation"
            honeypot_config = await self.coordinator_agent.create_honeypot_for_engagement(
                engagement_decision
            )
            
            # Stage 3: Attacker Interaction
            flow.current_stage = "attacker_interaction"
            session_data = await self.interaction_agent.handle_engagement_session(
                honeypot_config, engagement_decision
            )
            flow.honeypot_session = session_data
            
            # Stage 4: Intelligence Extraction and Analysis
            flow.current_stage = "intelligence_analysis"
            intelligence_report = await self.intelligence_agent.analyze_session(
                session_data
            )
            flow.intelligence_report = intelligence_report
            
            # Stage 5: Cleanup and Reporting
            flow.current_stage = "cleanup"
            await self.coordinator_agent.cleanup_honeypot_session(
                honeypot_config["session_id"]
            )
            
            # Complete flow
            flow.current_stage = "completed"
            flow.completion_time = datetime.utcnow()
            flow.success = True
            self.integration_metrics["successful_flows"] += 1
            
        except Exception as e:
            self.logger.error(f"End-to-end flow {flow_id} failed at stage {flow.current_stage}: {e}")
            flow.error_details = str(e)
            flow.completion_time = datetime.utcnow()
            flow.success = False
            self.integration_metrics["failed_flows"] += 1
        
        finally:
            self._complete_flow(flow)
        
        return flow_id
    
    def _complete_flow(self, flow: EndToEndFlow):
        """Complete and archive a flow"""
        # Move from active to completed
        if flow.flow_id in self.active_flows:
            del self.active_flows[flow.flow_id]
        
        self.completed_flows.append(flow)
        
        # Update metrics
        if flow.completion_time:
            duration = (flow.completion_time - flow.start_time).total_seconds()
            current_avg = self.integration_metrics["average_flow_duration"]
            total_flows = len(self.completed_flows)
            self.integration_metrics["average_flow_duration"] = (
                (current_avg * (total_flows - 1) + duration) / total_flows
            )
        
        # Cleanup old completed flows (keep last 100)
        if len(self.completed_flows) > 100:
            self.completed_flows = self.completed_flows[-100:]
    
    async def _health_check_loop(self):
        """Continuous health monitoring loop"""
        while True:
            try:
                await self._perform_health_check()
                await asyncio.sleep(self.config["integration"]["health_check_interval"])
            except Exception as e:
                self.logger.error(f"Health check failed: {e}")
                await asyncio.sleep(5)  # Shorter retry interval on failure
    
    async def _perform_health_check(self):
        """Perform comprehensive system health check"""
        self.system_health.timestamp = datetime.utcnow()
        
        # Check AgentCore status
        try:
            agentcore_health = await self.agentcore_sdk.check_health()
            self.system_health.agentcore_status = agentcore_health["status"]
        except Exception as e:
            self.system_health.agentcore_status = f"error: {e}"
        
        # Check AWS services status
        try:
            aws_health = await self.aws_infrastructure.check_services_health()
            self.system_health.aws_services_status = "healthy" if all(
                status == "healthy" for status in aws_health.values()
            ) else "degraded"
        except Exception as e:
            self.system_health.aws_services_status = f"error: {e}"
        
        # Check honeypot status
        try:
            honeypot_health = await self.coordinator_agent.check_honeypot_infrastructure()
            self.system_health.honeypot_status = honeypot_health["status"]
        except Exception as e:
            self.system_health.honeypot_status = f"error: {e}"
        
        # Check dashboard status
        try:
            dashboard_health = await self.dashboard_manager.check_health()
            self.system_health.dashboard_status = dashboard_health["status"]
        except Exception as e:
            self.system_health.dashboard_status = f"error: {e}"
        
        # Update overall status
        self._update_overall_status()
        
        # Update active sessions count
        self.system_health.active_sessions = len(self.active_flows)
    
    def _update_overall_status(self):
        """Update overall system status based on component health"""
        statuses = [
            self.system_health.agentcore_status,
            self.system_health.aws_services_status,
            self.system_health.honeypot_status,
            self.system_health.dashboard_status
        ]
        
        if all("error" not in status for status in statuses):
            if all(status in ["healthy", "connected"] for status in statuses):
                self.system_health.overall_status = IntegrationStatus.CONNECTED
            else:
                self.system_health.overall_status = IntegrationStatus.DEGRADED
        else:
            self.system_health.overall_status = IntegrationStatus.FAILED
    
    async def _flow_monitoring_loop(self):
        """Monitor active flows for timeouts and issues"""
        while True:
            try:
                current_time = datetime.utcnow()
                timeout_threshold = timedelta(seconds=self.config["integration"]["flow_timeout"])
                
                # Check for timed out flows
                timed_out_flows = []
                for flow_id, flow in self.active_flows.items():
                    if current_time - flow.start_time > timeout_threshold:
                        timed_out_flows.append(flow_id)
                
                # Handle timed out flows
                for flow_id in timed_out_flows:
                    flow = self.active_flows[flow_id]
                    flow.error_details = "Flow timeout"
                    flow.completion_time = current_time
                    flow.success = False
                    self.integration_metrics["failed_flows"] += 1
                    self._complete_flow(flow)
                    
                    self.logger.warning(f"Flow {flow_id} timed out at stage {flow.current_stage}")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Flow monitoring failed: {e}")
                await asyncio.sleep(60)
    
    async def _performance_monitoring_loop(self):
        """Monitor system performance metrics"""
        while True:
            try:
                # Collect agent response times
                for agent_name, agent in [
                    ("coordinator", self.coordinator_agent),
                    ("detection", self.detection_agent),
                    ("interaction", self.interaction_agent),
                    ("intelligence", self.intelligence_agent)
                ]:
                    if agent:
                        response_time = await agent.get_average_response_time()
                        self.integration_metrics["agent_response_times"][agent_name] = response_time
                
                # Update system performance metrics
                self.system_health.performance_metrics = {
                    "active_flows": len(self.active_flows),
                    "completed_flows": len(self.completed_flows),
                    "success_rate": (
                        self.integration_metrics["successful_flows"] / 
                        max(1, self.integration_metrics["total_flows_processed"])
                    ) * 100,
                    "average_flow_duration": self.integration_metrics["average_flow_duration"],
                    "system_uptime": (
                        datetime.utcnow() - self.integration_metrics["system_uptime"]
                    ).total_seconds()
                }
                
                await asyncio.sleep(300)  # Update every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Performance monitoring failed: {e}")
                await asyncio.sleep(300)
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            "system_health": asdict(self.system_health),
            "integration_metrics": self.integration_metrics,
            "active_flows": len(self.active_flows),
            "completed_flows_last_24h": len([
                flow for flow in self.completed_flows
                if flow.completion_time and 
                (datetime.utcnow() - flow.completion_time).total_seconds() < 86400
            ])
        }
    
    async def get_flow_status(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """Get status of specific flow"""
        # Check active flows
        if flow_id in self.active_flows:
            return asdict(self.active_flows[flow_id])
        
        # Check completed flows
        for flow in self.completed_flows:
            if flow.flow_id == flow_id:
                return asdict(flow)
        
        return None
    
    async def emergency_shutdown(self, reason: str) -> bool:
        """Emergency shutdown of entire system"""
        self.logger.critical(f"Emergency shutdown initiated: {reason}")
        
        try:
            # Stop all active flows
            for flow_id in list(self.active_flows.keys()):
                flow = self.active_flows[flow_id]
                flow.error_details = f"Emergency shutdown: {reason}"
                flow.completion_time = datetime.utcnow()
                flow.success = False
                self._complete_flow(flow)
            
            # Shutdown honeypots
            if self.coordinator_agent:
                await self.coordinator_agent.emergency_shutdown_all_honeypots()
            
            # Shutdown agents
            for agent in [self.coordinator_agent, self.detection_agent,
                         self.interaction_agent, self.intelligence_agent]:
                if agent:
                    await agent.shutdown()
            
            # Shutdown dashboard
            if self.dashboard_manager:
                await self.dashboard_manager.shutdown()
            
            self.system_health.overall_status = IntegrationStatus.FAILED
            self.logger.critical("Emergency shutdown completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Emergency shutdown failed: {e}")
            return False
    
    async def shutdown(self):
        """Graceful system shutdown"""
        self.logger.info("Starting graceful system shutdown...")
        
        # Wait for active flows to complete (with timeout)
        shutdown_timeout = 300  # 5 minutes
        start_time = datetime.utcnow()
        
        while self.active_flows and (datetime.utcnow() - start_time).total_seconds() < shutdown_timeout:
            self.logger.info(f"Waiting for {len(self.active_flows)} active flows to complete...")
            await asyncio.sleep(10)
        
        # Force shutdown remaining flows
        if self.active_flows:
            self.logger.warning(f"Force completing {len(self.active_flows)} remaining flows")
            for flow_id in list(self.active_flows.keys()):
                flow = self.active_flows[flow_id]
                flow.error_details = "System shutdown"
                flow.completion_time = datetime.utcnow()
                flow.success = False
                self._complete_flow(flow)
        
        # Shutdown components
        await self.emergency_shutdown("Graceful shutdown")
        
        self.logger.info("System shutdown completed")


# Integration configuration
async def create_integration_config():
    """Create default integration configuration file"""
    config = {
        "agentcore": {
            "endpoint": "https://agentcore.us-east-1.amazonaws.com",
            "region": "us-east-1",
            "timeout": 30,
            "retry_attempts": 3
        },
        "aws_services": {
            "region": "us-east-1",
            "s3_bucket": "ai-honeypot-data",
            "rds_endpoint": "ai-honeypot-db.cluster-xyz.us-east-1.rds.amazonaws.com",
            "sns_topic": "ai-honeypot-alerts"
        },
        "honeypots": {
            "max_concurrent_sessions": 10,
            "session_timeout": 3600,
            "auto_destroy_timeout": 3600
        },
        "dashboard": {
            "port": 8080,
            "host": "0.0.0.0",
            "auth_required": True
        },
        "integration": {
            "health_check_interval": 30,
            "flow_timeout": 1800,
            "max_active_flows": 50
        }
    }
    
    with open("config/integration_config.json", "w") as f:
        json.dump(config, f, indent=2)


if __name__ == "__main__":
    # Example usage
    async def main():
        # Create configuration
        await create_integration_config()
        
        # Initialize system integration
        integration_manager = SystemIntegrationManager()
        
        # Initialize system
        success = await integration_manager.initialize_system()
        if not success:
            print("System initialization failed")
            return
        
        # Example threat event processing
        threat_event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "external_feed",
            "threat_type": "suspicious_login",
            "confidence_score": 0.85,
            "indicators": ["192.168.1.100", "admin@company.com"],
            "raw_data": {"login_attempts": 5, "source_ip": "192.168.1.100"}
        }
        
        # Process end-to-end flow
        flow_id = await integration_manager.process_end_to_end_flow(threat_event)
        print(f"Started end-to-end flow: {flow_id}")
        
        # Monitor system for a while
        for i in range(10):
            status = await integration_manager.get_system_status()
            print(f"System status: {status['system_health']['overall_status']}")
            await asyncio.sleep(30)
        
        # Graceful shutdown
        await integration_manager.shutdown()
    
    asyncio.run(main())