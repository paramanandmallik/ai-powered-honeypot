"""
Coordinator Agent for AI-Powered Honeypot System
Orchestrates the entire honeypot lifecycle and coordinates between all other agents.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from uuid import uuid4

from strands import tool
from ..base_agent import BaseAgent
from .orchestration_engine import OrchestrationEngine, WorkflowStatus, HoneypotStatus
from .honeypot_manager import HoneypotManager
from .monitoring_system import SystemMonitoringSystem


class CoordinatorAgent(BaseAgent):
    """
    Coordinator Agent that manages the entire honeypot system lifecycle.
    Orchestrates workflows, coordinates agents, and manages honeypot instances.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        capabilities = [
            "workflow_orchestration",
            "agent_coordination", 
            "honeypot_lifecycle_management",
            "resource_management",
            "emergency_procedures",
            "system_monitoring"
        ]
        
        super().__init__("coordinator", capabilities, config)
        
        # Initialize orchestration engine
        self.orchestration_engine = OrchestrationEngine(self)
        
        # Initialize honeypot manager
        self.honeypot_manager = HoneypotManager(self)
        
        # Initialize monitoring system
        self.monitoring_system = SystemMonitoringSystem(self)
        
        # Message routing
        self.message_handlers = {
            "engagement_decision": self.handle_engagement_decision,
            "honeypot_request": self.handle_honeypot_request,
            "agent_coordination": self.handle_agent_coordination,
            "emergency_shutdown": self.handle_emergency_shutdown,
            "health_check": self.handle_health_check,
            "system_status": self.handle_system_status,
            "resource_allocation": self.handle_resource_allocation
        }
        
        # Configuration
        self.auto_scaling_enabled = config.get("auto_scaling_enabled", True) if config else True
        self.max_concurrent_engagements = config.get("max_concurrent_engagements", 10) if config else 10
        self.honeypot_timeout_minutes = config.get("honeypot_timeout_minutes", 60) if config else 60
        
        self.logger.info("Coordinator Agent initialized")
    
    async def initialize(self):
        """Initialize the coordinator agent"""
        try:
            # Start orchestration engine
            await self.orchestration_engine.start()
            
            # Start honeypot manager
            await self.honeypot_manager.start()
            
            # Start monitoring system
            await self.monitoring_system.start()
            
            # Register with other agents
            await self._register_with_agents()
            
            # Start monitoring tasks
            asyncio.create_task(self._honeypot_lifecycle_monitor())
            asyncio.create_task(self._system_health_monitor())
            
            self.logger.info("Coordinator Agent initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize coordinator agent: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup coordinator agent resources"""
        try:
            # Stop monitoring system
            await self.monitoring_system.stop()
            
            # Stop honeypot manager
            await self.honeypot_manager.stop()
            
            # Stop orchestration engine
            await self.orchestration_engine.stop()
            
            self.logger.info("Coordinator Agent cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during coordinator agent cleanup: {e}")
    
    async def process_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process incoming messages"""
        try:
            message_type = message.get("message_type")
            
            if message_type in self.message_handlers:
                handler = self.message_handlers[message_type]
                response = await handler(message)
                
                self.increment_message_count(message_type)
                return response
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                return {"success": False, "error": f"Unknown message type: {message_type}"}
                
        except Exception as e:
            self.logger.error(f"Failed to process message: {e}")
            return {"success": False, "error": str(e)}
    
    # Message Handlers
    async def handle_engagement_decision(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle engagement decision from Detection Agent"""
        try:
            payload = message.get("payload", {})
            threat_data = payload.get("threat_data", {})
            engagement_approved = payload.get("engagement_approved", False)
            
            if not engagement_approved:
                self.logger.info("Engagement not approved, skipping honeypot creation")
                return {"success": True, "action": "engagement_declined"}
            
            # Create appropriate honeypot based on threat type
            honeypot_type = self._determine_honeypot_type(threat_data)
            honeypot_config = self._generate_honeypot_config(honeypot_type, threat_data)
            
            # Create honeypot
            honeypot_id = await self.orchestration_engine.create_honeypot(
                honeypot_type, honeypot_config
            )
            
            if honeypot_id:
                # Notify Interaction Agent
                await self.orchestration_engine.send_agent_message(
                    "interaction",
                    "honeypot_ready",
                    {
                        "honeypot_id": honeypot_id,
                        "honeypot_type": honeypot_type,
                        "threat_data": threat_data,
                        "config": honeypot_config
                    }
                )
                
                return {
                    "success": True,
                    "honeypot_id": honeypot_id,
                    "honeypot_type": honeypot_type,
                    "action": "honeypot_created"
                }
            else:
                return {"success": False, "error": "Failed to create honeypot"}
                
        except Exception as e:
            self.logger.error(f"Failed to handle engagement decision: {e}")
            return {"success": False, "error": str(e)}
    
    async def handle_honeypot_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle manual honeypot creation request"""
        try:
            payload = message.get("payload", {})
            honeypot_type = payload.get("honeypot_type")
            config = payload.get("config", {})
            
            if not honeypot_type:
                return {"success": False, "error": "Missing honeypot_type"}
            
            honeypot_id = await self.orchestration_engine.create_honeypot(
                honeypot_type, config
            )
            
            if honeypot_id:
                return {
                    "success": True,
                    "honeypot_id": honeypot_id,
                    "honeypot_type": honeypot_type
                }
            else:
                return {"success": False, "error": "Failed to create honeypot"}
                
        except Exception as e:
            self.logger.error(f"Failed to handle honeypot request: {e}")
            return {"success": False, "error": str(e)}
    
    async def handle_agent_coordination(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle agent coordination requests"""
        try:
            payload = message.get("payload", {})
            coordination_type = payload.get("coordination_type")
            agents = payload.get("agents", [])
            parameters = payload.get("parameters", {})
            
            result = await self.orchestration_engine.coordinate_agents(
                coordination_type, agents, parameters
            )
            
            return {"success": True, "coordination_result": result}
            
        except Exception as e:
            self.logger.error(f"Failed to handle agent coordination: {e}")
            return {"success": False, "error": str(e)}
    
    async def handle_emergency_shutdown(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle emergency shutdown request"""
        try:
            payload = message.get("payload", {})
            reason = payload.get("reason", "Emergency shutdown requested")
            initiated_by = payload.get("initiated_by", "unknown")
            
            await self.orchestration_engine.emergency_shutdown(reason, initiated_by)
            
            return {"success": True, "action": "emergency_shutdown_initiated"}
            
        except Exception as e:
            self.logger.error(f"Failed to handle emergency shutdown: {e}")
            return {"success": False, "error": str(e)}
    
    async def handle_health_check(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle health check request"""
        try:
            health_data = await self.health_check_tool()
            system_status = await self.orchestration_engine.get_system_status()
            
            return {
                "success": True,
                "agent_health": health_data,
                "system_status": system_status
            }
            
        except Exception as e:
            self.logger.error(f"Failed to handle health check: {e}")
            return {"success": False, "error": str(e)}
    
    async def handle_system_status(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle system status request"""
        try:
            status = await self.orchestration_engine.get_system_status()
            return {"success": True, "system_status": status}
            
        except Exception as e:
            self.logger.error(f"Failed to handle system status: {e}")
            return {"success": False, "error": str(e)}
    
    async def handle_resource_allocation(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle resource allocation request"""
        try:
            payload = message.get("payload", {})
            resource_type = payload.get("resource_type")
            requirements = payload.get("requirements", {})
            
            allocation_id = await self.orchestration_engine.allocate_resources(
                resource_type, requirements
            )
            
            if allocation_id:
                return {"success": True, "allocation_id": allocation_id}
            else:
                return {"success": False, "error": "Resource allocation failed"}
                
        except Exception as e:
            self.logger.error(f"Failed to handle resource allocation: {e}")
            return {"success": False, "error": str(e)}
    
    # Strands Tools for Coordinator Agent
    @tool
    def create_honeypot_tool(self, honeypot_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new honeypot instance"""
        try:
            # This will be called asynchronously by the orchestration engine
            task = asyncio.create_task(
                self.orchestration_engine.create_honeypot(honeypot_type, config)
            )
            
            return {
                "action": "honeypot_creation_initiated",
                "honeypot_type": honeypot_type,
                "config": config,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create honeypot via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def destroy_honeypot_tool(self, honeypot_id: str, reason: str = "Manual destruction") -> Dict[str, Any]:
        """Destroy a honeypot instance"""
        try:
            task = asyncio.create_task(
                self.orchestration_engine.destroy_honeypot(honeypot_id, reason)
            )
            
            return {
                "action": "honeypot_destruction_initiated",
                "honeypot_id": honeypot_id,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to destroy honeypot via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def coordinate_agents_tool(self, coordination_type: str, agents: List[str], 
                             parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate multiple agents for a task"""
        try:
            task = asyncio.create_task(
                self.orchestration_engine.coordinate_agents(coordination_type, agents, parameters)
            )
            
            return {
                "action": "agent_coordination_initiated",
                "coordination_type": coordination_type,
                "agents": agents,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to coordinate agents via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def emergency_shutdown_tool(self, reason: str, initiated_by: str = "coordinator_agent") -> Dict[str, Any]:
        """Initiate emergency shutdown procedures"""
        try:
            task = asyncio.create_task(
                self.orchestration_engine.emergency_shutdown(reason, initiated_by)
            )
            
            return {
                "action": "emergency_shutdown_initiated",
                "reason": reason,
                "initiated_by": initiated_by,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to initiate emergency shutdown via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def get_system_status_tool(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        try:
            # Create async task to get status
            loop = asyncio.get_event_loop()
            status = loop.run_until_complete(self.orchestration_engine.get_system_status())
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get system status via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def get_system_health_tool(self) -> Dict[str, Any]:
        """Get system health monitoring data"""
        try:
            loop = asyncio.get_event_loop()
            health_data = loop.run_until_complete(self.monitoring_system.monitor_system_health())
            
            return health_data
            
        except Exception as e:
            self.logger.error(f"Failed to get system health via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def create_monitoring_alert_tool(self, alert_type: str, severity: str, title: str, 
                                   description: str) -> Dict[str, Any]:
        """Create a monitoring alert"""
        try:
            from .monitoring_system import AlertSeverity
            
            severity_enum = AlertSeverity(severity.lower())
            
            loop = asyncio.get_event_loop()
            alert_id = loop.run_until_complete(
                self.monitoring_system.create_alert(
                    alert_type, severity_enum, title, description, 
                    "coordinator", "coordinator_tool"
                )
            )
            
            return {
                "alert_id": alert_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create monitoring alert via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def get_performance_metrics_tool(self, time_range_hours: int = 1) -> Dict[str, Any]:
        """Get performance metrics summary"""
        try:
            loop = asyncio.get_event_loop()
            metrics = loop.run_until_complete(
                self.monitoring_system.get_performance_summary(time_range_hours)
            )
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to get performance metrics via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def get_active_alerts_tool(self, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get active monitoring alerts"""
        try:
            from .monitoring_system import AlertSeverity
            
            severity_enum = AlertSeverity(severity_filter.lower()) if severity_filter else None
            
            loop = asyncio.get_event_loop()
            alerts = loop.run_until_complete(
                self.monitoring_system.get_active_alerts(severity_enum)
            )
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to get active alerts via tool: {e}")
            return []
    
    @tool
    def create_workflow_tool(self, workflow_name: str, workflow_type: str, 
                           steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a new workflow"""
        try:
            task = asyncio.create_task(
                self.orchestration_engine.create_workflow(workflow_name, workflow_type, steps)
            )
            
            return {
                "action": "workflow_creation_initiated",
                "workflow_name": workflow_name,
                "workflow_type": workflow_type,
                "steps_count": len(steps),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create workflow via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def auto_scale_system_tool(self, scaling_trigger: str, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger auto-scaling based on system metrics"""
        try:
            task = asyncio.create_task(
                self._execute_auto_scaling(scaling_trigger, metrics)
            )
            
            return {
                "action": "auto_scaling_initiated",
                "scaling_trigger": scaling_trigger,
                "metrics": metrics,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to trigger auto-scaling via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def manage_resource_allocation_tool(self, action: str, resource_type: str, 
                                     allocation_params: Dict[str, Any]) -> Dict[str, Any]:
        """Manage resource allocation for agents and honeypots"""
        try:
            if action == "allocate":
                task = asyncio.create_task(
                    self.orchestration_engine.allocate_resources(resource_type, allocation_params)
                )
            elif action == "deallocate":
                allocation_id = allocation_params.get("allocation_id")
                if allocation_id:
                    task = asyncio.create_task(
                        self.orchestration_engine.deallocate_resources(allocation_id)
                    )
                else:
                    return {"error": "allocation_id required for deallocation"}
            else:
                return {"error": f"Unknown action: {action}"}
            
            return {
                "action": f"resource_{action}_initiated",
                "resource_type": resource_type,
                "params": allocation_params,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to manage resource allocation via tool: {e}")
            return {"error": str(e)}
    
    # Helper Methods
    def _determine_honeypot_type(self, threat_data: Dict[str, Any]) -> str:
        """Determine appropriate honeypot type based on threat data"""
        try:
            # Analyze threat indicators to determine best honeypot type
            attack_vectors = threat_data.get("attack_vectors", [])
            target_services = threat_data.get("target_services", [])
            
            # Priority mapping based on threat characteristics
            if "web" in attack_vectors or "http" in target_services:
                return "web_admin"
            elif "ssh" in attack_vectors or "22" in target_services:
                return "ssh"
            elif "database" in attack_vectors or any(port in target_services for port in ["3306", "5432", "1433"]):
                return "database"
            elif "smb" in attack_vectors or "445" in target_services:
                return "file_share"
            elif "email" in attack_vectors or any(port in target_services for port in ["25", "143", "993"]):
                return "email"
            else:
                # Default to web admin portal
                return "web_admin"
                
        except Exception as e:
            self.logger.error(f"Failed to determine honeypot type: {e}")
            return "web_admin"  # Safe default
    
    def _generate_honeypot_config(self, honeypot_type: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate honeypot configuration based on type and threat data"""
        try:
            base_config = {
                "honeypot_id": str(uuid4()),
                "honeypot_type": honeypot_type,
                "created_at": datetime.utcnow().isoformat(),
                "threat_context": threat_data,
                "timeout_minutes": self.honeypot_timeout_minutes
            }
            
            # Type-specific configuration
            if honeypot_type == "web_admin":
                base_config.update({
                    "port": 8080,
                    "ssl_enabled": True,
                    "admin_theme": "corporate",
                    "fake_users": 50,
                    "fake_departments": ["IT", "HR", "Finance", "Operations"]
                })
            elif honeypot_type == "ssh":
                base_config.update({
                    "port": 22,
                    "banner": "Ubuntu 20.04.3 LTS",
                    "fake_filesystem": True,
                    "command_simulation": True,
                    "fake_processes": ["apache2", "mysql", "nginx"]
                })
            elif honeypot_type == "database":
                base_config.update({
                    "port": 3306,
                    "database_type": "mysql",
                    "fake_databases": ["customers", "orders", "inventory"],
                    "fake_tables_per_db": 10,
                    "fake_records_per_table": 1000
                })
            elif honeypot_type == "file_share":
                base_config.update({
                    "port": 445,
                    "protocol": "smb",
                    "fake_shares": ["documents", "projects", "backups"],
                    "fake_files_per_share": 100,
                    "document_types": ["pdf", "docx", "xlsx", "txt"]
                })
            elif honeypot_type == "email":
                base_config.update({
                    "smtp_port": 25,
                    "imap_port": 143,
                    "fake_accounts": 20,
                    "fake_emails_per_account": 50,
                    "email_domains": ["company.com", "corp.local"]
                })
            
            return base_config
            
        except Exception as e:
            self.logger.error(f"Failed to generate honeypot config: {e}")
            return {"error": str(e)}
    
    async def _register_with_agents(self):
        """Register coordinator with other agents"""
        try:
            registration_message = {
                "coordinator_id": self.agent_id,
                "capabilities": self.capabilities,
                "status": "active",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            for agent_type in ["detection", "interaction", "intelligence"]:
                await self.orchestration_engine.send_agent_message(
                    agent_type,
                    "coordinator_registration",
                    registration_message
                )
            
            self.logger.info("Registered with all agents")
            
        except Exception as e:
            self.logger.error(f"Failed to register with agents: {e}")
    
    async def _honeypot_lifecycle_monitor(self):
        """Monitor honeypot lifecycle and handle timeouts"""
        while True:
            try:
                current_time = datetime.utcnow()
                
                for honeypot_id, honeypot in self.orchestration_engine.honeypot_instances.items():
                    if honeypot.status == HoneypotStatus.ACTIVE:
                        created_time = datetime.fromisoformat(honeypot.created_at)
                        age_minutes = (current_time - created_time).total_seconds() / 60
                        
                        # Check for timeout
                        if age_minutes > self.honeypot_timeout_minutes:
                            await self.orchestration_engine.destroy_honeypot(
                                honeypot_id, "Timeout - exceeded maximum lifetime"
                            )
                        
                        # Check for inactivity
                        elif honeypot.last_activity:
                            last_activity = datetime.fromisoformat(honeypot.last_activity)
                            inactive_minutes = (current_time - last_activity).total_seconds() / 60
                            
                            if inactive_minutes > 30:  # 30 minutes of inactivity
                                await self.orchestration_engine.destroy_honeypot(
                                    honeypot_id, "Inactivity timeout"
                                )
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in honeypot lifecycle monitor: {e}")
                await asyncio.sleep(60)
    
    async def _system_health_monitor(self):
        """Monitor overall system health and performance"""
        while True:
            try:
                # Get system status
                status = await self.orchestration_engine.get_system_status()
                
                # Check for critical issues
                if status.get("system_status") == "emergency":
                    self.logger.critical("System in emergency state")
                
                # Check agent health
                agent_health = status.get("agent_health", {})
                failed_agents = [agent for agent, health in agent_health.items() if health == "failed"]
                
                if failed_agents:
                    self.logger.warning(f"Failed agents detected: {failed_agents}")
                    
                    # Attempt to restart failed agents if auto-scaling is enabled
                    if self.auto_scaling_enabled:
                        for agent_type in failed_agents:
                            await self._attempt_agent_recovery(agent_type)
                
                # Check resource usage
                total_honeypots = status.get("total_honeypots", 0)
                if total_honeypots > self.max_concurrent_engagements:
                    self.logger.warning(f"High honeypot count: {total_honeypots}")
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in system health monitor: {e}")
                await asyncio.sleep(300)
    
    async def _attempt_agent_recovery(self, agent_type: str):
        """Attempt to recover a failed agent"""
        try:
            self.logger.info(f"Attempting recovery for {agent_type} agent")
            
            # Send recovery message
            await self.orchestration_engine.send_agent_message(
                agent_type,
                "recovery_request",
                {"initiated_by": "coordinator", "timestamp": datetime.utcnow().isoformat()}
            )
            
            # Wait and check if recovery was successful
            await asyncio.sleep(30)
            
            health_response = await self.orchestration_engine.send_agent_message(
                agent_type,
                "health_check",
                {}
            )
            
            if health_response and health_response.get("success"):
                self.logger.info(f"Successfully recovered {agent_type} agent")
                
                # Create alert for successful recovery
                await self.monitoring_system.create_alert(
                    "agent_recovery_success",
                    self.monitoring_system.AlertSeverity.MEDIUM,
                    f"Agent Recovery Successful",
                    f"{agent_type} agent has been successfully recovered",
                    "coordinator",
                    self.agent_id
                )
            else:
                self.logger.error(f"Failed to recover {agent_type} agent")
                
                # Create critical alert for failed recovery
                await self.monitoring_system.create_alert(
                    "agent_recovery_failed",
                    self.monitoring_system.AlertSeverity.CRITICAL,
                    f"Agent Recovery Failed",
                    f"Failed to recover {agent_type} agent - manual intervention required",
                    "coordinator",
                    self.agent_id
                )
                
        except Exception as e:
            self.logger.error(f"Error attempting agent recovery for {agent_type}: {e}")
            
            # Create alert for recovery error
            await self.monitoring_system.create_alert(
                "agent_recovery_error",
                self.monitoring_system.AlertSeverity.HIGH,
                f"Agent Recovery Error",
                f"Error during {agent_type} agent recovery: {str(e)}",
                "coordinator",
                self.agent_id
            )
    
    async def _execute_auto_scaling(self, scaling_trigger: str, metrics: Dict[str, Any]):
        """Execute auto-scaling decisions based on system metrics"""
        try:
            self.logger.info(f"Executing auto-scaling for trigger: {scaling_trigger}")
            
            # Analyze metrics to determine scaling action
            cpu_usage = metrics.get("cpu_usage", 0)
            memory_usage = metrics.get("memory_usage", 0)
            active_sessions = metrics.get("active_sessions", 0)
            queue_depth = metrics.get("message_queue_depth", 0)
            
            scaling_actions = []
            
            # Scale up conditions
            if cpu_usage > 80 or memory_usage > 85 or queue_depth > 100:
                # Scale up interaction agents for high load
                if active_sessions > 8:
                    scaling_actions.append({
                        "action": "scale_up",
                        "agent_type": "interaction",
                        "reason": f"High load: sessions={active_sessions}, cpu={cpu_usage}%"
                    })
                
                # Scale up detection agents for high queue depth
                if queue_depth > 50:
                    scaling_actions.append({
                        "action": "scale_up",
                        "agent_type": "detection",
                        "reason": f"High queue depth: {queue_depth}"
                    })
            
            # Scale down conditions
            elif cpu_usage < 20 and memory_usage < 30 and active_sessions < 2:
                scaling_actions.append({
                    "action": "scale_down",
                    "agent_type": "interaction",
                    "reason": f"Low utilization: sessions={active_sessions}, cpu={cpu_usage}%"
                })
            
            # Execute scaling actions
            for action in scaling_actions:
                await self._execute_scaling_action(action)
            
            # Log scaling decision
            await self.monitoring_system.log_audit_event(
                "auto_scaling_executed",
                "coordinator",
                None,
                "auto_scale",
                scaling_trigger,
                "success",
                {"actions": scaling_actions, "metrics": metrics}
            )
            
        except Exception as e:
            self.logger.error(f"Failed to execute auto-scaling: {e}")
    
    async def _execute_scaling_action(self, action: Dict[str, Any]):
        """Execute a specific scaling action"""
        try:
            action_type = action["action"]
            agent_type = action["agent_type"]
            reason = action["reason"]
            
            if action_type == "scale_up":
                # In AgentCore Runtime, this would trigger instance scaling
                self.logger.info(f"Scaling up {agent_type} agents: {reason}")
                
                # Send scaling message to AgentCore Runtime
                await self.orchestration_engine.send_agent_message(
                    "agentcore_runtime",
                    "scale_agent_instances",
                    {
                        "agent_type": agent_type,
                        "action": "scale_up",
                        "target_instances": 2,
                        "reason": reason
                    }
                )
                
            elif action_type == "scale_down":
                self.logger.info(f"Scaling down {agent_type} agents: {reason}")
                
                # Send scaling message to AgentCore Runtime
                await self.orchestration_engine.send_agent_message(
                    "agentcore_runtime",
                    "scale_agent_instances",
                    {
                        "agent_type": agent_type,
                        "action": "scale_down",
                        "target_instances": 1,
                        "reason": reason
                    }
                )
            
        except Exception as e:
            self.logger.error(f"Failed to execute scaling action: {e}")
    
    async def send_message(self, target_agent: str, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send message to another agent (used by orchestration engine)"""
        try:
            # In a real implementation, this would use AgentCore's messaging system
            # For now, we'll simulate the message sending
            
            self.logger.debug(f"Sending message to {target_agent}: {message.get('message_type')}")
            
            # Simulate response based on message type
            if message.get("message_type") == "health_check":
                return {
                    "success": True,
                    "agent_id": f"{target_agent}_agent",
                    "health": "healthy",
                    "response_time_ms": 50,
                    "error_count": 0,
                    "message_queue_depth": 0,
                    "resource_usage": {"cpu": 10, "memory": 256}
                }
            elif message.get("message_type") == "scale_agent_instances":
                return {
                    "success": True,
                    "message": "Scaling request processed",
                    "scaling_initiated": True
                }
            else:
                return {"success": True, "message": "Message processed"}
                
        except Exception as e:
            self.logger.error(f"Failed to send message to {target_agent}: {e}")
            return None