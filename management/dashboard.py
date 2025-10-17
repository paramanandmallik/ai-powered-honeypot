"""
Web-based Management Dashboard for AI-Powered Honeypot System
Provides real-time monitoring, visualization, and manual management capabilities.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from uuid import uuid4
from dataclasses import dataclass, asdict
from enum import Enum

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import uvicorn


class DashboardStatus(Enum):
    """Dashboard system status"""
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    ERROR = "error"


class HoneypotDisplayStatus(Enum):
    """Honeypot status for dashboard display"""
    ACTIVE = "active"
    CREATING = "creating"
    DESTROYING = "destroying"
    INACTIVE = "inactive"
    ERROR = "error"


@dataclass
class HoneypotInfo:
    """Honeypot information for dashboard display"""
    honeypot_id: str
    honeypot_type: str
    status: HoneypotDisplayStatus
    created_at: str
    last_activity: Optional[str]
    attacker_count: int
    interaction_count: int
    threat_level: str
    config: Dict[str, Any]


@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: str
    total_honeypots: int
    active_engagements: int
    total_interactions: int
    cpu_usage: float
    memory_usage: float
    network_traffic: float
    agent_health: Dict[str, str]
    alert_count: int


@dataclass
class AttackerInteraction:
    """Attacker interaction data for visualization"""
    interaction_id: str
    honeypot_id: str
    honeypot_type: str
    timestamp: str
    attacker_ip: str
    command: str
    response: str
    threat_score: float
    mitre_techniques: List[str]


class DashboardWebSocketManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.logger = logging.getLogger(__name__)
    
    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        self.logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            self.logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific WebSocket"""
        try:
            await websocket.send_text(message)
        except Exception as e:
            self.logger.error(f"Failed to send personal message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: str):
        """Broadcast message to all connected WebSockets"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                self.logger.error(f"Failed to broadcast to connection: {e}")
                disconnected.append(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            self.disconnect(connection)


class DashboardManager:
    """
    Web-based Management Dashboard Manager
    Provides real-time honeypot monitoring, attacker interaction visualization,
    system health dashboards, and manual honeypot management capabilities.
    """
    
    def __init__(self, coordinator_agent=None, config: Optional[Dict[str, Any]] = None):
        self.coordinator_agent = coordinator_agent
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Dashboard configuration
        self.host = self.config.get("host", "0.0.0.0")
        self.port = self.config.get("port", 8000)
        self.debug = self.config.get("debug", False)
        
        # Initialize FastAPI app
        self.app = FastAPI(
            title="AI Honeypot Management Dashboard",
            description="Real-time monitoring and management for AI-powered honeypot system",
            version="1.0.0"
        )
        
        # WebSocket manager for real-time updates
        self.websocket_manager = DashboardWebSocketManager()
        
        # Security
        self.security = HTTPBearer()
        
        # Data storage for dashboard
        self.honeypot_data: Dict[str, HoneypotInfo] = {}
        self.system_metrics_history: List[SystemMetrics] = []
        self.recent_interactions: List[AttackerInteraction] = []
        self.active_alerts: List[Dict[str, Any]] = []
        
        # Dashboard status
        self.status = DashboardStatus.ACTIVE
        
        # Setup routes
        self._setup_routes()
        
        # Background tasks
        self._background_tasks = []
        
        self.logger.info("Dashboard Manager initialized")
    
    def _setup_routes(self):
        """Setup FastAPI routes for the dashboard"""
        
        # Static files and templates
        self.app.mount("/static", StaticFiles(directory="management/static"), name="static")
        self.templates = Jinja2Templates(directory="management/templates")
        
        # Main dashboard route
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard_home(request):
            return self.templates.TemplateResponse("dashboard.html", {"request": request})
        
        # API Routes
        @self.app.get("/api/status")
        async def get_system_status():
            return await self.get_system_status()
        
        @self.app.get("/api/honeypots")
        async def get_honeypots():
            return await self.get_honeypots_status()
        
        @self.app.get("/api/metrics")
        async def get_metrics():
            return await self.get_system_metrics()
        
        @self.app.get("/api/interactions")
        async def get_interactions():
            return await self.get_recent_interactions()
        
        @self.app.get("/api/alerts")
        async def get_alerts():
            return await self.get_active_alerts()
        
        # Honeypot management routes
        @self.app.post("/api/honeypots")
        async def create_honeypot(request: dict):
            return await self.create_honeypot_manual(request)
        
        @self.app.delete("/api/honeypots/{honeypot_id}")
        async def destroy_honeypot(honeypot_id: str):
            return await self.destroy_honeypot_manual(honeypot_id)
        
        @self.app.post("/api/honeypots/{honeypot_id}/action")
        async def honeypot_action(honeypot_id: str, action: dict):
            return await self.perform_honeypot_action(honeypot_id, action)
        
        # Emergency controls
        @self.app.post("/api/emergency/shutdown")
        async def emergency_shutdown(request: dict):
            return await self.emergency_shutdown(request)
        
        # Enhanced API routes for real-time monitoring
        @self.app.get("/api/interactions/realtime")
        async def get_realtime_interactions():
            return await self.get_real_time_interactions()
        
        @self.app.get("/api/honeypots/health")
        async def get_honeypot_health():
            return await self.get_honeypot_health_details()
        
        @self.app.get("/api/system/alerts")
        async def get_system_alerts():
            return await self.get_system_alerts()
        
        @self.app.post("/api/honeypots/bulk-action")
        async def bulk_honeypot_action(request: dict):
            honeypot_ids = request.get("honeypot_ids", [])
            action = request.get("action")
            return await self.perform_bulk_honeypot_action(honeypot_ids, action)
        
        @self.app.get("/api/agentcore/metrics")
        async def get_agentcore_metrics():
            return await self._get_agentcore_metrics()
        
        # WebSocket endpoint for real-time updates
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await self.websocket_manager.connect(websocket)
            try:
                while True:
                    # Keep connection alive and handle incoming messages
                    data = await websocket.receive_text()
                    # Echo back for now (can be extended for client commands)
                    await self.websocket_manager.send_personal_message(f"Echo: {data}", websocket)
            except WebSocketDisconnect:
                self.websocket_manager.disconnect(websocket)
    
    async def start(self):
        """Start the dashboard manager"""
        try:
            # Start background monitoring tasks
            self._background_tasks.append(
                asyncio.create_task(self._monitor_system_metrics())
            )
            self._background_tasks.append(
                asyncio.create_task(self._monitor_honeypot_status())
            )
            self._background_tasks.append(
                asyncio.create_task(self._monitor_interactions())
            )
            self._background_tasks.append(
                asyncio.create_task(self._broadcast_updates())
            )
            
            self.logger.info("Dashboard Manager started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start dashboard manager: {e}")
            raise
    
    async def stop(self):
        """Stop the dashboard manager"""
        try:
            # Cancel background tasks
            for task in self._background_tasks:
                task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            
            self.logger.info("Dashboard Manager stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping dashboard manager: {e}")
    
    async def run_server(self):
        """Run the dashboard web server"""
        try:
            config = uvicorn.Config(
                self.app,
                host=self.host,
                port=self.port,
                log_level="info" if not self.debug else "debug"
            )
            server = uvicorn.Server(config)
            await server.serve()
            
        except Exception as e:
            self.logger.error(f"Failed to run dashboard server: {e}")
            raise
    
    # API Methods
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        try:
            # Get status from coordinator agent if available
            if self.coordinator_agent:
                coordinator_status = await self.coordinator_agent.get_system_status_tool()
            else:
                coordinator_status = {"status": "coordinator_unavailable"}
            
            return {
                "dashboard_status": self.status.value,
                "timestamp": datetime.utcnow().isoformat(),
                "coordinator_status": coordinator_status,
                "total_honeypots": len(self.honeypot_data),
                "active_honeypots": len([h for h in self.honeypot_data.values() 
                                       if h.status == HoneypotDisplayStatus.ACTIVE]),
                "total_interactions": sum(h.interaction_count for h in self.honeypot_data.values()),
                "active_alerts": len(self.active_alerts),
                "websocket_connections": len(self.websocket_manager.active_connections)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get system status: {e}")
            return {"error": str(e)}
    
    async def get_honeypots_status(self) -> List[Dict[str, Any]]:
        """Get status of all honeypots"""
        try:
            return [asdict(honeypot) for honeypot in self.honeypot_data.values()]
            
        except Exception as e:
            self.logger.error(f"Failed to get honeypots status: {e}")
            return []
    
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics including AgentCore Runtime metrics"""
        try:
            # Get latest metrics
            if self.system_metrics_history:
                latest_metrics = self.system_metrics_history[-1]
                
                # Get historical data for charts
                historical_data = []
                for metrics in self.system_metrics_history[-24:]:  # Last 24 data points
                    historical_data.append({
                        "timestamp": metrics.timestamp,
                        "cpu_usage": metrics.cpu_usage,
                        "memory_usage": metrics.memory_usage,
                        "network_traffic": metrics.network_traffic,
                        "total_honeypots": metrics.total_honeypots,
                        "active_engagements": metrics.active_engagements
                    })
                
                # Get AgentCore Runtime metrics
                agentcore_metrics = await self._get_agentcore_metrics()
                
                return {
                    "current_metrics": asdict(latest_metrics),
                    "historical_data": historical_data,
                    "agentcore_metrics": agentcore_metrics
                }
            else:
                return {"current_metrics": None, "historical_data": [], "agentcore_metrics": {}}
                
        except Exception as e:
            self.logger.error(f"Failed to get system metrics: {e}")
            return {"error": str(e)}
    
    async def get_recent_interactions(self) -> List[Dict[str, Any]]:
        """Get recent attacker interactions"""
        try:
            # Return last 100 interactions
            recent = self.recent_interactions[-100:]
            return [asdict(interaction) for interaction in recent]
            
        except Exception as e:
            self.logger.error(f"Failed to get recent interactions: {e}")
            return []
    
    async def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get active system alerts"""
        try:
            return self.active_alerts.copy()
            
        except Exception as e:
            self.logger.error(f"Failed to get active alerts: {e}")
            return []
    
    # Honeypot Management Methods
    async def create_honeypot_manual(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Create honeypot manually from dashboard"""
        try:
            honeypot_type = request.get("honeypot_type")
            config = request.get("config", {})
            
            if not honeypot_type:
                raise HTTPException(status_code=400, detail="Missing honeypot_type")
            
            # Use coordinator agent to create honeypot
            if self.coordinator_agent:
                result = self.coordinator_agent.create_honeypot_tool(honeypot_type, config)
                
                if "error" not in result:
                    # Add to local tracking
                    honeypot_id = config.get("honeypot_id", str(uuid4()))
                    self.honeypot_data[honeypot_id] = HoneypotInfo(
                        honeypot_id=honeypot_id,
                        honeypot_type=honeypot_type,
                        status=HoneypotDisplayStatus.CREATING,
                        created_at=datetime.utcnow().isoformat(),
                        last_activity=None,
                        attacker_count=0,
                        interaction_count=0,
                        threat_level="low",
                        config=config
                    )
                    
                    return {"success": True, "honeypot_id": honeypot_id}
                else:
                    return {"success": False, "error": result["error"]}
            else:
                return {"success": False, "error": "Coordinator agent not available"}
                
        except Exception as e:
            self.logger.error(f"Failed to create honeypot manually: {e}")
            return {"success": False, "error": str(e)}
    
    async def destroy_honeypot_manual(self, honeypot_id: str) -> Dict[str, Any]:
        """Destroy honeypot manually from dashboard"""
        try:
            if honeypot_id not in self.honeypot_data:
                raise HTTPException(status_code=404, detail="Honeypot not found")
            
            # Use coordinator agent to destroy honeypot
            if self.coordinator_agent:
                result = self.coordinator_agent.destroy_honeypot_tool(
                    honeypot_id, "Manual destruction from dashboard"
                )
                
                if "error" not in result:
                    # Update local tracking
                    if honeypot_id in self.honeypot_data:
                        self.honeypot_data[honeypot_id].status = HoneypotDisplayStatus.DESTROYING
                    
                    return {"success": True, "honeypot_id": honeypot_id}
                else:
                    return {"success": False, "error": result["error"]}
            else:
                return {"success": False, "error": "Coordinator agent not available"}
                
        except Exception as e:
            self.logger.error(f"Failed to destroy honeypot manually: {e}")
            return {"success": False, "error": str(e)}
    
    async def perform_honeypot_action(self, honeypot_id: str, action: Dict[str, Any]) -> Dict[str, Any]:
        """Perform action on specific honeypot"""
        try:
            if honeypot_id not in self.honeypot_data:
                raise HTTPException(status_code=404, detail="Honeypot not found")
            
            action_type = action.get("action_type")
            
            if action_type == "restart":
                # Restart honeypot
                return await self._restart_honeypot(honeypot_id)
            elif action_type == "update_config":
                # Update honeypot configuration
                new_config = action.get("config", {})
                return await self._update_honeypot_config(honeypot_id, new_config)
            elif action_type == "isolate":
                # Isolate honeypot (emergency action)
                return await self._isolate_honeypot(honeypot_id)
            else:
                return {"success": False, "error": f"Unknown action type: {action_type}"}
                
        except Exception as e:
            self.logger.error(f"Failed to perform honeypot action: {e}")
            return {"success": False, "error": str(e)}
    
    async def emergency_shutdown(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Perform emergency shutdown of entire system"""
        try:
            reason = request.get("reason", "Emergency shutdown from dashboard")
            
            if self.coordinator_agent:
                result = self.coordinator_agent.emergency_shutdown_tool(
                    reason, "dashboard_manager"
                )
                
                if "error" not in result:
                    # Update dashboard status
                    self.status = DashboardStatus.MAINTENANCE
                    
                    # Broadcast emergency notification
                    await self.websocket_manager.broadcast(json.dumps({
                        "type": "emergency_shutdown",
                        "reason": reason,
                        "timestamp": datetime.utcnow().isoformat()
                    }))
                    
                    return {"success": True, "action": "emergency_shutdown_initiated"}
                else:
                    return {"success": False, "error": result["error"]}
            else:
                return {"success": False, "error": "Coordinator agent not available"}
                
        except Exception as e:
            self.logger.error(f"Failed to perform emergency shutdown: {e}")
            return {"success": False, "error": str(e)}
    
    # Background Monitoring Tasks
    async def _monitor_system_metrics(self):
        """Monitor system performance metrics"""
        while True:
            try:
                # Collect system metrics
                metrics = SystemMetrics(
                    timestamp=datetime.utcnow().isoformat(),
                    total_honeypots=len(self.honeypot_data),
                    active_engagements=len([h for h in self.honeypot_data.values() 
                                          if h.status == HoneypotDisplayStatus.ACTIVE]),
                    total_interactions=sum(h.interaction_count for h in self.honeypot_data.values()),
                    cpu_usage=await self._get_cpu_usage(),
                    memory_usage=await self._get_memory_usage(),
                    network_traffic=await self._get_network_traffic(),
                    agent_health=await self._get_agent_health(),
                    alert_count=len(self.active_alerts)
                )
                
                # Add to history
                self.system_metrics_history.append(metrics)
                
                # Keep only last 24 hours of data (assuming 5-minute intervals)
                if len(self.system_metrics_history) > 288:
                    self.system_metrics_history = self.system_metrics_history[-288:]
                
                await asyncio.sleep(300)  # Update every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error monitoring system metrics: {e}")
                await asyncio.sleep(300)
    
    async def _monitor_honeypot_status(self):
        """Monitor honeypot status changes"""
        while True:
            try:
                # Get status from coordinator agent
                if self.coordinator_agent:
                    status = await self.coordinator_agent.get_system_status_tool()
                    
                    # Update honeypot data based on coordinator status
                    if "honeypots" in status:
                        for honeypot_id, honeypot_info in status["honeypots"].items():
                            if honeypot_id in self.honeypot_data:
                                # Update existing honeypot
                                self.honeypot_data[honeypot_id].status = HoneypotDisplayStatus(
                                    honeypot_info.get("status", "inactive")
                                )
                                self.honeypot_data[honeypot_id].last_activity = honeypot_info.get("last_activity")
                                self.honeypot_data[honeypot_id].attacker_count = honeypot_info.get("attacker_count", 0)
                                self.honeypot_data[honeypot_id].interaction_count = honeypot_info.get("interaction_count", 0)
                            else:
                                # Add new honeypot
                                self.honeypot_data[honeypot_id] = HoneypotInfo(
                                    honeypot_id=honeypot_id,
                                    honeypot_type=honeypot_info.get("type", "unknown"),
                                    status=HoneypotDisplayStatus(honeypot_info.get("status", "inactive")),
                                    created_at=honeypot_info.get("created_at", datetime.utcnow().isoformat()),
                                    last_activity=honeypot_info.get("last_activity"),
                                    attacker_count=honeypot_info.get("attacker_count", 0),
                                    interaction_count=honeypot_info.get("interaction_count", 0),
                                    threat_level=honeypot_info.get("threat_level", "low"),
                                    config=honeypot_info.get("config", {})
                                )
                
                await asyncio.sleep(30)  # Update every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring honeypot status: {e}")
                await asyncio.sleep(30)
    
    async def _monitor_interactions(self):
        """Monitor attacker interactions in real-time"""
        while True:
            try:
                # Get real-time interactions from coordinator agent
                if self.coordinator_agent:
                    interactions_data = await self.coordinator_agent.get_recent_interactions_tool()
                    
                    for interaction_data in interactions_data.get("interactions", []):
                        # Create AttackerInteraction object
                        interaction = AttackerInteraction(
                            interaction_id=interaction_data.get("interaction_id", str(uuid4())),
                            honeypot_id=interaction_data.get("honeypot_id", ""),
                            honeypot_type=interaction_data.get("honeypot_type", "unknown"),
                            timestamp=interaction_data.get("timestamp", datetime.utcnow().isoformat()),
                            attacker_ip=interaction_data.get("attacker_ip", "unknown"),
                            command=interaction_data.get("command", ""),
                            response=interaction_data.get("response", ""),
                            threat_score=interaction_data.get("threat_score", 0.0),
                            mitre_techniques=interaction_data.get("mitre_techniques", [])
                        )
                        
                        # Add to recent interactions
                        self.recent_interactions.append(interaction)
                        
                        # Keep only last 1000 interactions
                        if len(self.recent_interactions) > 1000:
                            self.recent_interactions = self.recent_interactions[-1000:]
                        
                        # Check for high-priority interactions and create alerts
                        if interaction.threat_score > 0.8:
                            alert = {
                                "alert_id": str(uuid4()),
                                "title": f"High-Threat Interaction Detected",
                                "description": f"High-threat interaction (score: {interaction.threat_score:.2f}) detected on {interaction.honeypot_type} honeypot from {interaction.attacker_ip}",
                                "severity": "high" if interaction.threat_score > 0.9 else "medium",
                                "category": "security",
                                "timestamp": datetime.utcnow().isoformat(),
                                "source": "interaction_monitor",
                                "affected_components": [interaction.honeypot_id],
                                "recommended_actions": [
                                    "Review interaction details",
                                    "Check for lateral movement attempts",
                                    "Update threat intelligence feeds"
                                ],
                                "auto_resolution": False,
                                "escalation_level": 2 if interaction.threat_score > 0.9 else 1
                            }
                            
                            self.active_alerts.append(alert)
                            
                            # Broadcast high-priority alert
                            await self.websocket_manager.broadcast(json.dumps({
                                "type": "high_priority_alert",
                                "alert": alert,
                                "interaction": asdict(interaction)
                            }))
                
                await asyncio.sleep(10)  # Update every 10 seconds for real-time monitoring
                
            except Exception as e:
                self.logger.error(f"Error monitoring interactions: {e}")
                await asyncio.sleep(10)
    
    async def _broadcast_updates(self):
        """Broadcast real-time updates to connected WebSocket clients"""
        while True:
            try:
                if self.websocket_manager.active_connections:
                    # Get latest system metrics
                    latest_metrics = None
                    if self.system_metrics_history:
                        latest_metrics = asdict(self.system_metrics_history[-1])
                    
                    # Get AgentCore metrics
                    agentcore_metrics = await self._get_agentcore_metrics()
                    
                    # Prepare comprehensive update data
                    update_data = {
                        "type": "system_update",
                        "timestamp": datetime.utcnow().isoformat(),
                        "honeypots": {
                            "total": len(self.honeypot_data),
                            "active": len([h for h in self.honeypot_data.values() 
                                         if h.status == HoneypotDisplayStatus.ACTIVE]),
                            "creating": len([h for h in self.honeypot_data.values() 
                                           if h.status == HoneypotDisplayStatus.CREATING]),
                            "destroying": len([h for h in self.honeypot_data.values() 
                                             if h.status == HoneypotDisplayStatus.DESTROYING]),
                            "error": len([h for h in self.honeypot_data.values() 
                                        if h.status == HoneypotDisplayStatus.ERROR])
                        },
                        "alerts": {
                            "total": len(self.active_alerts),
                            "critical": len([a for a in self.active_alerts if a.get("severity") == "critical"]),
                            "high": len([a for a in self.active_alerts if a.get("severity") == "high"]),
                            "medium": len([a for a in self.active_alerts if a.get("severity") == "medium"])
                        },
                        "interactions": {
                            "recent_count": len(self.recent_interactions[-10:]),
                            "total_today": len([i for i in self.recent_interactions 
                                              if datetime.fromisoformat(i.timestamp.replace('Z', '+00:00')).date() == datetime.utcnow().date()]),
                            "high_threat_count": len([i for i in self.recent_interactions[-50:] if i.threat_score > 0.7])
                        },
                        "system_metrics": latest_metrics,
                        "agentcore_metrics": agentcore_metrics,
                        "websocket_connections": len(self.websocket_manager.active_connections)
                    }
                    
                    # Broadcast to all connected clients
                    await self.websocket_manager.broadcast(json.dumps(update_data))
                
                await asyncio.sleep(5)  # Broadcast every 5 seconds for real-time feel
                
            except Exception as e:
                self.logger.error(f"Error broadcasting updates: {e}")
                await asyncio.sleep(5)
    
    # Helper Methods
    async def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            import psutil
            return psutil.cpu_percent(interval=1)
        except ImportError:
            # Simulate CPU usage if psutil not available
            import random
            return random.uniform(10, 80)
    
    async def _get_memory_usage(self) -> float:
        """Get current memory usage percentage"""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except ImportError:
            # Simulate memory usage if psutil not available
            import random
            return random.uniform(30, 70)
    
    async def _get_network_traffic(self) -> float:
        """Get current network traffic (MB/s)"""
        try:
            import psutil
            net_io = psutil.net_io_counters()
            # This is a simplified calculation
            return (net_io.bytes_sent + net_io.bytes_recv) / (1024 * 1024)
        except ImportError:
            # Simulate network traffic if psutil not available
            import random
            return random.uniform(0.1, 10.0)
    
    async def _get_agent_health(self) -> Dict[str, str]:
        """Get health status of all agents"""
        try:
            if self.coordinator_agent:
                health_data = await self.coordinator_agent.get_system_health_tool()
                return health_data.get("agent_health", {})
            else:
                return {
                    "detection": "unknown",
                    "coordinator": "unknown", 
                    "interaction": "unknown",
                    "intelligence": "unknown"
                }
        except Exception as e:
            self.logger.error(f"Failed to get agent health: {e}")
            return {}
    
    async def _restart_honeypot(self, honeypot_id: str) -> Dict[str, Any]:
        """Restart a specific honeypot"""
        try:
            # Implementation would restart the honeypot
            self.logger.info(f"Restarting honeypot {honeypot_id}")
            return {"success": True, "action": "restart_initiated"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _update_honeypot_config(self, honeypot_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update honeypot configuration"""
        try:
            if honeypot_id in self.honeypot_data:
                self.honeypot_data[honeypot_id].config.update(config)
                return {"success": True, "action": "config_updated"}
            else:
                return {"success": False, "error": "Honeypot not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _isolate_honeypot(self, honeypot_id: str) -> Dict[str, Any]:
        """Isolate a honeypot (emergency action)"""
        try:
            # Implementation would isolate the honeypot from network
            self.logger.warning(f"Isolating honeypot {honeypot_id}")
            return {"success": True, "action": "isolation_initiated"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _get_agentcore_metrics(self) -> Dict[str, Any]:
        """Get AgentCore Runtime specific metrics"""
        try:
            if self.coordinator_agent:
                # Get AgentCore Runtime metrics from coordinator
                agentcore_data = await self.coordinator_agent.get_agentcore_metrics_tool()
                
                return {
                    "agent_instances": agentcore_data.get("agent_instances", {}),
                    "message_queue_depth": agentcore_data.get("message_queue_depth", 0),
                    "workflow_executions": agentcore_data.get("workflow_executions", 0),
                    "scaling_events": agentcore_data.get("scaling_events", []),
                    "runtime_health": agentcore_data.get("runtime_health", "unknown"),
                    "deployment_status": agentcore_data.get("deployment_status", {}),
                    "resource_utilization": agentcore_data.get("resource_utilization", {})
                }
            else:
                # Return mock data if coordinator not available
                return {
                    "agent_instances": {
                        "detection": {"count": 2, "status": "healthy"},
                        "coordinator": {"count": 1, "status": "healthy"},
                        "interaction": {"count": 3, "status": "healthy"},
                        "intelligence": {"count": 2, "status": "healthy"}
                    },
                    "message_queue_depth": 0,
                    "workflow_executions": 0,
                    "scaling_events": [],
                    "runtime_health": "healthy",
                    "deployment_status": {"last_deployment": "2024-01-01T00:00:00Z"},
                    "resource_utilization": {"cpu": 45.2, "memory": 62.1}
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get AgentCore metrics: {e}")
            return {}
    
    async def get_real_time_interactions(self) -> List[Dict[str, Any]]:
        """Get real-time attacker interactions for visualization"""
        try:
            # Get recent interactions with enhanced details for visualization
            interactions = []
            
            if self.coordinator_agent:
                # Get real-time interaction data from coordinator
                interaction_data = await self.coordinator_agent.get_real_time_interactions_tool()
                
                for interaction in interaction_data.get("interactions", []):
                    interactions.append({
                        "interaction_id": interaction.get("interaction_id"),
                        "honeypot_id": interaction.get("honeypot_id"),
                        "honeypot_type": interaction.get("honeypot_type"),
                        "timestamp": interaction.get("timestamp"),
                        "attacker_ip": interaction.get("attacker_ip"),
                        "command": interaction.get("command", ""),
                        "response": interaction.get("response", ""),
                        "threat_score": interaction.get("threat_score", 0.0),
                        "mitre_techniques": interaction.get("mitre_techniques", []),
                        "session_duration": interaction.get("session_duration", 0),
                        "geographic_location": interaction.get("geographic_location", {}),
                        "user_agent": interaction.get("user_agent", ""),
                        "attack_vector": interaction.get("attack_vector", ""),
                        "confidence_score": interaction.get("confidence_score", 0.0)
                    })
            
            return interactions[-50:]  # Return last 50 interactions
            
        except Exception as e:
            self.logger.error(f"Failed to get real-time interactions: {e}")
            return []
    
    async def get_honeypot_health_details(self) -> Dict[str, Any]:
        """Get detailed health information for all honeypots"""
        try:
            health_details = {}
            
            if self.coordinator_agent:
                # Get detailed health data from coordinator
                health_data = await self.coordinator_agent.get_honeypot_health_details_tool()
                
                for honeypot_id, health_info in health_data.get("honeypots", {}).items():
                    health_details[honeypot_id] = {
                        "status": health_info.get("status", "unknown"),
                        "uptime": health_info.get("uptime", 0),
                        "cpu_usage": health_info.get("cpu_usage", 0.0),
                        "memory_usage": health_info.get("memory_usage", 0.0),
                        "network_connections": health_info.get("network_connections", 0),
                        "error_count": health_info.get("error_count", 0),
                        "last_health_check": health_info.get("last_health_check", ""),
                        "performance_metrics": health_info.get("performance_metrics", {}),
                        "security_events": health_info.get("security_events", [])
                    }
            
            return health_details
            
        except Exception as e:
            self.logger.error(f"Failed to get honeypot health details: {e}")
            return {}
    
    async def get_system_alerts(self) -> List[Dict[str, Any]]:
        """Get system alerts with enhanced details"""
        try:
            alerts = []
            
            if self.coordinator_agent:
                # Get system alerts from coordinator
                alert_data = await self.coordinator_agent.get_system_alerts_tool()
                
                for alert in alert_data.get("alerts", []):
                    alerts.append({
                        "alert_id": alert.get("alert_id"),
                        "title": alert.get("title"),
                        "description": alert.get("description"),
                        "severity": alert.get("severity", "info"),
                        "category": alert.get("category", "system"),
                        "timestamp": alert.get("timestamp"),
                        "source": alert.get("source", "system"),
                        "affected_components": alert.get("affected_components", []),
                        "recommended_actions": alert.get("recommended_actions", []),
                        "auto_resolution": alert.get("auto_resolution", False),
                        "escalation_level": alert.get("escalation_level", 1)
                    })
            
            # Add any local dashboard alerts
            alerts.extend(self.active_alerts)
            
            return sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)
            
        except Exception as e:
            self.logger.error(f"Failed to get system alerts: {e}")
            return []
    
    async def perform_bulk_honeypot_action(self, honeypot_ids: List[str], action: str) -> Dict[str, Any]:
        """Perform bulk action on multiple honeypots"""
        try:
            results = {}
            
            for honeypot_id in honeypot_ids:
                if action == "restart":
                    result = await self._restart_honeypot(honeypot_id)
                elif action == "destroy":
                    result = await self.destroy_honeypot_manual(honeypot_id)
                elif action == "isolate":
                    result = await self._isolate_honeypot(honeypot_id)
                else:
                    result = {"success": False, "error": f"Unknown action: {action}"}
                
                results[honeypot_id] = result
            
            success_count = sum(1 for r in results.values() if r.get("success", False))
            
            return {
                "success": True,
                "total_processed": len(honeypot_ids),
                "successful": success_count,
                "failed": len(honeypot_ids) - success_count,
                "results": results
            }
            
        except Exception as e:
            self.logger.error(f"Failed to perform bulk honeypot action: {e}")
            return {"success": False, "error": str(e)}