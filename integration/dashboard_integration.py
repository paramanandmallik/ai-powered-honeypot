#!/usr/bin/env python3
"""
Dashboard Integration Module

Provides integration between the management dashboard and all system components
including AgentCore Runtime agents, AWS services, and honeypot infrastructure.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import websockets
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

from management.dashboard import DashboardManager


@dataclass
class DashboardConnection:
    """Dashboard connection tracking"""
    connection_id: str
    client_ip: str
    connect_time: datetime
    last_activity: datetime
    subscriptions: List[str]


class DashboardIntegration:
    """
    Manages integration between management dashboard and system components
    """
    
    def __init__(self, dashboard_manager: DashboardManager):
        self.logger = logging.getLogger(__name__)
        self.dashboard_manager = dashboard_manager
        
        # Connected agents
        self.connected_agents = {}
        
        # Active dashboard connections
        self.active_connections: Dict[str, DashboardConnection] = {}
        
        # Real-time data streams
        self.data_streams = {
            "system_health": [],
            "active_sessions": [],
            "threat_events": [],
            "intelligence_reports": [],
            "agent_metrics": []
        }
        
        # Integration status
        self.integration_status = {
            "agents_connected": 0,
            "dashboard_clients": 0,
            "data_streams_active": 0,
            "last_update": datetime.utcnow()
        }
    
    async def connect_agents(self, agents: Dict[str, Any]):
        """Connect AI agents to dashboard for monitoring"""
        self.logger.info("Connecting agents to dashboard...")
        
        for agent_name, agent in agents.items():
            try:
                # Register agent with dashboard
                await self._register_agent(agent_name, agent)
                
                # Set up agent data streaming
                await self._setup_agent_streaming(agent_name, agent)
                
                # Set up agent control interface
                await self._setup_agent_controls(agent_name, agent)
                
                self.connected_agents[agent_name] = agent
                self.logger.info(f"Agent {agent_name} connected to dashboard")
                
            except Exception as e:
                self.logger.error(f"Failed to connect agent {agent_name}: {e}")
        
        self.integration_status["agents_connected"] = len(self.connected_agents)
        self.logger.info(f"Connected {len(self.connected_agents)} agents to dashboard")
    
    async def _register_agent(self, agent_name: str, agent: Any):
        """Register agent with dashboard"""
        agent_info = {
            "name": agent_name,
            "type": agent.__class__.__name__,
            "status": "connected",
            "last_heartbeat": datetime.utcnow().isoformat(),
            "capabilities": await agent.get_capabilities(),
            "metrics": await agent.get_metrics()
        }
        
        # Register with dashboard manager
        await self.dashboard_manager.register_agent(agent_name, agent_info)
    
    async def _setup_agent_streaming(self, agent_name: str, agent: Any):
        """Set up real-time data streaming from agent"""
        # Set up metrics streaming
        async def stream_metrics():
            while True:
                try:
                    metrics = await agent.get_metrics()
                    await self._broadcast_agent_metrics(agent_name, metrics)
                    await asyncio.sleep(10)  # Update every 10 seconds
                except Exception as e:
                    self.logger.error(f"Metrics streaming failed for {agent_name}: {e}")
                    await asyncio.sleep(30)
        
        # Set up event streaming
        async def stream_events():
            async for event in agent.get_event_stream():
                await self._broadcast_agent_event(agent_name, event)
        
        # Start streaming tasks
        asyncio.create_task(stream_metrics())
        asyncio.create_task(stream_events())
    
    async def _setup_agent_controls(self, agent_name: str, agent: Any):
        """Set up agent control interface through dashboard"""
        # Register control endpoints
        control_endpoints = {
            "start": agent.start,
            "stop": agent.stop,
            "restart": agent.restart,
            "get_status": agent.get_status,
            "update_config": agent.update_config
        }
        
        await self.dashboard_manager.register_agent_controls(agent_name, control_endpoints)
    
    async def _broadcast_agent_metrics(self, agent_name: str, metrics: Dict[str, Any]):
        """Broadcast agent metrics to dashboard clients"""
        message = {
            "type": "agent_metrics",
            "agent": agent_name,
            "timestamp": datetime.utcnow().isoformat(),
            "data": metrics
        }
        
        # Add to data stream
        self.data_streams["agent_metrics"].append(message)
        
        # Keep only last 100 entries
        if len(self.data_streams["agent_metrics"]) > 100:
            self.data_streams["agent_metrics"] = self.data_streams["agent_metrics"][-100:]
        
        # Broadcast to connected clients
        await self._broadcast_to_clients("agent_metrics", message)
    
    async def _broadcast_agent_event(self, agent_name: str, event: Dict[str, Any]):
        """Broadcast agent events to dashboard clients"""
        message = {
            "type": "agent_event",
            "agent": agent_name,
            "timestamp": datetime.utcnow().isoformat(),
            "data": event
        }
        
        # Determine appropriate stream based on event type
        if event.get("event_type") == "threat_detected":
            self.data_streams["threat_events"].append(message)
        elif event.get("event_type") == "session_started":
            self.data_streams["active_sessions"].append(message)
        elif event.get("event_type") == "intelligence_generated":
            self.data_streams["intelligence_reports"].append(message)
        
        # Broadcast to connected clients
        await self._broadcast_to_clients("agent_event", message)
    
    async def _broadcast_to_clients(self, message_type: str, message: Dict[str, Any]):
        """Broadcast message to all connected dashboard clients"""
        for connection_id, connection in self.active_connections.items():
            if message_type in connection.subscriptions:
                try:
                    await self.dashboard_manager.send_to_client(connection_id, message)
                except Exception as e:
                    self.logger.error(f"Failed to send message to client {connection_id}: {e}")
    
    async def handle_client_connection(self, client_id: str, client_ip: str):
        """Handle new dashboard client connection"""
        connection = DashboardConnection(
            connection_id=client_id,
            client_ip=client_ip,
            connect_time=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            subscriptions=["system_health", "agent_metrics", "agent_event"]
        )
        
        self.active_connections[client_id] = connection
        self.integration_status["dashboard_clients"] = len(self.active_connections)
        
        self.logger.info(f"Dashboard client {client_id} connected from {client_ip}")
        
        # Send initial data to client
        await self._send_initial_data(client_id)
    
    async def handle_client_disconnection(self, client_id: str):
        """Handle dashboard client disconnection"""
        if client_id in self.active_connections:
            connection = self.active_connections[client_id]
            del self.active_connections[client_id]
            
            self.integration_status["dashboard_clients"] = len(self.active_connections)
            
            self.logger.info(f"Dashboard client {client_id} disconnected")
    
    async def _send_initial_data(self, client_id: str):
        """Send initial data to newly connected client"""
        try:
            # Send system status
            system_status = await self._get_system_status()
            await self.dashboard_manager.send_to_client(client_id, {
                "type": "system_status",
                "data": system_status
            })
            
            # Send agent status
            agent_status = await self._get_agent_status()
            await self.dashboard_manager.send_to_client(client_id, {
                "type": "agent_status",
                "data": agent_status
            })
            
            # Send recent data streams
            for stream_name, stream_data in self.data_streams.items():
                if stream_data:
                    await self.dashboard_manager.send_to_client(client_id, {
                        "type": "historical_data",
                        "stream": stream_name,
                        "data": stream_data[-10:]  # Last 10 entries
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to send initial data to client {client_id}: {e}")
    
    async def _get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "agents_connected": len(self.connected_agents),
            "dashboard_clients": len(self.active_connections),
            "active_sessions": len([
                msg for msg in self.data_streams["active_sessions"]
                if (datetime.utcnow() - datetime.fromisoformat(msg["timestamp"])).total_seconds() < 3600
            ]),
            "recent_threats": len([
                msg for msg in self.data_streams["threat_events"]
                if (datetime.utcnow() - datetime.fromisoformat(msg["timestamp"])).total_seconds() < 3600
            ]),
            "integration_status": self.integration_status
        }
    
    async def _get_agent_status(self) -> Dict[str, Any]:
        """Get status of all connected agents"""
        agent_status = {}
        
        for agent_name, agent in self.connected_agents.items():
            try:
                status = await agent.get_status()
                metrics = await agent.get_metrics()
                
                agent_status[agent_name] = {
                    "status": status,
                    "metrics": metrics,
                    "last_update": datetime.utcnow().isoformat()
                }
            except Exception as e:
                agent_status[agent_name] = {
                    "status": "error",
                    "error": str(e),
                    "last_update": datetime.utcnow().isoformat()
                }
        
        return agent_status
    
    async def handle_client_command(self, client_id: str, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle command from dashboard client"""
        try:
            command_type = command.get("type")
            
            if command_type == "agent_control":
                return await self._handle_agent_control(command)
            elif command_type == "system_control":
                return await self._handle_system_control(command)
            elif command_type == "subscription_update":
                return await self._handle_subscription_update(client_id, command)
            elif command_type == "data_request":
                return await self._handle_data_request(command)
            else:
                return {"success": False, "error": f"Unknown command type: {command_type}"}
        
        except Exception as e:
            self.logger.error(f"Failed to handle client command: {e}")
            return {"success": False, "error": str(e)}
    
    async def _handle_agent_control(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle agent control command"""
        agent_name = command.get("agent")
        action = command.get("action")
        params = command.get("params", {})
        
        if agent_name not in self.connected_agents:
            return {"success": False, "error": f"Agent {agent_name} not connected"}
        
        agent = self.connected_agents[agent_name]
        
        try:
            if action == "start":
                result = await agent.start()
            elif action == "stop":
                result = await agent.stop()
            elif action == "restart":
                result = await agent.restart()
            elif action == "get_status":
                result = await agent.get_status()
            elif action == "update_config":
                result = await agent.update_config(params.get("config", {}))
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
            
            return {"success": True, "result": result}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _handle_system_control(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle system control command"""
        action = command.get("action")
        
        try:
            if action == "emergency_shutdown":
                # Trigger emergency shutdown through dashboard manager
                result = await self.dashboard_manager.emergency_shutdown()
                return {"success": True, "result": result}
            elif action == "get_system_status":
                result = await self._get_system_status()
                return {"success": True, "result": result}
            else:
                return {"success": False, "error": f"Unknown system action: {action}"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _handle_subscription_update(self, client_id: str, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle client subscription update"""
        if client_id not in self.active_connections:
            return {"success": False, "error": "Client not connected"}
        
        subscriptions = command.get("subscriptions", [])
        self.active_connections[client_id].subscriptions = subscriptions
        
        return {"success": True, "subscriptions": subscriptions}
    
    async def _handle_data_request(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle data request from client"""
        data_type = command.get("data_type")
        params = command.get("params", {})
        
        try:
            if data_type == "historical_metrics":
                agent_name = params.get("agent")
                hours = params.get("hours", 24)
                
                # Filter metrics for specific agent and time range
                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                metrics = [
                    msg for msg in self.data_streams["agent_metrics"]
                    if msg["agent"] == agent_name and 
                    datetime.fromisoformat(msg["timestamp"]) > cutoff_time
                ]
                
                return {"success": True, "data": metrics}
            
            elif data_type == "session_details":
                session_id = params.get("session_id")
                
                # Find session details in data streams
                session_data = None
                for msg in self.data_streams["active_sessions"]:
                    if msg["data"].get("session_id") == session_id:
                        session_data = msg
                        break
                
                if session_data:
                    return {"success": True, "data": session_data}
                else:
                    return {"success": False, "error": "Session not found"}
            
            else:
                return {"success": False, "error": f"Unknown data type: {data_type}"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def update_system_health(self, health_data: Dict[str, Any]):
        """Update system health data and broadcast to clients"""
        message = {
            "type": "system_health",
            "timestamp": datetime.utcnow().isoformat(),
            "data": health_data
        }
        
        # Add to data stream
        self.data_streams["system_health"].append(message)
        
        # Keep only last 100 entries
        if len(self.data_streams["system_health"]) > 100:
            self.data_streams["system_health"] = self.data_streams["system_health"][-100:]
        
        # Broadcast to connected clients
        await self._broadcast_to_clients("system_health", message)
    
    async def get_integration_status(self) -> Dict[str, Any]:
        """Get dashboard integration status"""
        return {
            "integration_status": self.integration_status,
            "connected_agents": list(self.connected_agents.keys()),
            "active_connections": len(self.active_connections),
            "data_streams": {
                stream_name: len(stream_data)
                for stream_name, stream_data in self.data_streams.items()
            }
        }
    
    async def cleanup_old_data(self):
        """Clean up old data from streams"""
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        for stream_name, stream_data in self.data_streams.items():
            # Remove entries older than 24 hours
            self.data_streams[stream_name] = [
                msg for msg in stream_data
                if datetime.fromisoformat(msg["timestamp"]) > cutoff_time
            ]
        
        self.logger.info("Cleaned up old data from streams")
    
    async def shutdown(self):
        """Shutdown dashboard integration"""
        self.logger.info("Shutting down dashboard integration...")
        
        # Disconnect all clients
        for client_id in list(self.active_connections.keys()):
            await self.handle_client_disconnection(client_id)
        
        # Clear data streams
        for stream_name in self.data_streams:
            self.data_streams[stream_name].clear()
        
        # Clear connected agents
        self.connected_agents.clear()
        
        self.logger.info("Dashboard integration shutdown completed")


# Example usage and testing
if __name__ == "__main__":
    async def test_dashboard_integration():
        from management.dashboard import DashboardManager
        
        # Create dashboard manager
        dashboard_manager = DashboardManager(host="localhost", port=8080)
        await dashboard_manager.initialize()
        
        # Create dashboard integration
        dashboard_integration = DashboardIntegration(dashboard_manager)
        
        # Simulate agent connections
        mock_agents = {
            "coordinator": type('MockAgent', (), {
                'get_capabilities': lambda: {"type": "coordinator"},
                'get_metrics': lambda: {"cpu": 50, "memory": 60},
                'get_status': lambda: {"status": "running"},
                'get_event_stream': lambda: iter([])
            })(),
            "detection": type('MockAgent', (), {
                'get_capabilities': lambda: {"type": "detection"},
                'get_metrics': lambda: {"cpu": 30, "memory": 40},
                'get_status': lambda: {"status": "running"},
                'get_event_stream': lambda: iter([])
            })()
        }
        
        # Connect agents
        await dashboard_integration.connect_agents(mock_agents)
        
        # Simulate client connection
        await dashboard_integration.handle_client_connection("client1", "127.0.0.1")
        
        # Get status
        status = await dashboard_integration.get_integration_status()
        print(f"Integration status: {status}")
        
        # Cleanup
        await dashboard_integration.shutdown()
    
    asyncio.run(test_dashboard_integration())