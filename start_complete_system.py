#!/usr/bin/env python3
"""
Complete AI-Powered Honeypot System Startup Script
Starts AgentCore with dashboard integration and attack simulation
"""

import asyncio
import logging
import signal
import sys
import os
from datetime import datetime
from typing import Dict, Any

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from integration.system_integration_manager import SystemIntegrationManager
from integration.dashboard_integration import DashboardIntegration
from management.dashboard import DashboardManager
from deployment.mock_agentcore.main_enhanced import app as agentcore_app
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CompleteSystemManager:
    """Manages the complete AI-Powered Honeypot System"""
    
    def __init__(self):
        self.integration_manager = None
        self.dashboard_manager = None
        self.dashboard_integration = None
        self.agentcore_server = None
        self.running = False
        
    async def start_system(self):
        """Start the complete system"""
        logger.info("🚀 Starting AI-Powered Honeypot System...")
        
        try:
            # 1. Start Dashboard Manager
            await self._start_dashboard_manager()
            
            # 2. Start Dashboard Integration
            await self._start_dashboard_integration()
            
            # 3. Start System Integration Manager
            await self._start_system_integration()
            
            # 4. Start AgentCore Runtime
            await self._start_agentcore_runtime()
            
            # 5. Connect all components
            await self._connect_components()
            
            self.running = True
            logger.info("✅ Complete system started successfully!")
            logger.info("📊 Dashboard: http://localhost:8080")
            logger.info("🤖 AgentCore API: http://localhost:8000")
            logger.info("🎯 Attack Simulator: Ready for attacks")
            
        except Exception as e:
            logger.error(f"❌ Failed to start system: {e}")
            await self.shutdown_system()
            raise
    
    async def _start_dashboard_manager(self):
        """Start the dashboard manager"""
        logger.info("📊 Starting Dashboard Manager...")
        
        self.dashboard_manager = DashboardManager(
            host="0.0.0.0",
            port=8080,
            auth_required=False
        )
        
        await self.dashboard_manager.initialize()
        logger.info("✅ Dashboard Manager started")
    
    async def _start_dashboard_integration(self):
        """Start dashboard integration"""
        logger.info("🔗 Starting Dashboard Integration...")
        
        self.dashboard_integration = DashboardIntegration(self.dashboard_manager)
        logger.info("✅ Dashboard Integration started")
    
    async def _start_system_integration(self):
        """Start system integration manager"""
        logger.info("🔧 Starting System Integration Manager...")
        
        self.integration_manager = SystemIntegrationManager()
        await self.integration_manager.initialize()
        logger.info("✅ System Integration Manager started")
    
    async def _start_agentcore_runtime(self):
        """Start AgentCore runtime server"""
        logger.info("🤖 Starting AgentCore Runtime...")
        
        # Start AgentCore server in background
        config = uvicorn.Config(
            agentcore_app,
            host="0.0.0.0",
            port=8000,
            log_level="info"
        )
        
        self.agentcore_server = uvicorn.Server(config)
        
        # Start server in background task
        asyncio.create_task(self.agentcore_server.serve())
        
        # Wait a moment for server to start
        await asyncio.sleep(2)
        logger.info("✅ AgentCore Runtime started")
    
    async def _connect_components(self):
        """Connect all system components"""
        logger.info("🔗 Connecting system components...")
        
        # Connect agents to dashboard
        agents = {
            "coordinator": self.integration_manager.coordinator_agent,
            "detection": self.integration_manager.detection_agent,
            "interaction": self.integration_manager.interaction_agent,
            "intelligence": self.integration_manager.intelligence_agent
        }
        
        # Filter out None agents
        connected_agents = {k: v for k, v in agents.items() if v is not None}
        
        if connected_agents:
            await self.dashboard_integration.connect_agents(connected_agents)
            logger.info(f"✅ Connected {len(connected_agents)} agents to dashboard")
        else:
            logger.warning("⚠️  No agents available to connect to dashboard")
        
        # Start system health monitoring
        asyncio.create_task(self._monitor_system_health())
        
        logger.info("✅ All components connected")
    
    async def _monitor_system_health(self):
        """Monitor system health and update dashboard"""
        while self.running:
            try:
                # Get system health from integration manager
                health_data = await self.integration_manager.get_system_health()
                
                # Add additional metrics
                health_data.update({
                    "timestamp": datetime.utcnow().isoformat(),
                    "dashboard_clients": len(self.dashboard_integration.active_connections),
                    "active_agents": len(self.dashboard_integration.connected_agents)
                })
                
                # Update dashboard
                await self.dashboard_integration.update_system_health(health_data.__dict__)
                
                # Wait 10 seconds before next update
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(30)
    
    async def simulate_attack_detection(self, attack_data: Dict[str, Any]):
        """Simulate attack detection and honeypot creation"""
        try:
            logger.info(f"🎯 Processing attack: {attack_data['type']} from {attack_data['source_ip']}")
            
            # Simulate detection agent processing
            if self.integration_manager.detection_agent:
                detection_result = await self.integration_manager.detection_agent.process_attack(attack_data)
                
                # If attack detected with high confidence, create honeypot
                if detection_result.get("confidence", 0) > 0.8:
                    logger.info(f"🎭 Creating honeypot for attack: {attack_data['type']}")
                    
                    # Simulate honeypot creation
                    honeypot_data = {
                        "honeypot_id": f"hp_{int(datetime.utcnow().timestamp())}",
                        "type": self._determine_honeypot_type(attack_data["type"]),
                        "target_ip": attack_data["source_ip"],
                        "created_at": datetime.utcnow().isoformat()
                    }
                    
                    # Notify dashboard of new honeypot
                    await self.dashboard_integration._broadcast_to_clients("honeypot_created", {
                        "type": "honeypot_created",
                        "data": honeypot_data,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                    # Simulate engagement after delay
                    asyncio.create_task(self._simulate_honeypot_engagement(honeypot_data))
                    
                    return {"success": True, "honeypot_created": True, "honeypot_id": honeypot_data["honeypot_id"]}
                else:
                    logger.info(f"⚠️  Attack confidence too low: {detection_result.get('confidence', 0):.2f}")
                    return {"success": True, "honeypot_created": False, "reason": "low_confidence"}
            else:
                logger.warning("⚠️  Detection agent not available")
                return {"success": False, "error": "detection_agent_unavailable"}
                
        except Exception as e:
            logger.error(f"❌ Attack processing failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _determine_honeypot_type(self, attack_type: str) -> str:
        """Determine honeypot type based on attack"""
        type_mapping = {
            "SQL Injection": "web_admin",
            "XSS Attack": "web_server",
            "Brute Force": "ssh_server",
            "Directory Traversal": "file_server",
            "Command Injection": "web_admin"
        }
        return type_mapping.get(attack_type, "generic")
    
    async def _simulate_honeypot_engagement(self, honeypot_data: Dict[str, Any]):
        """Simulate honeypot engagement and eventual destruction"""
        try:
            # Wait for engagement to start
            engagement_delay = 5 + (hash(honeypot_data["honeypot_id"]) % 20)  # 5-25 seconds
            await asyncio.sleep(engagement_delay)
            
            # Simulate engagement
            engagement_duration = 30 + (hash(honeypot_data["honeypot_id"]) % 120)  # 30-150 seconds
            interactions = 5 + (hash(honeypot_data["honeypot_id"]) % 45)  # 5-50 interactions
            
            logger.info(f"👤 Attacker engaging with honeypot {honeypot_data['honeypot_id']}")
            
            # Notify dashboard of engagement
            await self.dashboard_integration._broadcast_to_clients("honeypot_engaged", {
                "type": "honeypot_engaged",
                "data": {
                    "honeypot_id": honeypot_data["honeypot_id"],
                    "duration": engagement_duration,
                    "interactions": interactions,
                    "status": "engaged"
                },
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Wait for engagement to complete
            await asyncio.sleep(engagement_duration)
            
            # Generate intelligence
            intelligence_data = {
                "report_id": f"intel_{int(datetime.utcnow().timestamp())}",
                "honeypot_id": honeypot_data["honeypot_id"],
                "iocs_extracted": 2 + (hash(honeypot_data["honeypot_id"]) % 6),  # 2-8 IOCs
                "mitre_techniques": ["T1190", "T1059"],
                "threat_level": "HIGH",
                "confidence": 0.85 + (hash(honeypot_data["honeypot_id"]) % 10) / 100  # 0.85-0.95
            }
            
            logger.info(f"🧠 Intelligence generated for honeypot {honeypot_data['honeypot_id']}")
            
            # Notify dashboard of intelligence
            await self.dashboard_integration._broadcast_to_clients("intelligence_generated", {
                "type": "intelligence_generated",
                "data": intelligence_data,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Wait a bit then destroy honeypot
            await asyncio.sleep(10)
            
            logger.info(f"🗑️  Destroying honeypot {honeypot_data['honeypot_id']}")
            
            # Notify dashboard of honeypot destruction
            await self.dashboard_integration._broadcast_to_clients("honeypot_destroyed", {
                "type": "honeypot_destroyed",
                "data": {
                    "honeypot_id": honeypot_data["honeypot_id"],
                    "final_stats": {
                        "duration": engagement_duration,
                        "interactions": interactions,
                        "intelligence_reports": 1
                    }
                },
                "timestamp": datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"❌ Honeypot engagement simulation failed: {e}")
    
    async def shutdown_system(self):
        """Shutdown the complete system"""
        logger.info("🛑 Shutting down AI-Powered Honeypot System...")
        
        self.running = False
        
        try:
            # Shutdown components in reverse order
            if self.dashboard_integration:
                await self.dashboard_integration.shutdown()
            
            if self.integration_manager:
                await self.integration_manager.shutdown()
            
            if self.agentcore_server:
                self.agentcore_server.should_exit = True
            
            if self.dashboard_manager:
                await self.dashboard_manager.shutdown()
            
            logger.info("✅ System shutdown completed")
            
        except Exception as e:
            logger.error(f"❌ Error during shutdown: {e}")

# Global system manager instance
system_manager = None

async def main():
    """Main function"""
    global system_manager
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        if system_manager:
            asyncio.create_task(system_manager.shutdown_system())
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Create and start system
        system_manager = CompleteSystemManager()
        await system_manager.start_system()
        
        # Keep running
        while system_manager.running:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"System error: {e}")
    finally:
        if system_manager:
            await system_manager.shutdown_system()

if __name__ == "__main__":
    asyncio.run(main())