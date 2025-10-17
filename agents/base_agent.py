"""
Base Agent Class for AgentCore Runtime Integration
Provides common functionality for all AI agents in the honeypot system using Strands Agents framework.
"""

import asyncio
import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Union
from uuid import uuid4

from strands import Agent, tool
from strands.models import BedrockModel
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Metrics
MESSAGES_PROCESSED = Counter('agent_messages_processed_total', 'Total messages processed', ['agent_type', 'message_type'])
MESSAGE_PROCESSING_TIME = Histogram('agent_message_processing_seconds', 'Time spent processing messages', ['agent_type', 'message_type'])
AGENT_HEALTH = Gauge('agent_health_status', 'Agent health status (1=healthy, 0=unhealthy)', ['agent_id'])
ACTIVE_SESSIONS = Gauge('agent_active_sessions', 'Number of active sessions', ['agent_id'])

class BaseAgent(ABC):
    """Base class for all AgentCore Runtime agents using Strands framework"""
    
    def __init__(self, agent_type: str, capabilities: List[str], config: Optional[Dict[str, Any]] = None):
        self.agent_type = agent_type
        self.agent_id = f"{agent_type}-{str(uuid4())[:8]}"
        self.agent_name = f"AI Honeypot {agent_type.title()} Agent"
        self.capabilities = capabilities
        self.config = config or {}
        
        # Initialize logging
        self.logger = logging.getLogger(f"{agent_type}_agent")
        self.logger.setLevel(logging.INFO)
        
        # Initialize AI processing system
        # For AgentCore Runtime, we'll use a mock AI system for local testing
        # In production, this would be handled by AgentCore's built-in AI capabilities
        self.system_prompt = self._create_system_prompt()
        self.use_mock_ai = os.getenv("USE_MOCK_AI", "true").lower() == "true"
        
        # Initialize Strands Agent only if Bedrock credentials are available
        self.strands_agent = None
        if not self.use_mock_ai:
            try:
                model_id = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
                self.strands_agent = Agent(
                    model=BedrockModel(model_id=model_id),
                    system_prompt=self.system_prompt,
                    agent_id=self.agent_id,
                    name=self.agent_name,
                    description=f"AI-powered {agent_type} agent for honeypot system",
                    tools=self._get_agent_tools()
                )
                self.logger.info("Initialized with Bedrock model")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Bedrock model, falling back to mock AI: {e}")
                self.use_mock_ai = True
        
        # Agent state
        self.state: Dict[str, Any] = {
            "status": "initializing",
            "last_activity": datetime.utcnow().isoformat(),
            "processed_messages": 0,
            "active_sessions": 0,
            "health_status": "healthy"
        }
        
        # Performance tracking
        self.start_time = datetime.utcnow()
        self.message_count = 0
        self.error_count = 0
        
        self.logger.info(f"Initialized {self.agent_name} ({self.agent_id})")
    
    def _create_system_prompt(self) -> str:
        """Create system prompt for the agent"""
        return f"""You are {self.agent_name}, an AI-powered agent in a honeypot security system.

Your role: {self.agent_type} agent
Capabilities: {', '.join(self.capabilities)}

You are designed to:
1. Process security-related data and make intelligent decisions
2. Communicate with other agents in the system
3. Maintain situational awareness and context
4. Respond to threats and anomalies appropriately
5. Generate actionable intelligence and insights

Always respond in a structured, professional manner and use the available tools to accomplish your tasks.
When processing security data, prioritize accuracy and provide confidence scores for your assessments.
"""

    def _get_agent_tools(self) -> List[Callable]:
        """Get the tools available to this agent"""
        return [
            self.health_check_tool,
            self.get_status_tool,
            self.update_config_tool,
            self.log_activity_tool,
            self.send_alert_tool
        ]
    
    async def start(self):
        """Start the agent"""
        try:
            # Start metrics server only if not disabled
            if not self.config.get("disable_metrics", False):
                metrics_port = self.config.get("metrics_port", int(os.getenv(f"{self.agent_type.upper()}_METRICS_PORT", "9000")))
                start_http_server(metrics_port)
                self.logger.info(f"Metrics server started on port {metrics_port}")
            else:
                self.logger.info("Metrics server disabled for testing")
            
            # Update state
            self.state["status"] = "running"
            self.state["started_at"] = datetime.utcnow().isoformat()
            
            # Set health metric only if metrics are enabled
            if not self.config.get("disable_metrics", False):
                AGENT_HEALTH.labels(agent_id=self.agent_id).set(1)
            
            # Call agent-specific initialization
            await self.initialize()
            
            self.logger.info(f"{self.agent_name} started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start agent: {e}")
            self.state["status"] = "error"
            self.state["error"] = str(e)
            raise
    
    async def stop(self):
        """Stop the agent"""
        try:
            self.state["status"] = "stopping"
            
            # Call agent-specific cleanup
            await self.cleanup()
            
            # Update metrics
            AGENT_HEALTH.labels(agent_id=self.agent_id).set(0)
            
            self.logger.info(f"{self.agent_name} stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping agent: {e}")
    
    async def process_with_ai(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Process a prompt using AI (Strands agent or mock AI for testing)"""
        try:
            # Add context to the prompt if provided
            if context:
                context_str = json.dumps(context, indent=2)
                full_prompt = f"{prompt}\n\nContext:\n{context_str}"
            else:
                full_prompt = prompt
            
            # Process with appropriate AI system
            if self.use_mock_ai or self.strands_agent is None:
                result = await self._process_with_mock_ai(full_prompt)
            else:
                result = self.strands_agent(full_prompt)
            
            # Update metrics
            MESSAGES_PROCESSED.labels(
                agent_type=self.agent_type,
                message_type="ai_processing"
            ).inc()
            
            return str(result)
            
        except Exception as e:
            self.logger.error(f"Failed to process with AI: {e}")
            self.error_count += 1
            raise
    
    async def analyze_data(self, data: Dict[str, Any], analysis_type: str) -> Dict[str, Any]:
        """Analyze data using AI capabilities"""
        try:
            prompt = f"""Analyze the following {analysis_type} data and provide insights:

Data: {json.dumps(data, indent=2)}

Please provide:
1. Key findings
2. Risk assessment (Low/Medium/High)
3. Confidence score (0-100)
4. Recommended actions
5. Any anomalies or patterns detected

Format your response as JSON with these fields: findings, risk_level, confidence_score, recommendations, anomalies."""

            result_str = await self.process_with_ai(prompt)
            
            # Try to parse as JSON, fallback to structured text
            try:
                result = json.loads(result_str)
            except json.JSONDecodeError:
                result = {
                    "findings": result_str,
                    "risk_level": "Medium",
                    "confidence_score": 50,
                    "recommendations": ["Review analysis manually"],
                    "anomalies": []
                }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to analyze data: {e}")
            self.error_count += 1
            raise
    
    def _update_state(self):
        """Update agent state"""
        self.state["last_activity"] = datetime.utcnow().isoformat()
        self.state["processed_messages"] = self.message_count
        self.state["error_count"] = self.error_count
        self.state["uptime_seconds"] = (datetime.utcnow() - self.start_time).total_seconds()
        
        # In AgentCore Runtime, state management is handled by the platform
        # No need for external state management
    
    # Strands tools for agent functionality
    @tool
    def health_check_tool(self) -> Dict[str, Any]:
        """Get agent health status"""
        health_data = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "status": self.state["status"],
            "health": "healthy" if self.error_count < 10 else "degraded",
            "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "processed_messages": self.message_count,
            "error_count": self.error_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        return health_data
    
    @tool
    def get_status_tool(self) -> Dict[str, Any]:
        """Get agent status and configuration"""
        status_data = {
            **self.state,
            "capabilities": self.capabilities,
            "config": self.config
        }
        return status_data
    
    @tool
    def update_config_tool(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update agent configuration"""
        self.config.update(new_config)
        self.logger.info("Configuration updated via tool")
        
        return {
            "agent_id": self.agent_id,
            "config": self.config,
            "updated_at": datetime.utcnow().isoformat()
        }
    
    @tool
    def log_activity_tool(self, activity: str, details: Optional[Dict[str, Any]] = None) -> str:
        """Log agent activity"""
        log_data = {
            "agent_id": self.agent_id,
            "activity": activity,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if details:
            log_data.update(details)
        
        self.logger.info(f"Activity: {activity}", extra=log_data)
        return f"Activity logged: {activity}"
    
    @tool
    def send_alert_tool(self, alert_type: str, alert_message: str, severity: str = "medium") -> Dict[str, Any]:
        """Send an alert notification"""
        alert_data = {
            "alert_id": str(uuid4()),
            "agent_id": self.agent_id,
            "alert_type": alert_type,
            "alert_message": alert_message,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.logger.warning(f"Alert: {alert_type} - {alert_message}")
        
        # In a real implementation, this would send to an alerting system
        return alert_data
    
    # Abstract methods that must be implemented by subclasses
    @abstractmethod
    async def initialize(self):
        """Agent-specific initialization logic"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Agent-specific cleanup logic"""
        pass
    
    @abstractmethod
    async def process_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process agent-specific messages"""
        pass
    
    # Optional methods that can be overridden
    async def on_config_update(self, new_config: Dict[str, Any]):
        """Handle configuration updates (optional override)"""
        pass
    
    async def _process_with_mock_ai(self, prompt: str) -> str:
        """Mock AI processing for testing without Bedrock credentials"""
        # Simple rule-based responses for testing
        prompt_lower = prompt.lower()
        
        # Generate appropriate responses based on agent type and prompt content
        if "greeting" in prompt_lower or "welcome" in prompt_lower:
            if self.agent_type == "interaction":
                return "Welcome to the system. Please enter your credentials."
            else:
                return "System initialized and ready."
        
        elif "ssh" in prompt_lower and "banner" in prompt_lower:
            return "SSH-2.0-OpenSSH_8.0\nLast login: Mon Dec 16 10:30:15 2024 from 192.168.1.100"
        
        elif "admin" in prompt_lower and "portal" in prompt_lower:
            return "Welcome to Admin Portal v2.1\nPlease authenticate to continue."
        
        elif "database" in prompt_lower and "connection" in prompt_lower:
            return "MySQL Server 8.0.35\nConnection established successfully."
        
        elif "analyze" in prompt_lower or "assessment" in prompt_lower:
            return json.dumps({
                "findings": "Mock analysis completed",
                "risk_level": "Medium",
                "confidence_score": 75,
                "recommendations": ["Continue monitoring", "Review logs"],
                "anomalies": ["Unusual login pattern detected"]
            })
        
        elif "credentials" in prompt_lower or "password" in prompt_lower:
            return "Username: admin\nPassword: synthetic_password_123"
        
        elif "command" in prompt_lower or "execute" in prompt_lower:
            return "Command executed successfully.\nOutput: Mock command response"
        
        else:
            # Generic response based on agent type
            if self.agent_type == "detection":
                return "Threat analysis complete. No immediate threats detected."
            elif self.agent_type == "interaction":
                return "I understand. Let me help you with that request."
            elif self.agent_type == "coordinator":
                return "Coordination task acknowledged. Processing request."
            elif self.agent_type == "intelligence":
                return "Intelligence analysis in progress. Results will be available shortly."
            else:
                return "Request processed successfully."
    
    def is_using_agentcore_runtime(self) -> bool:
        """Check if running in AgentCore Runtime environment"""
        return not self.use_mock_ai
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get agent-specific metrics (optional override)"""
        return {
            "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "processed_messages": self.message_count,
            "error_count": self.error_count,
            "active_sessions": self.state.get("active_sessions", 0)
        }
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get agent health status (optional override)"""
        return {
            "status": "healthy" if self.error_count < 10 else "degraded",
            "last_activity": self.state["last_activity"],
            "error_rate": self.error_count / max(self.message_count, 1)
        }
    
    # Utility methods
    def log_activity(self, activity: str, details: Optional[Dict[str, Any]] = None):
        """Log agent activity"""
        log_data = {
            "agent_id": self.agent_id,
            "activity": activity,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if details:
            log_data.update(details)
        
        self.logger.info(f"Activity: {activity}", extra=log_data)
    
    def increment_message_count(self, message_type: str):
        """Increment message processing metrics"""
        self.message_count += 1
        MESSAGES_PROCESSED.labels(
            agent_type=self.agent_type,
            message_type=message_type
        ).inc()
        self._update_state()
    
    def record_processing_time(self, message_type: str, processing_time: float):
        """Record message processing time"""
        MESSAGE_PROCESSING_TIME.labels(
            agent_type=self.agent_type,
            message_type=message_type
        ).observe(processing_time)
    
    def update_active_sessions(self, count: int):
        """Update active sessions count"""
        self.state["active_sessions"] = count
        ACTIVE_SESSIONS.labels(agent_id=self.agent_id).set(count)
        self._update_state()
    
    # AgentCore Runtime integration methods
    def create_agentcore_app(self):
        """Create AgentCore Runtime application for deployment"""
        try:
            from bedrock_agentcore.runtime import BedrockAgentCoreApp
            
            app = BedrockAgentCoreApp()
            
            @app.entrypoint
            def invoke(payload):
                """Process user input and return a response"""
                user_message = payload.get("prompt", "No prompt provided")
                
                # Process with Strands agent
                if self.strands_agent:
                    result = self.strands_agent(user_message)
                else:
                    # Fallback to mock processing
                    import asyncio
                    result = asyncio.run(self._process_with_mock_ai(user_message))
                
                # Update metrics
                self.increment_message_count("agentcore_invocation")
                
                return {
                    "agent_id": self.agent_id,
                    "agent_type": self.agent_type,
                    "result": str(result),
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            @app.health_check
            def health():
                """Health check endpoint for AgentCore Runtime"""
                health_data = self.health_check_tool()
                return {
                    "status": "healthy" if health_data.get("health") == "healthy" else "unhealthy",
                    "details": health_data
                }
            
            return app
            
        except ImportError:
            # Fallback for environments without AgentCore Runtime
            self.logger.warning("AgentCore Runtime not available, creating mock app")
            return self._create_mock_agentcore_app()
    
    def _create_mock_agentcore_app(self):
        """Create mock AgentCore app for testing"""
        try:
            from fastapi import FastAPI
            
            app = FastAPI(title=f"{self.agent_name} Mock App")
            
            @app.post("/invoke")
            async def invoke(payload: dict):
                """Mock invoke endpoint"""
                user_message = payload.get("prompt", "No prompt provided")
                result = await self._process_with_mock_ai(user_message)
                
                self.increment_message_count("mock_invocation")
                
                return {
                    "agent_id": self.agent_id,
                    "agent_type": self.agent_type,
                    "result": str(result),
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            @app.get("/health")
            async def health():
                """Mock health check endpoint"""
                health_data = self.health_check_tool()
                return {
                    "status": "healthy" if health_data.get("health") == "healthy" else "unhealthy",
                    "details": health_data
                }
            
            return app
            
        except ImportError:
            self.logger.error("Neither AgentCore Runtime nor FastAPI available")
            return None