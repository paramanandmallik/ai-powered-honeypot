# Agent Development Guide

## Overview

This guide provides comprehensive instructions for developing AI agents within the honeypot system, including coding standards, testing practices, and deployment procedures.

## Agent Development Framework

### Base Agent Class

All agents inherit from the `BaseAgent` class which provides core functionality:

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import asyncio
import logging
from datetime import datetime

class BaseAgent(ABC):
    def __init__(self, agent_id: str, config: Dict[str, Any]):
        self.agent_id = agent_id
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__name__}_{agent_id}")
        self.state = {}
        self.metrics = AgentMetrics(agent_id)
        
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize agent resources and connections"""
        pass
        
    @abstractmethod
    async def handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process incoming messages from other agents"""
        pass
        
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up resources before shutdown"""
        pass
        
    async def health_check(self) -> Dict[str, Any]:
        """Return agent health status"""
        return {
            "status": "healthy",
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": await self.metrics.get_current_metrics()
        }
```

### Agent Implementation Pattern

#### Detection Agent Example

```python
class DetectionAgent(BaseAgent):
    def __init__(self, agent_id: str, config: Dict[str, Any]):
        super().__init__(agent_id, config)
        self.ai_analyzer = None
        self.threat_threshold = config.get("threat_threshold", 0.75)
        
    async def initialize(self) -> None:
        """Initialize AI models and threat analysis components"""
        self.ai_analyzer = await AIThreatAnalyzer.create(
            model_endpoint=self.config["ai_model_endpoint"],
            api_key=self.config["ai_api_key"]
        )
        
        # Initialize MITRE ATT&CK framework
        self.mitre_mapper = MitreAttackMapper()
        await self.mitre_mapper.load_framework()
        
        self.logger.info(f"Detection Agent {self.agent_id} initialized")
        
    async def handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process threat detection messages"""
        message_type = message.get("type")
        
        if message_type == "threat_feed_update":
            return await self.process_threat_feed(message["payload"])
        elif message_type == "manual_trigger":
            return await self.evaluate_manual_threat(message["payload"])
        else:
            self.logger.warning(f"Unknown message type: {message_type}")
            return None
```

## Development Standards

### Code Structure

```
agents/
├── __init__.py
├── base_agent.py
├── detection/
│   ├── __init__.py
│   ├── detection_agent.py
│   ├── ai_analyzer.py
│   └── mitre_mapper.py
├── coordinator/
│   ├── __init__.py
│   ├── coordinator_agent.py
│   ├── honeypot_manager.py
│   └── orchestration_engine.py
├── interaction/
│   ├── __init__.py
│   ├── interaction_agent.py
│   ├── synthetic_data_generator.py
│   └── security_controls.py
└── intelligence/
    ├── __init__.py
    ├── intelligence_agent.py
    ├── session_analyzer.py
    └── intelligence_reporter.py
```

### Coding Standards

#### Error Handling
```python
class AgentError(Exception):
    """Base exception for agent errors"""
    pass

class MessageProcessingError(AgentError):
    """Error processing agent messages"""
    pass

async def handle_message_safely(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        return await self.handle_message(message)
    except MessageProcessingError as e:
        self.logger.error(f"Message processing failed: {e}")
        await self.metrics.increment_error_count()
        return {"error": str(e), "retry": True}
    except Exception as e:
        self.logger.exception(f"Unexpected error: {e}")
        await self.metrics.increment_error_count()
        return {"error": "Internal error", "retry": False}
```##
## Logging Standards
```python
import logging
import json
from datetime import datetime

class StructuredLogger:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.logger = logging.getLogger(agent_id)
        
    def log_event(self, level: str, event_type: str, message: str, **kwargs):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": self.agent_id,
            "event_type": event_type,
            "message": message,
            "level": level,
            **kwargs
        }
        
        if level == "ERROR":
            self.logger.error(json.dumps(log_entry))
        elif level == "WARNING":
            self.logger.warning(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))

# Usage example
logger = StructuredLogger("detection-agent-001")
logger.log_event("INFO", "threat_detected", "High confidence threat detected", 
                 confidence=0.89, threat_type="ssh_brute_force")
```

#### Configuration Management
```python
from dataclasses import dataclass
from typing import Optional
import os

@dataclass
class AgentConfig:
    agent_id: str
    log_level: str = "INFO"
    ai_model_endpoint: Optional[str] = None
    threat_thres
hold: float = 0.75
    max_concurrent_sessions: int = 10
    
    @classmethod
    def from_env(cls, agent_id: str) -> 'AgentConfig':
        return cls(
            agent_id=agent_id,
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            ai_model_endpoint=os.getenv("AI_MODEL_ENDPOINT"),
            threat_threshold=float(os.getenv("THREAT_THRESHOLD", "0.75")),
            max_concurrent_sessions=int(os.getenv("MAX_CONCURRENT_SESSIONS", "10"))
        )
```

### Testing Framework

#### Unit Testing
```python
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from agents.detection.detection_agent import DetectionAgent

class TestDetectionAgent:
    @pytest.fixture
    async def detection_agent(self):
        config = {
            "ai_model_endpoint": "mock://ai-model",
            "threat_threshold": 0.75
        }
        agent = DetectionAgent("test-agent", config)
        agent.ai_analyzer = AsyncMock()
        await agent.initialize()
        return agent
        
    @pytest.mark.asyncio
    async def test_threat_detection_high_confidence(self, detection_agent):
        # Mock AI analyzer to return high confidence
        detection_agent.ai_analyzer.analyze.return_value = 0.89
        
        message = {
            "type": "threat_feed_update",
            "payload": {
                "source_ip": "192.168.1.100",
                "attack_type": "ssh_brute_force"
            }
        }
        
        result = await detection_agent.handle_message(message)
        
        assert result["engagement_decision"] is True
        assert result["confidence_score"] == 0.89
        
    @pytest.mark.asyncio
    async def test_threat_detection_low_confidence(self, detection_agent):
        # Mock AI analyzer to return low confidence
        detection_agent.ai_analyzer.analyze.return_value = 0.45
        
        message = {
            "type": "threat_feed_update",
            "payload": {
                "source_ip": "192.168.1.100",
                "attack_type": "port_scan"
            }
        }
        
        result = await detection_agent.handle_message(message)
        
        assert result["engagement_decision"] is False
        assert result["confidence_score"] == 0.45
```

#### Integration Testing
```python
import pytest
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.detection.detection_agent import DetectionAgent
from tests.utils.mock_agentcore import MockAgentCoreRuntime

class TestAgentIntegration:
    @pytest.fixture
    async def agent_runtime(self):
        runtime = MockAgentCoreRuntime()
        
        # Create and register agents
        detection_agent = DetectionAgent("detection-001", {})
        coordinator_agent = CoordinatorAgent("coordinator-001", {})
        
        await runtime.register_agent(detection_agent)
        await runtime.register_agent(coordinator_agent)
        
        return runtime
        
    @pytest.mark.asyncio
    async def test_threat_to_engagement_workflow(self, agent_runtime):
        # Simulate threat detection
        threat_message = {
            "type": "threat_detected",
            "payload": {
                "confidence_score": 0.89,
                "threat_type": "ssh_brute_force"
            }
        }
        
        # Send message through runtime
        await agent_runtime.send_message("detection-001", "coordinator-001", threat_message)
        
        # Verify engagement was created
        coordinator = agent_runtime.get_agent("coordinator-001")
        assert len(coordinator.active_engagements) == 1
```

### Performance Optimization

#### Async Programming Best Practices
```python
import asyncio
from typing import List, Dict, Any

class OptimizedAgent(BaseAgent):
    async def process_multiple_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process multiple messages concurrently"""
        
        # Create tasks for concurrent processing
        tasks = [self.handle_message(msg) for msg in messages]
        
        # Process with timeout and error handling
        results = []
        for task in asyncio.as_completed(tasks, timeout=30):
            try:
                result = await task
                results.append(result)
            except asyncio.TimeoutError:
                self.logger.warning("Message processing timeout")
                results.append({"error": "timeout"})
            except Exception as e:
                self.logger.error(f"Message processing error: {e}")
                results.append({"error": str(e)})
                
        return results
        
    async def batch_process_with_backpressure(self, message_queue: asyncio.Queue) -> None:
        """Process messages with backpressure control"""
        
        batch_size = 10
        semaphore = asyncio.Semaphore(5)  # Limit concurrent processing
        
        while True:
            batch = []
            
            # Collect batch of messages
            for _ in range(batch_size):
                try:
                    message = await asyncio.wait_for(message_queue.get(), timeout=1.0)
                    batch.append(message)
                except asyncio.TimeoutError:
                    break
                    
            if not batch:
                await asyncio.sleep(0.1)
                continue
                
            # Process batch with semaphore
            async with semaphore:
                await self.process_multiple_messages(batch)
```

#### Memory Management
```python
import gc
import psutil
from typing import Optional

class MemoryOptimizedAgent(BaseAgent):
    def __init__(self, agent_id: str, config: Dict[str, Any]):
        super().__init__(agent_id, config)
        self.memory_threshold = config.get("memory_threshold_mb", 512)
        self.cache = {}
        self.cache_max_size = config.get("cache_max_size", 1000)
        
    async def check_memory_usage(self) -> None:
        """Monitor and manage memory usage"""
        
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        if memory_mb > self.memory_threshold:
            self.logger.warning(f"High memory usage: {memory_mb:.1f}MB")
            
            # Clear cache if too large
            if len(self.cache) > self.cache_max_size:
                self.cache.clear()
                
            # Force garbage collection
            gc.collect()
            
            # Log memory after cleanup
            new_memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
            self.logger.info(f"Memory after cleanup: {new_memory_mb:.1f}MB")
```

### Deployment and Maintenance

#### Agent Packaging
```python
# setup.py for agent deployment
from setuptools import setup, find_packages

setup(
    name="honeypot-agents",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "asyncio",
        "aiohttp",
        "pydantic",
        "structlog",
        "prometheus-client",
        "agentcore-runtime-sdk"
    ],
    entry_points={
        "console_scripts": [
            "detection-agent=agents.detection.detection_agent:main",
            "coordinator-agent=agents.coordinator.coordinator_agent:main",
            "interaction-agent=agents.interaction.interaction_agent:main",
            "intelligence-agent=agents.intelligence.intelligence_agent:main"
        ]
    }
)
```

#### Health Monitoring
```python
from prometheus_client import Counter, Histogram, Gauge
import time

class AgentMetrics:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        
        # Prometheus metrics
        self.message_counter = Counter(
            "agent_messages_processed_total",
            "Total messages processed",
            ["agent_id", "message_type", "status"]
        )
        
        self.processing_time = Histogram(
            "agent_message_processing_seconds",
            "Time spent processing messages",
            ["agent_id", "message_type"]
        )
        
        self.active_sessions = Gauge(
            "agent_active_sessions",
            "Number of active sessions",
            ["agent_id"]
        )
        
    async def record_message_processed(self, message_type: str, status: str, duration: float):
        self.message_counter.labels(
            agent_id=self.agent_id,
            message_type=message_type,
            status=status
        ).inc()
        
        self.processing_time.labels(
            agent_id=self.agent_id,
            message_type=message_type
        ).observe(duration)
```

This development guide provides the foundation for building robust, scalable AI agents within the honeypot system architecture.