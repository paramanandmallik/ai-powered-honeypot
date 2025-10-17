"""
Mock AgentCore Runtime Message Bus for Local Development
Simulates AgentCore's messaging system using Redis and RabbitMQ
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
import redis
import aio_pika
from aio_pika import Message, ExchangeType

logger = logging.getLogger(__name__)

class MockMessageBus:
    """Mock implementation of AgentCore Runtime message bus"""
    
    def __init__(self, redis_url: str, rabbitmq_url: str):
        self.redis_url = redis_url
        self.rabbitmq_url = rabbitmq_url
        self.redis_client = None
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None
        self.exchanges = {}
        self.queues = {}
        self.subscribers = {}
        self.message_handlers = {}
        
    async def initialize(self):
        """Initialize message bus connections"""
        try:
            # Initialize Redis for state management
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            await asyncio.get_event_loop().run_in_executor(None, self.redis_client.ping)
            
            # Initialize RabbitMQ for message passing
            self.rabbitmq_connection = await aio_pika.connect_robust(self.rabbitmq_url)
            self.rabbitmq_channel = await self.rabbitmq_connection.channel()
            
            # Create default exchanges
            await self._create_default_exchanges()
            
            logger.info("Mock AgentCore message bus initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize message bus: {e}")
            raise
    
    async def _create_default_exchanges(self):
        """Create default exchanges for agent communication"""
        exchange_configs = [
            ("agent.events", ExchangeType.TOPIC),
            ("agent.commands", ExchangeType.DIRECT),
            ("agent.responses", ExchangeType.DIRECT),
            ("system.notifications", ExchangeType.FANOUT),
            ("honeypot.lifecycle", ExchangeType.TOPIC),
            ("intelligence.reports", ExchangeType.TOPIC)
        ]
        
        for exchange_name, exchange_type in exchange_configs:
            exchange = await self.rabbitmq_channel.declare_exchange(
                exchange_name, exchange_type, durable=True
            )
            self.exchanges[exchange_name] = exchange
            logger.debug(f"Created exchange: {exchange_name}")
    
    async def publish_message(self, exchange_name: str, routing_key: str, 
                            message_data: Dict[str, Any], 
                            message_type: str = "event") -> str:
        """Publish a message to the specified exchange"""
        try:
            message_id = str(uuid.uuid4())
            
            # Prepare message with metadata
            full_message = {
                "message_id": message_id,
                "timestamp": datetime.utcnow().isoformat(),
                "message_type": message_type,
                "routing_key": routing_key,
                "data": message_data
            }
            
            # Get exchange
            exchange = self.exchanges.get(exchange_name)
            if not exchange:
                raise ValueError(f"Exchange {exchange_name} not found")
            
            # Publish message
            message = Message(
                json.dumps(full_message).encode(),
                message_id=message_id,
                timestamp=datetime.utcnow(),
                content_type="application/json"
            )
            
            await exchange.publish(message, routing_key=routing_key)
            
            # Store message in Redis for debugging
            await self._store_message_history(message_id, full_message)
            
            logger.debug(f"Published message {message_id} to {exchange_name}/{routing_key}")
            return message_id
            
        except Exception as e:
            logger.error(f"Failed to publish message: {e}")
            raise
    
    async def subscribe_to_messages(self, exchange_name: str, routing_key: str,
                                  handler: Callable, queue_name: Optional[str] = None) -> str:
        """Subscribe to messages from specified exchange and routing key"""
        try:
            if not queue_name:
                queue_name = f"queue.{exchange_name}.{routing_key}.{uuid.uuid4().hex[:8]}"
            
            # Get exchange
            exchange = self.exchanges.get(exchange_name)
            if not exchange:
                raise ValueError(f"Exchange {exchange_name} not found")
            
            # Declare queue
            queue = await self.rabbitmq_channel.declare_queue(
                queue_name, durable=True, auto_delete=False
            )
            
            # Bind queue to exchange
            await queue.bind(exchange, routing_key=routing_key)
            
            # Set up message handler
            async def message_handler(message: aio_pika.IncomingMessage):
                async with message.process():
                    try:
                        message_data = json.loads(message.body.decode())
                        await handler(message_data)
                        logger.debug(f"Processed message {message_data.get('message_id')}")
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
                        raise
            
            # Start consuming
            await queue.consume(message_handler)
            
            # Store subscription info
            subscription_id = str(uuid.uuid4())
            self.subscribers[subscription_id] = {
                "exchange": exchange_name,
                "routing_key": routing_key,
                "queue_name": queue_name,
                "handler": handler
            }
            
            logger.info(f"Subscribed to {exchange_name}/{routing_key} with queue {queue_name}")
            return subscription_id
            
        except Exception as e:
            logger.error(f"Failed to subscribe to messages: {e}")
            raise
    
    async def send_command(self, target_agent: str, command: str, 
                          parameters: Dict[str, Any]) -> str:
        """Send a command to a specific agent"""
        command_data = {
            "target_agent": target_agent,
            "command": command,
            "parameters": parameters,
            "sender": "mock-agentcore"
        }
        
        return await self.publish_message(
            "agent.commands", 
            target_agent, 
            command_data, 
            "command"
        )
    
    async def send_response(self, original_message_id: str, response_data: Dict[str, Any],
                          success: bool = True) -> str:
        """Send a response to a command or request"""
        response = {
            "original_message_id": original_message_id,
            "success": success,
            "response_data": response_data,
            "sender": "mock-agentcore"
        }
        
        return await self.publish_message(
            "agent.responses",
            original_message_id,
            response,
            "response"
        )
    
    async def broadcast_notification(self, notification_type: str, 
                                   notification_data: Dict[str, Any]) -> str:
        """Broadcast a system notification to all agents"""
        notification = {
            "notification_type": notification_type,
            "data": notification_data,
            "sender": "mock-agentcore"
        }
        
        return await self.publish_message(
            "system.notifications",
            "",
            notification,
            "notification"
        )
    
    async def get_agent_state(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get current state of an agent"""
        try:
            state_key = f"agent:state:{agent_id}"
            state_data = self.redis_client.get(state_key)
            
            if state_data:
                return json.loads(state_data)
            return None
            
        except Exception as e:
            logger.error(f"Failed to get agent state for {agent_id}: {e}")
            return None
    
    async def set_agent_state(self, agent_id: str, state_data: Dict[str, Any]) -> bool:
        """Set current state of an agent"""
        try:
            state_key = f"agent:state:{agent_id}"
            state_json = json.dumps(state_data)
            
            # Set state with expiration (24 hours)
            result = self.redis_client.setex(state_key, 86400, state_json)
            
            # Also update last seen timestamp
            last_seen_key = f"agent:last_seen:{agent_id}"
            self.redis_client.setex(last_seen_key, 86400, datetime.utcnow().isoformat())
            
            return bool(result)
            
        except Exception as e:
            logger.error(f"Failed to set agent state for {agent_id}: {e}")
            return False
    
    async def get_active_agents(self) -> List[str]:
        """Get list of currently active agents"""
        try:
            pattern = "agent:last_seen:*"
            keys = self.redis_client.keys(pattern)
            
            active_agents = []
            for key in keys:
                agent_id = key.replace("agent:last_seen:", "")
                last_seen_str = self.redis_client.get(key)
                
                if last_seen_str:
                    last_seen = datetime.fromisoformat(last_seen_str)
                    # Consider agent active if seen within last 5 minutes
                    if (datetime.utcnow() - last_seen).total_seconds() < 300:
                        active_agents.append(agent_id)
            
            return active_agents
            
        except Exception as e:
            logger.error(f"Failed to get active agents: {e}")
            return []
    
    async def _store_message_history(self, message_id: str, message_data: Dict[str, Any]):
        """Store message in Redis for debugging and history"""
        try:
            history_key = f"message:history:{message_id}"
            message_json = json.dumps(message_data)
            
            # Store message with 1 hour expiration
            self.redis_client.setex(history_key, 3600, message_json)
            
            # Add to recent messages list (keep last 1000)
            recent_key = "messages:recent"
            self.redis_client.lpush(recent_key, message_id)
            self.redis_client.ltrim(recent_key, 0, 999)
            
        except Exception as e:
            logger.error(f"Failed to store message history: {e}")
    
    async def get_message_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent message history for debugging"""
        try:
            recent_key = "messages:recent"
            message_ids = self.redis_client.lrange(recent_key, 0, limit - 1)
            
            messages = []
            for message_id in message_ids:
                history_key = f"message:history:{message_id}"
                message_data = self.redis_client.get(history_key)
                
                if message_data:
                    messages.append(json.loads(message_data))
            
            return messages
            
        except Exception as e:
            logger.error(f"Failed to get message history: {e}")
            return []
    
    async def cleanup(self):
        """Cleanup connections and resources"""
        try:
            if self.rabbitmq_connection:
                await self.rabbitmq_connection.close()
            
            if self.redis_client:
                self.redis_client.close()
                
            logger.info("Mock AgentCore message bus cleaned up")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

# Global message bus instance
message_bus = None

async def get_message_bus() -> MockMessageBus:
    """Get or create global message bus instance"""
    global message_bus
    
    if message_bus is None:
        import os
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        rabbitmq_url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
        
        message_bus = MockMessageBus(redis_url, rabbitmq_url)
        await message_bus.initialize()
    
    return message_bus