# Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting procedures for common issues in the AI-Powered Honeypot System, including diagnostic tools, resolution steps, and preventive measures.

## System Health Diagnostics

### Quick Health Check

```bash
# Run comprehensive system health check
python scripts/system_health_check.py

# Check individual agent status
python scripts/check_agent_status.py --agent detection-agent
python scripts/check_agent_status.py --agent coordinator-agent
python scripts/check_agent_status.py --agent interaction-agent
python scripts/check_agent_status.py --agent intelligence-agent

# Verify AgentCore Runtime connectivity
python scripts/verify_agentcore_connection.py
```

### Diagnostic Tools

#### System Health Monitor
```python
# scripts/system_health_check.py
import asyncio
import json
from datetime import datetime
from agentcore_runtime import AgentCoreClient

class SystemHealthChecker:
    def __init__(self):
        self.client = AgentCoreClient()
        self.agents = ["detection-agent", "coordinator-agent", "interaction-agent", "intelligence-agent"]
    
    async def run_comprehensive_check(self):
        """Run complete system health diagnostics"""
        
        print("🔍 Starting comprehensive system health check...")
        
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": "unknown",
            "agents": {},
            "infrastructure": {},
            "connectivity": {},
            "performance": {}
        }
        
        # Check agent health
        agent_issues = await self.check_agent_health(results)
        
        # Check infrastructure
        infra_issues = await self.check_infrastructure(results)
        
        # Check connectivity
        conn_issues = await self.check_connectivity(results)
        
        # Check performance
        perf_issues = await self.check_performance(results)
        
        # Determine overall status
        total_issues = agent_issues + infra_issues + conn_issues + perf_issues
        
        if total_issues == 0:
            results["overall_status"] = "healthy"
            print("✅ System is healthy")
        elif total_issues <= 2:
            results["overall_status"] = "degraded"
            print("⚠️  System is degraded")
        else:
            results["overall_status"] = "unhealthy"
            print("❌ System is unhealthy")
        
        # Generate report
        self.generate_health_report(results)
        
        return results
    
    async def check_agent_health(self, results):
        """Check health of all agents"""
        
        print("Checking agent health...")
        issues = 0
        
        for agent_name in self.agents:
            try:
                # Get agent status
                status = await self.client.get_agent_status(agent_name)
                
                # Get agent health
                health = await self.client.check_agent_health(agent_name)
                
                # Get agent metrics
                metrics = await self.client.get_agent_metrics(agent_name)
                
                agent_result = {
                    "status": status.state,
                    "health": health.status,
                    "instance_count": status.instance_count,
                    "error_rate": metrics.error_rate,
                    "response_time_p95": metrics.response_time_p95,
                    "memory_usage": metrics.memory_usage_percent,
                    "cpu_usage": metrics.cpu_usage_percent,
                    "issues": []
                }
                
                # Check for issues
                if status.state != "running":
                    agent_result["issues"].append(f"Agent not running: {status.state}")
                    issues += 1
                
                if health.status != "healthy":
                    agent_result["issues"].append(f"Agent unhealthy: {health.status}")
                    issues += 1
                
                if metrics.error_rate > 0.1:
                    agent_result["issues"].append(f"High error rate: {metrics.error_rate:.2%}")
                    issues += 1
                
                if metrics.response_time_p95 > 2000:
                    agent_result["issues"].append(f"High response time: {metrics.response_time_p95}ms")
                    issues += 1
                
                results["agents"][agent_name] = agent_result
                
                if agent_result["issues"]:
                    print(f"  ❌ {agent_name}: {', '.join(agent_result['issues'])}")
                else:
                    print(f"  ✅ {agent_name}: healthy")
                    
            except Exception as e:
                results["agents"][agent_name] = {
                    "status": "error",
                    "error": str(e),
                    "issues": [f"Failed to check agent: {e}"]
                }
                print(f"  ❌ {agent_name}: {e}")
                issues += 1
        
        return issues
```

## Common Issues and Solutions

### Agent Issues

#### Agent Not Starting

**Symptoms:**
- Agent status shows "failed" or "pending"
- Health checks return connection errors
- No logs from agent

**Diagnostic Steps:**
```bash
# Check agent status
agentcore get agent detection-agent -o yaml

# Check agent logs
agentcore logs detection-agent --tail 100

# Check resource constraints
kubectl describe pod -l app=detection-agent

# Check configuration
agentcore describe agent detection-agent
```

**Common Causes and Solutions:**

1. **Resource Constraints**
   ```yaml
   # Increase resource limits in agent configuration
   resources:
     requests:
       memory: "1Gi"
       cpu: "500m"
     limits:
       memory: "2Gi" 
       cpu: "1000m"
   ```

2. **Configuration Errors**
   ```bash
   # Validate configuration
   python scripts/validate_agent_config.py detection-agent.yaml
   
   # Fix common configuration issues
   python scripts/fix_agent_config.py detection-agent.yaml
   ```

3. **Dependency Issues**
   ```bash
   # Check external dependencies
   python scripts/check_dependencies.py
   
   # Test database connectivity
   python scripts/test_db_connection.py
   
   # Test AI model endpoint
   python scripts/test_ai_endpoint.py
   ```

#### High Error Rates

**Symptoms:**
- Error rate > 10%
- Frequent timeout errors
- Failed message processing

**Diagnostic Steps:**
```python
# scripts/diagnose_errors.py
async def diagnose_high_error_rate(agent_name: str):
    client = AgentCoreClient()
    
    # Get recent error logs
    logs = await client.get_agent_logs(
        agent_name, 
        level="ERROR", 
        since="1h",
        limit=100
    )
    
    # Analyze error patterns
    error_analysis = {
        "total_errors": len(logs),
        "error_types": {},
        "error_timeline": {},
        "recommendations": []
    }
    
    for log_entry in logs:
        # Categorize errors
        error_type = categorize_error(log_entry.message)
        error_analysis["error_types"][error_type] = error_analysis["error_types"].get(error_type, 0) + 1
        
        # Timeline analysis
        hour = log_entry.timestamp.strftime("%H:00")
        error_analysis["error_timeline"][hour] = error_analysis["error_timeline"].get(hour, 0) + 1
    
    # Generate recommendations
    if "timeout" in error_analysis["error_types"]:
        error_analysis["recommendations"].append("Increase timeout values in configuration")
    
    if "memory" in error_analysis["error_types"]:
        error_analysis["recommendations"].append("Increase memory allocation")
    
    if "connection" in error_analysis["error_types"]:
        error_analysis["recommendations"].append("Check network connectivity and retry logic")
    
    return error_analysis

def categorize_error(error_message: str) -> str:
    """Categorize error based on message content"""
    
    error_message_lower = error_message.lower()
    
    if "timeout" in error_message_lower:
        return "timeout"
    elif "memory" in error_message_lower or "oom" in error_message_lower:
        return "memory"
    elif "connection" in error_message_lower or "network" in error_message_lower:
        return "connection"
    elif "permission" in error_message_lower or "auth" in error_message_lower:
        return "authentication"
    elif "database" in error_message_lower or "sql" in error_message_lower:
        return "database"
    else:
        return "unknown"
```

**Solutions:**

1. **Timeout Issues**
   ```python
   # Increase timeout values
   config = {
       "message_timeout": 30,  # seconds
       "ai_model_timeout": 60,  # seconds
       "database_timeout": 10   # seconds
   }
   ```

2. **Memory Issues**
   ```bash
   # Monitor memory usage
   python scripts/monitor_memory.py --agent detection-agent
   
   # Optimize memory usage
   python scripts/optimize_memory.py --agent detection-agent
   ```

3. **Connection Issues**
   ```python
   # Implement retry logic with exponential backoff
   import asyncio
   import random
   
   async def retry_with_backoff(func, max_retries=3, base_delay=1):
       for attempt in range(max_retries):
           try:
               return await func()
           except Exception as e:
               if attempt == max_retries - 1:
                   raise e
               
               delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
               await asyncio.sleep(delay)
   ```

#### Agent Communication Issues

**Symptoms:**
- Messages not being delivered
- Workflow timeouts
- State synchronization problems

**Diagnostic Steps:**
```python
# scripts/test_agent_communication.py
async def test_agent_communication():
    client = AgentCoreClient()
    
    # Test message routing
    test_message = {
        "type": "test_message",
        "payload": {"test_data": "hello"},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Send test message between agents
    result = await client.send_message(
        source_agent="detection-agent",
        target_agent="coordinator-agent",
        message=test_message
    )
    
    # Wait for response
    response = await client.wait_for_message_response(
        message_id=result.message_id,
        timeout=10
    )
    
    if response:
        print("✅ Agent communication working")
    else:
        print("❌ Agent communication failed")
        
    # Test workflow execution
    workflow_result = await client.execute_workflow(
        workflow_id="test_workflow",
        parameters={"test": True}
    )
    
    print(f"Workflow result: {workflow_result.status}")
```

### Infrastructure Issues

#### Database Connection Problems

**Symptoms:**
- Database connection timeouts
- SQL query failures
- Data inconsistencies

**Diagnostic Steps:**
```python
# scripts/test_database.py
import asyncio
import asyncpg
from datetime import datetime

async def test_database_connection():
    try:
        # Test connection
        conn = await asyncpg.connect(
            host="honeypot-db.cluster-xxx.us-west-2.rds.amazonaws.com",
            port=5432,
            user="honeypot_user",
            password="password",
            database="honeypot_db",
            command_timeout=10
        )
        
        # Test basic query
        result = await conn.fetchval("SELECT 1")
        assert result == 1
        
        # Test table access
        tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        
        print(f"✅ Database connection successful, {len(tables)} tables found")
        
        # Test performance
        start_time = datetime.utcnow()
        await conn.fetchval("SELECT COUNT(*) FROM threat_events")
        query_time = (datetime.utcnow() - start_time).total_seconds()
        
        if query_time > 1.0:
            print(f"⚠️  Slow query performance: {query_time:.2f}s")
        else:
            print(f"✅ Query performance good: {query_time:.2f}s")
        
        await conn.close()
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False
    
    return True
```

**Solutions:**

1. **Connection Pool Configuration**
   ```python
   # Optimize connection pool settings
   DATABASE_CONFIG = {
       "min_size": 5,
       "max_size": 20,
       "max_queries": 50000,
       "max_inactive_connection_lifetime": 300,
       "command_timeout": 30
   }
   ```

2. **Query Optimization**
   ```sql
   -- Add indexes for common queries
   CREATE INDEX CONCURRENTLY idx_threat_events_timestamp 
   ON threat_events(created_at);
   
   CREATE INDEX CONCURRENTLY idx_engagements_status 
   ON engagements(status) WHERE status = 'active';
   ```

#### Storage Issues

**Symptoms:**
- S3 upload failures
- Disk space warnings
- File access errors

**Diagnostic Steps:**
```python
# scripts/test_storage.py
import boto3
import os
from datetime import datetime

def test_s3_connectivity():
    try:
        s3_client = boto3.client('s3')
        
        # Test bucket access
        buckets = s3_client.list_buckets()
        print(f"✅ S3 connectivity successful, {len(buckets['Buckets'])} buckets accessible")
        
        # Test upload
        test_key = f"health-check/{datetime.utcnow().isoformat()}.txt"
        s3_client.put_object(
            Bucket="honeypot-system-data",
            Key=test_key,
            Body="Health check test file"
        )
        
        # Test download
        response = s3_client.get_object(
            Bucket="honeypot-system-data",
            Key=test_key
        )
        
        # Cleanup
        s3_client.delete_object(
            Bucket="honeypot-system-data",
            Key=test_key
        )
        
        print("✅ S3 read/write operations successful")
        return True
        
    except Exception as e:
        print(f"❌ S3 connectivity failed: {e}")
        return False

def check_disk_space():
    """Check local disk space usage"""
    
    statvfs = os.statvfs('/')
    
    # Calculate disk usage
    total_space = statvfs.f_frsize * statvfs.f_blocks
    free_space = statvfs.f_frsize * statvfs.f_available
    used_space = total_space - free_space
    
    usage_percent = (used_space / total_space) * 100
    
    print(f"Disk usage: {usage_percent:.1f}% ({used_space / (1024**3):.1f}GB / {total_space / (1024**3):.1f}GB)")
    
    if usage_percent > 90:
        print("❌ Critical: Disk usage > 90%")
        return False
    elif usage_percent > 80:
        print("⚠️  Warning: Disk usage > 80%")
        return True
    else:
        print("✅ Disk usage normal")
        return True
```

### Performance Issues

#### High Response Times

**Symptoms:**
- API response times > 2 seconds
- Agent message processing delays
- Dashboard loading slowly

**Diagnostic Steps:**
```python
# scripts/performance_analysis.py
import asyncio
import time
import statistics
from typing import List

class PerformanceAnalyzer:
    def __init__(self):
        self.client = AgentCoreClient()
    
    async def analyze_response_times(self, agent_name: str, sample_size: int = 100) -> dict:
        """Analyze agent response times"""
        
        response_times = []
        errors = 0
        
        print(f"Analyzing response times for {agent_name} (sample size: {sample_size})")
        
        for i in range(sample_size):
            try:
                start_time = time.time()
                
                # Send test message
                await self.client.send_message(
                    target_agent=agent_name,
                    message_type="health_check",
                    payload={}
                )
                
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # Convert to ms
                response_times.append(response_time)
                
                if i % 10 == 0:
                    print(f"  Progress: {i}/{sample_size}")
                
            except Exception as e:
                errors += 1
                print(f"  Error in request {i}: {e}")
        
        if not response_times:
            return {"error": "No successful requests"}
        
        analysis = {
            "sample_size": len(response_times),
            "errors": errors,
            "error_rate": errors / sample_size,
            "min_ms": min(response_times),
            "max_ms": max(response_times),
            "mean_ms": statistics.mean(response_times),
            "median_ms": statistics.median(response_times),
            "p95_ms": self.percentile(response_times, 95),
            "p99_ms": self.percentile(response_times, 99)
        }
        
        # Performance assessment
        if analysis["p95_ms"] > 2000:
            analysis["assessment"] = "poor"
        elif analysis["p95_ms"] > 1000:
            analysis["assessment"] = "degraded"
        else:
            analysis["assessment"] = "good"
        
        return analysis
    
    def percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value"""
        sorted_data = sorted(data)
        index = (percentile / 100) * (len(sorted_data) - 1)
        
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))
```

**Solutions:**

1. **Optimize Agent Code**
   ```python
   # Use async/await properly
   async def optimized_message_handler(self, message):
       # Process multiple operations concurrently
       tasks = [
           self.validate_message(message),
           self.enrich_message_data(message),
           self.check_cache(message)
       ]
       
       validation, enrichment, cache_result = await asyncio.gather(*tasks)
       
       # Continue processing...
   ```

2. **Implement Caching**
   ```python
   import asyncio
   from functools import wraps
   
   def cache_result(ttl_seconds=300):
       def decorator(func):
           cache = {}
           
           @wraps(func)
           async def wrapper(*args, **kwargs):
               cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"
               
               if cache_key in cache:
                   result, timestamp = cache[cache_key]
                   if time.time() - timestamp < ttl_seconds:
                       return result
               
               result = await func(*args, **kwargs)
               cache[cache_key] = (result, time.time())
               
               return result
           
           return wrapper
       return decorator
   ```

3. **Database Query Optimization**
   ```python
   # Use connection pooling and prepared statements
   async def optimized_query(self, query: str, params: tuple):
       async with self.db_pool.acquire() as conn:
           # Use prepared statement for better performance
           stmt = await conn.prepare(query)
           return await stmt.fetch(*params)
   ```

## Emergency Procedures

### System Shutdown

```python
# scripts/emergency_shutdown.py
async def emergency_shutdown(reason: str):
    """Emergency shutdown of entire honeypot system"""
    
    print(f"🚨 EMERGENCY SHUTDOWN INITIATED: {reason}")
    
    client = AgentCoreClient()
    
    # 1. Stop all active engagements
    print("Terminating all active engagements...")
    engagements = await client.list_active_engagements()
    
    for engagement in engagements:
        await client.terminate_engagement(
            engagement.id, 
            reason=f"Emergency shutdown: {reason}"
        )
    
    # 2. Destroy all honeypots
    print("Destroying all honeypots...")
    honeypots = await client.list_active_honeypots()
    
    for honeypot in honeypots:
        await client.destroy_honeypot(honeypot.id)
    
    # 3. Stop agents in reverse dependency order
    shutdown_order = ["intelligence-agent", "interaction-agent", "detection-agent", "coordinator-agent"]
    
    for agent_name in shutdown_order:
        print(f"Stopping {agent_name}...")
        await client.stop_agent(agent_name)
    
    # 4. Send notifications
    await send_emergency_notification(reason)
    
    print("🚨 Emergency shutdown completed")

async def send_emergency_notification(reason: str):
    """Send emergency notifications to administrators"""
    
    notification = {
        "severity": "critical",
        "event": "emergency_shutdown",
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat(),
        "system": "honeypot-system"
    }
    
    # Send SNS notification
    sns_client = boto3.client('sns')
    await sns_client.publish(
        TopicArn="arn:aws:sns:us-west-2:123456789:honeypot-alerts",
        Message=json.dumps(notification),
        Subject="EMERGENCY: Honeypot System Shutdown"
    )
```

This troubleshooting guide provides comprehensive diagnostic and resolution procedures for maintaining system health and resolving issues quickly.