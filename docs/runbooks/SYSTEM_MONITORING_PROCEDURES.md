# System Monitoring Procedures

## Overview

This runbook provides comprehensive procedures for monitoring the AI-Powered Honeypot System, including health checks, performance monitoring, alerting configuration, and maintenance tasks.

## Daily Monitoring Procedures

### Morning Health Check (Start of Business Day)

#### Step 1: System Status Overview
```bash
# Run comprehensive system health check
python scripts/daily_health_check.py

# Check AgentCore Runtime status
python scripts/check_agentcore_status.py

# Verify all agents are running
python scripts/verify_agent_status.py --all
```

#### Step 2: Review Overnight Activity
```python
# scripts/overnight_activity_review.py
import asyncio
from datetime import datetime, timedelta

async def review_overnight_activity():
    """Review system activity from previous night"""
    
    # Define time range (6 PM yesterday to 8 AM today)
    end_time = datetime.utcnow().replace(hour=8, minute=0, second=0, microsecond=0)
    start_time = (end_time - timedelta(days=1)).replace(hour=18, minute=0, second=0, microsecond=0)
    
    print(f"📊 Reviewing activity from {start_time} to {end_time}")
    
    # Get threat detection summary
    threats = await get_threats_detected(start_time, end_time)
    print(f"🎯 Threats detected: {len(threats)}")
    
    # Get engagement summary
    engagements = await get_engagements_completed(start_time, end_time)
    print(f"🎭 Engagements completed: {len(engagements)}")
    
    # Get intelligence reports
    reports = await get_intelligence_reports(start_time, end_time)
    print(f"📋 Intelligence reports generated: {len(reports)}")
    
    # Check for any alerts or incidents
    alerts = await get_system_alerts(start_time, end_time, severity=["high", "critical"])
    if alerts:
        print(f"⚠️  {len(alerts)} high/critical alerts - REVIEW REQUIRED")
        for alert in alerts:
            print(f"   - {alert.timestamp}: {alert.message}")
    else:
        print("✅ No critical alerts overnight")
    
    # Performance summary
    performance = await get_performance_summary(start_time, end_time)
    print(f"⚡ Avg response time: {performance['avg_response_time']:.0f}ms")
    print(f"📈 Peak concurrent engagements: {performance['peak_engagements']}")
    
    return {
        "threats_detected": len(threats),
        "engagements_completed": len(engagements),
        "reports_generated": len(reports),
        "alerts_count": len(alerts),
        "performance": performance
    }

if __name__ == "__main__":
    summary = asyncio.run(review_overnight_activity())
    print(f"\n📊 Overnight Summary: {summary}")
```

#### Step 3: Infrastructure Health Check
```python
# scripts/infrastructure_health_check.py
async def check_infrastructure_health():
    """Check health of supporting infrastructure"""
    
    health_status = {
        "timestamp": datetime.utcnow().isoformat(),
        "overall_status": "unknown",
        "components": {}
    }
    
    # Check database connectivity and performance
    print("Checking database health...")
    db_health = await check_database_health()
    health_status["components"]["database"] = db_health
    
    if db_health["status"] == "healthy":
        print(f"✅ Database: {db_health['response_time']:.0f}ms response time")
    else:
        print(f"❌ Database: {db_health['error']}")
    
    # Check S3 storage
    print("Checking S3 storage...")
    s3_health = await check_s3_health()
    health_status["components"]["storage"] = s3_health
    
    if s3_health["status"] == "healthy":
        print(f"✅ S3 Storage: {s3_health['usage_percent']:.1f}% used")
    else:
        print(f"❌ S3 Storage: {s3_health['error']}")
    
    # Check CloudWatch metrics
    print("Checking CloudWatch...")
    cw_health = await check_cloudwatch_health()
    health_status["components"]["monitoring"] = cw_health
    
    # Check network connectivity
    print("Checking network connectivity...")
    network_health = await check_network_health()
    health_status["components"]["network"] = network_health
    
    # Determine overall status
    component_statuses = [comp["status"] for comp in health_status["components"].values()]
    
    if all(status == "healthy" for status in component_statuses):
        health_status["overall_status"] = "healthy"
        print("✅ All infrastructure components healthy")
    elif any(status == "unhealthy" for status in component_statuses):
        health_status["overall_status"] = "unhealthy"
        print("❌ One or more infrastructure components unhealthy")
    else:
        health_status["overall_status"] = "degraded"
        print("⚠️  Infrastructure performance degraded")
    
    return health_status
```### Even
ing Monitoring Check (End of Business Day)

#### Step 1: Daily Activity Summary
```python
# scripts/daily_summary_report.py
async def generate_daily_summary():
    """Generate end-of-day activity summary"""
    
    # Define business day (8 AM to 6 PM)
    today = datetime.utcnow().date()
    start_time = datetime.combine(today, datetime.min.time().replace(hour=8))
    end_time = datetime.combine(today, datetime.min.time().replace(hour=18))
    
    summary = {
        "date": today.isoformat(),
        "business_hours": f"{start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')} UTC",
        "metrics": {},
        "top_threats": [],
        "system_performance": {},
        "issues_encountered": []
    }
    
    # Collect daily metrics
    summary["metrics"] = {
        "threats_detected": await count_threats_detected(start_time, end_time),
        "engagements_created": await count_engagements_created(start_time, end_time),
        "engagements_completed": await count_engagements_completed(start_time, end_time),
        "intelligence_reports": await count_intelligence_reports(start_time, end_time),
        "unique_attackers": await count_unique_attackers(start_time, end_time)
    }
    
    # Get top threats by confidence score
    threats = await get_threats_detected(start_time, end_time)
    summary["top_threats"] = sorted(threats, key=lambda x: x.confidence_score, reverse=True)[:5]
    
    # System performance metrics
    performance = await get_performance_metrics(start_time, end_time)
    summary["system_performance"] = {
        "avg_response_time": performance["avg_response_time"],
        "peak_response_time": performance["peak_response_time"],
        "error_rate": performance["error_rate"],
        "uptime_percentage": performance["uptime_percentage"]
    }
    
    # Check for any issues during the day
    issues = await get_system_issues(start_time, end_time)
    summary["issues_encountered"] = [
        {
            "time": issue.timestamp,
            "severity": issue.severity,
            "description": issue.description,
            "resolved": issue.resolved
        }
        for issue in issues
    ]
    
    # Save daily summary
    await save_daily_summary(summary)
    
    print(f"📊 Daily Summary for {today}")
    print(f"   Threats detected: {summary['metrics']['threats_detected']}")
    print(f"   Engagements: {summary['metrics']['engagements_completed']}")
    print(f"   Avg response time: {summary['system_performance']['avg_response_time']:.0f}ms")
    print(f"   System uptime: {summary['system_performance']['uptime_percentage']:.1f}%")
    
    if summary["issues_encountered"]:
        print(f"   ⚠️  {len(summary['issues_encountered'])} issues encountered")
    else:
        print("   ✅ No issues encountered")
    
    return summary
```

#### Step 2: Prepare for Overnight Operations
```bash
# Verify overnight monitoring is active
python scripts/verify_monitoring_active.py

# Check alert thresholds are appropriate
python scripts/check_alert_thresholds.py

# Ensure on-call rotation is current
python scripts/verify_oncall_schedule.py

# Run preventive maintenance if scheduled
python scripts/check_maintenance_schedule.py
```

## Real-Time Monitoring Dashboards

### Primary Dashboard Metrics

#### System Health Dashboard
```python
# Dashboard configuration for Grafana/CloudWatch
SYSTEM_HEALTH_METRICS = {
    "agent_health": {
        "query": "honeypot_agent_health_status",
        "threshold": {"healthy": 4, "degraded": 3, "critical": 2},
        "alert_on": "value < 4"
    },
    "response_time": {
        "query": "honeypot_response_time_p95",
        "threshold": {"good": 1000, "degraded": 2000, "critical": 5000},
        "alert_on": "value > 2000"
    },
    "error_rate": {
        "query": "honeypot_error_rate",
        "threshold": {"good": 0.01, "degraded": 0.05, "critical": 0.1},
        "alert_on": "value > 0.05"
    },
    "active_engagements": {
        "query": "honeypot_active_engagements",
        "threshold": {"normal": 10, "high": 15, "critical": 20},
        "alert_on": "value > 15"
    }
}
```

#### Security Dashboard Metrics
```python
SECURITY_METRICS = {
    "threat_detection_rate": {
        "query": "rate(honeypot_threats_detected_total[5m])",
        "description": "Threats detected per minute"
    },
    "high_confidence_threats": {
        "query": "honeypot_threats_detected{confidence=\"high\"}",
        "alert_on": "increase > 5 in 10m"
    },
    "real_data_alerts": {
        "query": "honeypot_real_data_detected_total",
        "alert_on": "increase > 0",
        "severity": "critical"
    },
    "engagement_success_rate": {
        "query": "honeypot_successful_engagements / honeypot_total_engagements",
        "threshold": {"good": 0.8, "degraded": 0.6, "critical": 0.4}
    }
}
```

### Alert Configuration

#### Critical Alerts (Immediate Response Required)
```yaml
# alerts/critical.yml
groups:
  - name: honeypot_critical
    rules:
      - alert: RealDataDetected
        expr: increase(honeypot_real_data_detected_total[1m]) > 0
        for: 0s
        labels:
          severity: critical
        annotations:
          summary: "Real data detected in honeypot system"
          description: "IMMEDIATE ACTION REQUIRED: Real data has been detected"
          
      - alert: SystemCompromise
        expr: honeypot_security_breach_detected > 0
        for: 0s
        labels:
          severity: critical
        annotations:
          summary: "Potential system compromise detected"
          
      - alert: AllAgentsDown
        expr: honeypot_healthy_agents < 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "All agents are unhealthy"
```

#### High Priority Alerts
```yaml
# alerts/high_priority.yml
groups:
  - name: honeypot_high_priority
    rules:
      - alert: HighErrorRate
        expr: honeypot_error_rate > 0.1
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "High error rate detected"
          
      - alert: SlowResponseTime
        expr: honeypot_response_time_p95 > 5000
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "Response times are too slow"
          
      - alert: AgentUnhealthy
        expr: honeypot_agent_health_status < 4
        for: 2m
        labels:
          severity: high
        annotations:
          summary: "One or more agents are unhealthy"
```

## Performance Monitoring

### Key Performance Indicators (KPIs)

#### System Performance KPIs
```python
# scripts/calculate_kpis.py
async def calculate_system_kpis(time_range: str = "24h"):
    """Calculate key performance indicators"""
    
    kpis = {}
    
    # Availability KPI (target: 99.9%)
    uptime_data = await get_uptime_data(time_range)
    kpis["availability_percent"] = (uptime_data["uptime_seconds"] / uptime_data["total_seconds"]) * 100
    
    # Response Time KPI (target: <2000ms P95)
    response_times = await get_response_times(time_range)
    kpis["response_time_p95_ms"] = calculate_percentile(response_times, 95)
    
    # Error Rate KPI (target: <1%)
    error_data = await get_error_data(time_range)
    kpis["error_rate_percent"] = (error_data["errors"] / error_data["total_requests"]) * 100
    
    # Threat Detection Accuracy (target: >90%)
    detection_data = await get_detection_accuracy(time_range)
    kpis["detection_accuracy_percent"] = detection_data["accuracy"] * 100
    
    # Engagement Success Rate (target: >80%)
    engagement_data = await get_engagement_data(time_range)
    kpis["engagement_success_rate"] = (engagement_data["successful"] / engagement_data["total"]) * 100
    
    # Intelligence Quality Score (target: >85%)
    intelligence_data = await get_intelligence_quality(time_range)
    kpis["intelligence_quality_score"] = intelligence_data["average_confidence"] * 100
    
    return kpis

async def check_kpi_targets(kpis: dict):
    """Check if KPIs meet target thresholds"""
    
    targets = {
        "availability_percent": 99.9,
        "response_time_p95_ms": 2000,
        "error_rate_percent": 1.0,
        "detection_accuracy_percent": 90.0,
        "engagement_success_rate": 80.0,
        "intelligence_quality_score": 85.0
    }
    
    results = {}
    
    for kpi, value in kpis.items():
        target = targets.get(kpi)
        if target:
            if kpi == "response_time_p95_ms" or kpi == "error_rate_percent":
                # Lower is better for these metrics
                results[kpi] = {
                    "value": value,
                    "target": target,
                    "meets_target": value <= target,
                    "variance": ((value - target) / target) * 100
                }
            else:
                # Higher is better for these metrics
                results[kpi] = {
                    "value": value,
                    "target": target,
                    "meets_target": value >= target,
                    "variance": ((value - target) / target) * 100
                }
    
    return results
```

### Capacity Planning

#### Resource Utilization Monitoring
```python
# scripts/capacity_monitoring.py
async def monitor_resource_capacity():
    """Monitor system resource capacity and predict scaling needs"""
    
    capacity_report = {
        "timestamp": datetime.utcnow().isoformat(),
        "current_utilization": {},
        "trends": {},
        "scaling_recommendations": []
    }
    
    # CPU utilization by agent
    for agent in ["detection-agent", "coordinator-agent", "interaction-agent", "intelligence-agent"]:
        cpu_usage = await get_agent_cpu_usage(agent)
        memory_usage = await get_agent_memory_usage(agent)
        
        capacity_report["current_utilization"][agent] = {
            "cpu_percent": cpu_usage,
            "memory_percent": memory_usage,
            "instance_count": await get_agent_instance_count(agent)
        }
        
        # Check if scaling is needed
        if cpu_usage > 70 or memory_usage > 80:
            capacity_report["scaling_recommendations"].append({
                "agent": agent,
                "action": "scale_up",
                "reason": f"High resource usage: CPU {cpu_usage}%, Memory {memory_usage}%"
            })
    
    # Database capacity
    db_metrics = await get_database_metrics()
    capacity_report["current_utilization"]["database"] = {
        "cpu_percent": db_metrics["cpu_utilization"],
        "memory_percent": db_metrics["memory_utilization"],
        "storage_percent": db_metrics["storage_utilization"],
        "connections_percent": (db_metrics["active_connections"] / db_metrics["max_connections"]) * 100
    }
    
    # Storage capacity
    storage_metrics = await get_storage_metrics()
    capacity_report["current_utilization"]["storage"] = {
        "s3_usage_gb": storage_metrics["s3_usage_gb"],
        "s3_growth_rate_gb_per_day": storage_metrics["growth_rate"],
        "estimated_days_to_limit": storage_metrics["days_to_limit"]
    }
    
    return capacity_report
```

This monitoring runbook provides comprehensive procedures for maintaining system health and performance visibility.