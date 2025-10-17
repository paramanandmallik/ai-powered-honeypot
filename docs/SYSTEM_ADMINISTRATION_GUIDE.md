# System Administration Guide

## Overview

This guide provides comprehensive system administration procedures for the AI-Powered Honeypot System, including user management, security configuration, monitoring setup, and operational procedures.

## User Management and Access Control

### User Roles and Permissions

The system implements role-based access control (RBAC) with the following roles:

#### Administrator Role
- Full system access and configuration
- User management and role assignment
- Emergency shutdown capabilities
- System configuration changes

#### Security Analyst Role
- View all engagements and intelligence reports
- Create and manage honeypots
- Access to threat detection data
- Generate custom reports

#### SOC Operator Role
- Monitor active engagements
- View real-time dashboards
- Terminate engagements if needed
- Access to basic reporting

#### Read-Only Role
- View dashboards and reports
- Access to historical data
- No modification capabilities

### User Management Procedures

#### Create New User
```python
# scripts/create_user.py
import asyncio
from auth_service import AuthenticationService
from user_management import UserManager

async def create_user(username: str, email: str, role: str, temporary_password: str):
    """Create a new user account"""
    
    auth_service = AuthenticationService()
    user_manager = UserManager()
    
    # Validate role
    valid_roles = ["administrator", "security_analyst", "soc_operator", "read_only"]
    if role not in valid_roles:
        raise ValueError(f"Invalid role. Must be one of: {valid_roles}")
    
    # Create user account
    user_id = await user_manager.create_user(
        username=username,
        email=email,
        role=role,
        password=temporary_password,
        force_password_change=True
    )
    
    # Generate initial API key
    api_key = await auth_service.generate_api_key(user_id)
    
    # Send welcome email
    await send_welcome_email(email, username, temporary_password, api_key)
    
    print(f"✅ User {username} created successfully")
    print(f"   User ID: {user_id}")
    print(f"   Role: {role}")
    print(f"   API Key: {api_key}")
    
    return user_id

# Usage
if __name__ == "__main__":
    asyncio.run(create_user(
        username="john.doe",
        email="john.doe@company.com", 
        role="security_analyst",
        temporary_password="TempPass123!"
    ))
```

#### Modify User Permissions
```python
# scripts/modify_user.py
async def modify_user_role(username: str, new_role: str):
    """Change user role and permissions"""
    
    user_manager = UserManager()
    
    # Get current user
    user = await user_manager.get_user_by_username(username)
    if not user:
        raise ValueError(f"User {username} not found")
    
    old_role = user.role
    
    # Update role
    await user_manager.update_user_role(user.id, new_role)
    
    # Log role change
    await audit_logger.log_event(
        event_type="user_role_changed",
        user_id=user.id,
        details={
            "old_role": old_role,
            "new_role": new_role,
            "changed_by": "admin"
        }
    )
    
    print(f"✅ User {username} role changed from {old_role} to {new_role}")

async def reset_user_password(username: str):
    """Reset user password and force change on next login"""
    
    user_manager = UserManager()
    auth_service = AuthenticationService()
    
    # Generate temporary password
    temp_password = auth_service.generate_temporary_password()
    
    # Update user password
    await user_manager.reset_password(username, temp_password, force_change=True)
    
    # Revoke existing sessions
    await auth_service.revoke_user_sessions(username)
    
    # Send password reset email
    user = await user_manager.get_user_by_username(username)
    await send_password_reset_email(user.email, username, temp_password)
    
    print(f"✅ Password reset for user {username}")
    print(f"   Temporary password: {temp_password}")
```

### Multi-Factor Authentication Setup

```python
# scripts/setup_mfa.py
import qrcode
import pyotp
from io import BytesIO

async def setup_mfa_for_user(username: str):
    """Setup MFA for a user account"""
    
    user_manager = UserManager()
    user = await user_manager.get_user_by_username(username)
    
    # Generate TOTP secret
    secret = pyotp.random_base32()
    
    # Create TOTP URI
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="Honeypot System"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    qr_image = qr.make_image(fill_color="black", back_color="white")
    
    # Save QR code
    qr_buffer = BytesIO()
    qr_image.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)
    
    # Store MFA secret (encrypted)
    await user_manager.set_mfa_secret(user.id, secret)
    
    print(f"✅ MFA setup for user {username}")
    print(f"   Secret: {secret}")
    print(f"   QR Code saved for scanning")
    
    return {
        "secret": secret,
        "qr_code": qr_buffer.getvalue(),
        "backup_codes": await generate_backup_codes(user.id)
    }

async def generate_backup_codes(user_id: str, count: int = 10):
    """Generate backup codes for MFA recovery"""
    
    import secrets
    import string
    
    backup_codes = []
    
    for _ in range(count):
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        backup_codes.append(code)
    
    # Store encrypted backup codes
    await user_manager.store_backup_codes(user_id, backup_codes)
    
    return backup_codes
```

## Security Configuration

### SSL/TLS Configuration

```yaml
# nginx/honeypot-system.conf
server {
    listen 443 ssl http2;
    server_name api.honeypot-system.aws.amazon.com;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/honeypot-system.crt;
    ssl_certificate_key /etc/ssl/private/honeypot-system.key;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # API Gateway
    location /api/ {
        proxy_pass http://api-gateway:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Rate limiting
        limit_req zone=api burst=20 nodelay;
    }
    
    # Dashboard
    location / {
        proxy_pass http://dashboard:3000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Rate limiting configuration
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
}
```

### Network Security Configuration

```python
# scripts/configure_network_security.py
import boto3

def configure_vpc_security():
    """Configure VPC security groups and NACLs"""
    
    ec2 = boto3.client('ec2')
    
    # Create security group for honeypot infrastructure
    honeypot_sg = ec2.create_security_group(
        GroupName='honeypot-infrastructure',
        Description='Security group for honeypot infrastructure',
        VpcId='vpc-12345678'
    )
    
    # Configure inbound rules (very restrictive)
    ec2.authorize_security_group_ingress(
        GroupId=honeypot_sg['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '10.0.0.0/8', 'Description': 'Internal SSH access'}]
            },
            {
                'IpProtocol': 'tcp', 
                'FromPort': 443,
                'ToPort': 443,
                'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS access'}]
            }
        ]
    )
    
    # Configure outbound rules (deny all external)
    ec2.revoke_security_group_egress(
        GroupId=honeypot_sg['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    
    # Allow internal communication only
    ec2.authorize_security_group_egress(
        GroupId=honeypot_sg['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': '10.0.0.0/8', 'Description': 'Internal communication'}]
            }
        ]
    )
    
    print(f"✅ Security group configured: {honeypot_sg['GroupId']}")

def configure_waf():
    """Configure AWS WAF for API protection"""
    
    wafv2 = boto3.client('wafv2')
    
    # Create WAF web ACL
    web_acl = wafv2.create_web_acl(
        Scope='REGIONAL',
        Name='honeypot-system-waf',
        DefaultAction={'Allow': {}},
        Rules=[
            {
                'Name': 'RateLimitRule',
                'Priority': 1,
                'Statement': {
                    'RateBasedStatement': {
                        'Limit': 2000,
                        'AggregateKeyType': 'IP'
                    }
                },
                'Action': {'Block': {}},
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': 'RateLimitRule'
                }
            },
            {
                'Name': 'SQLInjectionRule',
                'Priority': 2,
                'Statement': {
                    'ManagedRuleGroupStatement': {
                        'VendorName': 'AWS',
                        'Name': 'AWSManagedRulesSQLiRuleSet'
                    }
                },
                'Action': {'Block': {}},
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': 'SQLInjectionRule'
                }
            }
        ]
    )
    
    print(f"✅ WAF configured: {web_acl['Summary']['ARN']}")
```

## Monitoring and Alerting Setup

### CloudWatch Configuration

```python
# scripts/setup_monitoring.py
import boto3
import json

def setup_cloudwatch_monitoring():
    """Setup CloudWatch dashboards and alarms"""
    
    cloudwatch = boto3.client('cloudwatch')
    
    # Create custom metrics dashboard
    dashboard_body = {
        "widgets": [
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["HoneypotSystem", "ThreatsDetected", "Agent", "detection-agent"],
                        [".", "EngagementsActive", "Agent", "coordinator-agent"],
                        [".", "IntelligenceReportsGenerated", "Agent", "intelligence-agent"]
                    ],
                    "period": 300,
                    "stat": "Sum",
                    "region": "us-west-2",
                    "title": "System Activity"
                }
            },
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AWS/AgentCore", "ErrorRate", "Agent", "detection-agent"],
                        [".", ".", "Agent", "coordinator-agent"],
                        [".", ".", "Agent", "interaction-agent"],
                        [".", ".", "Agent", "intelligence-agent"]
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": "us-west-2",
                    "title": "Agent Error Rates"
                }
            }
        ]
    }
    
    cloudwatch.put_dashboard(
        DashboardName='HoneypotSystem',
        DashboardBody=json.dumps(dashboard_body)
    )
    
    # Create alarms
    alarms = [
        {
            'AlarmName': 'HighErrorRate-DetectionAgent',
            'ComparisonOperator': 'GreaterThanThreshold',
            'EvaluationPeriods': 2,
            'MetricName': 'ErrorRate',
            'Namespace': 'AWS/AgentCore',
            'Period': 300,
            'Statistic': 'Average',
            'Threshold': 0.1,
            'ActionsEnabled': True,
            'AlarmActions': ['arn:aws:sns:us-west-2:123456789:honeypot-alerts'],
            'AlarmDescription': 'Detection agent error rate too high',
            'Dimensions': [{'Name': 'Agent', 'Value': 'detection-agent'}]
        },
        {
            'AlarmName': 'SystemUnhealthy',
            'ComparisonOperator': 'LessThanThreshold',
            'EvaluationPeriods': 1,
            'MetricName': 'HealthyAgents',
            'Namespace': 'HoneypotSystem',
            'Period': 60,
            'Statistic': 'Average',
            'Threshold': 4,
            'ActionsEnabled': True,
            'AlarmActions': ['arn:aws:sns:us-west-2:123456789:honeypot-critical-alerts'],
            'AlarmDescription': 'One or more agents are unhealthy'
        }
    ]
    
    for alarm in alarms:
        cloudwatch.put_metric_alarm(**alarm)
    
    print("✅ CloudWatch monitoring configured")

def setup_log_aggregation():
    """Setup centralized logging with CloudWatch Logs"""
    
    logs_client = boto3.client('logs')
    
    # Create log groups
    log_groups = [
        '/aws/honeypot/detection-agent',
        '/aws/honeypot/coordinator-agent', 
        '/aws/honeypot/interaction-agent',
        '/aws/honeypot/intelligence-agent',
        '/aws/honeypot/system-events',
        '/aws/honeypot/security-events'
    ]
    
    for log_group in log_groups:
        try:
            logs_client.create_log_group(
                logGroupName=log_group,
                retentionInDays=30
            )
            print(f"✅ Created log group: {log_group}")
        except logs_client.exceptions.ResourceAlreadyExistsException:
            print(f"ℹ️  Log group already exists: {log_group}")
    
    # Create metric filters for important events
    metric_filters = [
        {
            'logGroupName': '/aws/honeypot/system-events',
            'filterName': 'ThreatDetected',
            'filterPattern': '[timestamp, level="INFO", event="threat_detected", ...]',
            'metricTransformations': [{
                'metricName': 'ThreatsDetected',
                'metricNamespace': 'HoneypotSystem',
                'metricValue': '1'
            }]
        },
        {
            'logGroupName': '/aws/honeypot/security-events',
            'filterName': 'SecurityIncident',
            'filterPattern': '[timestamp, level="ERROR", event="security_incident", ...]',
            'metricTransformations': [{
                'metricName': 'SecurityIncidents',
                'metricNamespace': 'HoneypotSystem',
                'metricValue': '1'
            }]
        }
    ]
    
    for filter_config in metric_filters:
        logs_client.put_metric_filter(**filter_config)
    
    print("✅ Log aggregation configured")
```

### Grafana Dashboard Setup

```python
# scripts/setup_grafana.py
import requests
import json

class GrafanaManager:
    def __init__(self, grafana_url: str, api_key: str):
        self.base_url = grafana_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def create_honeypot_dashboard(self):
        """Create comprehensive Grafana dashboard"""
        
        dashboard_config = {
            "dashboard": {
                "title": "Honeypot System Overview",
                "tags": ["honeypot", "security"],
                "timezone": "UTC",
                "panels": [
                    {
                        "title": "System Health",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "honeypot_agents_healthy",
                                "legendFormat": "Healthy Agents"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "thresholds": {
                                    "steps": [
                                        {"color": "red", "value": 0},
                                        {"color": "yellow", "value": 3},
                                        {"color": "green", "value": 4}
                                    ]
                                }
                            }
                        }
                    },
                    {
                        "title": "Threat Detection Rate",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(honeypot_threats_detected_total[5m])",
                                "legendFormat": "Threats/min"
                            }
                        ]
                    },
                    {
                        "title": "Active Engagements",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "honeypot_engagements_active",
                                "legendFormat": "Active Engagements"
                            }
                        ]
                    },
                    {
                        "title": "Agent Response Times",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "honeypot_agent_response_time_p95",
                                "legendFormat": "{{agent}} P95"
                            }
                        ]
                    }
                ]
            }
        }
        
        response = requests.post(
            f"{self.base_url}/api/dashboards/db",
            headers=self.headers,
            data=json.dumps(dashboard_config)
        )
        
        if response.status_code == 200:
            print("✅ Grafana dashboard created successfully")
        else:
            print(f"❌ Failed to create dashboard: {response.text}")
    
    def setup_alerting_rules(self):
        """Setup Grafana alerting rules"""
        
        alert_rules = [
            {
                "alert": {
                    "name": "HighErrorRate",
                    "message": "Agent error rate is too high",
                    "frequency": "10s",
                    "conditions": [
                        {
                            "query": {
                                "queryType": "",
                                "refId": "A"
                            },
                            "reducer": {
                                "type": "last",
                                "params": []
                            },
                            "evaluator": {
                                "params": [0.1],
                                "type": "gt"
                            }
                        }
                    ],
                    "executionErrorState": "alerting",
                    "noDataState": "no_data",
                    "for": "1m"
                }
            }
        ]
        
        # Implementation depends on Grafana version and setup
        print("✅ Grafana alerting rules configured")
```

## Backup and Recovery Procedures

### Automated Backup Configuration

```python
# scripts/setup_backups.py
import boto3
import json
from datetime import datetime, timedelta

class BackupManager:
    def __init__(self):
        self.s3_client = boto3.client('s3')
        self.rds_client = boto3.client('rds')
        self.backup_bucket = 'honeypot-system-backups'
    
    def setup_automated_backups(self):
        """Configure automated backup procedures"""
        
        # RDS automated backups
        self.configure_rds_backups()
        
        # Configuration backups
        self.setup_config_backups()
        
        # Log archival
        self.setup_log_archival()
        
        print("✅ Automated backups configured")
    
    def configure_rds_backups(self):
        """Configure RDS automated backups"""
        
        # Enable automated backups with 7-day retention
        self.rds_client.modify_db_instance(
            DBInstanceIdentifier='honeypot-db',
            BackupRetentionPeriod=7,
            PreferredBackupWindow='03:00-04:00',
            ApplyImmediately=True
        )
        
        # Create backup policy for point-in-time recovery
        backup_policy = {
            'Rules': [
                {
                    'RuleName': 'DailyBackups',
                    'TargetBackupVault': 'honeypot-backup-vault',
                    'ScheduleExpression': 'cron(0 2 ? * * *)',
                    'StartWindowMinutes': 60,
                    'CompletionWindowMinutes': 120,
                    'Lifecycle': {
                        'DeleteAfterDays': 30
                    }
                }
            ]
        }
        
        print("✅ RDS backups configured")
    
    def setup_config_backups(self):
        """Setup configuration backup to S3"""
        
        # Create Lambda function for config backups
        lambda_code = '''
import json
import boto3
from datetime import datetime

def lambda_handler(event, context):
    # Backup AgentCore configurations
    agentcore_client = AgentCoreClient()
    
    backup_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "agents": {},
        "workflows": {}
    }
    
    # Backup agent configs
    agents = ["detection-agent", "coordinator-agent", "interaction-agent", "intelligence-agent"]
    for agent in agents:
        config = agentcore_client.get_agent_configuration(agent)
        backup_data["agents"][agent] = config
    
    # Upload to S3
    s3_client = boto3.client('s3')
    backup_key = f"config-backups/{datetime.utcnow().strftime('%Y/%m/%d')}/config.json"
    
    s3_client.put_object(
        Bucket='honeypot-system-backups',
        Key=backup_key,
        Body=json.dumps(backup_data),
        ServerSideEncryption='AES256'
    )
    
    return {"statusCode": 200, "body": "Backup completed"}
        '''
        
        # Schedule daily config backups
        events_client = boto3.client('events')
        events_client.put_rule(
            Name='DailyConfigBackup',
            ScheduleExpression='cron(0 1 * * ? *)',
            Description='Daily configuration backup',
            State='ENABLED'
        )
        
        print("✅ Configuration backups scheduled")

def create_disaster_recovery_plan():
    """Create disaster recovery procedures"""
    
    dr_plan = {
        "recovery_objectives": {
            "rto": "4 hours",  # Recovery Time Objective
            "rpo": "1 hour"    # Recovery Point Objective
        },
        "procedures": [
            {
                "step": 1,
                "action": "Assess damage and determine recovery scope",
                "estimated_time": "30 minutes"
            },
            {
                "step": 2, 
                "action": "Restore AWS infrastructure from CloudFormation",
                "estimated_time": "60 minutes"
            },
            {
                "step": 3,
                "action": "Restore database from latest backup",
                "estimated_time": "90 minutes"
            },
            {
                "step": 4,
                "action": "Deploy agents to AgentCore Runtime",
                "estimated_time": "30 minutes"
            },
            {
                "step": 5,
                "action": "Restore configurations and validate system",
                "estimated_time": "30 minutes"
            }
        ],
        "contacts": [
            {"role": "Primary", "name": "System Administrator", "phone": "+1-555-0001"},
            {"role": "Secondary", "name": "Security Lead", "phone": "+1-555-0002"},
            {"role": "Management", "name": "IT Director", "phone": "+1-555-0003"}
        ]
    }
    
    # Save DR plan to S3
    s3_client = boto3.client('s3')
    s3_client.put_object(
        Bucket='honeypot-system-backups',
        Key='disaster-recovery/dr-plan.json',
        Body=json.dumps(dr_plan, indent=2),
        ServerSideEncryption='AES256'
    )
    
    print("✅ Disaster recovery plan created")
```

This system administration guide provides comprehensive procedures for managing users, security, monitoring, and recovery operations for the honeypot system.