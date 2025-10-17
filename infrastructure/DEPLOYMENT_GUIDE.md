# AI Honeypot Infrastructure Deployment Guide

This guide provides step-by-step instructions for deploying the AI Honeypot AgentCore infrastructure on AWS.

## Overview

The AI Honeypot infrastructure consists of:

- **Network Layer**: VPC with isolated subnets for security
- **Database Layer**: RDS PostgreSQL for intelligence data storage
- **Storage Layer**: S3 buckets for session data and audit logs
- **Compute Layer**: Lambda functions for data processing
- **Integration Layer**: API Gateway and SNS for external integrations
- **Monitoring Layer**: CloudWatch dashboards and alarms

## Prerequisites

### 1. AWS Account Setup

- AWS account with appropriate permissions
- AWS CLI configured with credentials
- Sufficient service quotas for the deployment

### 2. Development Environment

```bash
# Install required tools
npm install -g aws-cdk
pip install boto3 psycopg2-binary

# Verify installations
aws --version
cdk --version
python --version
```

### 3. Environment Configuration

Set environment variables:

```bash
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION=us-east-1
export ENVIRONMENT=dev  # or staging, prod
```

## Deployment Methods

### Method 1: Complete Automated Deployment (Recommended)

Use the complete deployment script for end-to-end deployment:

```bash
cd infrastructure
python deploy_complete.py --action deploy --environment dev --region us-east-1
```

This script will:
1. Validate prerequisites
2. Deploy all CDK stacks in order
3. Initialize the database schema
4. Configure monitoring and alerting
5. Validate the deployment
6. Generate a deployment summary

### Method 2: Manual Step-by-Step Deployment

#### Step 1: Bootstrap CDK

```bash
cd infrastructure/cdk
cdk bootstrap aws://$AWS_ACCOUNT_ID/$AWS_REGION
```

#### Step 2: Deploy Infrastructure Stacks

Deploy stacks in the correct order:

```bash
# Network foundation
cdk deploy HoneypotNetworkStack --require-approval never

# Security and IAM
cdk deploy HoneypotSecurityStack --require-approval never

# Storage
cdk deploy HoneypotStorageStack --require-approval never

# Database
cdk deploy HoneypotDatabaseStack --require-approval never

# Monitoring
cdk deploy HoneypotMonitoringStack --require-approval never

# Integration services
cdk deploy HoneypotIntegrationStack --require-approval never
```

#### Step 3: Initialize Database

Wait for RDS to be available, then initialize the schema:

```bash
# Wait for database to be ready
aws rds wait db-instance-available --db-instance-identifier <db-identifier>

# Initialize database schema
python ../initialize_database.py --environment dev
```

#### Step 4: Validate Deployment

```bash
python validate_deployment.py --region us-east-1
```

### Method 3: Individual Stack Deployment

For development or troubleshooting, deploy individual stacks:

```bash
python deploy.py --action deploy --environment dev --stacks HoneypotNetworkStack
```

## Post-Deployment Configuration

### 1. Database Access

The database is automatically initialized with the required schema. To connect manually:

```bash
# Get database endpoint from CDK outputs
DB_ENDPOINT=$(aws cloudformation describe-stacks \
  --stack-name HoneypotDatabaseStack \
  --query 'Stacks[0].Outputs[?OutputKey==`DatabaseEndpoint`].OutputValue' \
  --output text)

# Get credentials from Secrets Manager
SECRET_ARN=$(aws secretsmanager list-secrets \
  --query 'SecretList[?contains(Name, `Database`)].ARN' \
  --output text)

# Connect to database
psql -h $DB_ENDPOINT -U honeypot_admin -d honeypot_intelligence
```

### 2. API Gateway Configuration

Configure API keys for external integrations:

```bash
# Get API Gateway ID
API_ID=$(aws apigateway get-rest-apis \
  --query 'items[?contains(name, `honeypot`)].id' \
  --output text)

# Create usage plan and API key (done automatically via CDK)
echo "API Gateway ID: $API_ID"
```

### 3. SNS Topic Subscriptions

Configure SNS topic subscriptions for alerts:

```bash
# Subscribe to alerts topic
aws sns subscribe \
  --topic-arn arn:aws:sns:$AWS_REGION:$AWS_ACCOUNT_ID:ai-honeypot-system-alerts \
  --protocol email \
  --notification-endpoint your-email@company.com
```

### 4. CloudWatch Dashboards

Access the CloudWatch dashboard:

```bash
# Get dashboard URL from CDK outputs
DASHBOARD_URL=$(aws cloudformation describe-stacks \
  --stack-name HoneypotMonitoringStack \
  --query 'Stacks[0].Outputs[?OutputKey==`DashboardUrl`].OutputValue' \
  --output text)

echo "Dashboard URL: $DASHBOARD_URL"
```

## Environment-Specific Configurations

### Development Environment

```yaml
# config.yaml - dev section
dev:
  database:
    instance_type: "t3.medium"
    multi_az: false
    backup_retention_days: 7
  monitoring:
    log_retention_days: 30
```

### Staging Environment

```yaml
# config.yaml - staging section
staging:
  database:
    instance_type: "t3.large"
    multi_az: true
    backup_retention_days: 14
  monitoring:
    log_retention_days: 90
```

### Production Environment

```yaml
# config.yaml - prod section
prod:
  database:
    instance_type: "r5.xlarge"
    multi_az: true
    backup_retention_days: 30
  monitoring:
    log_retention_days: 365
```

## Monitoring and Maintenance

### Health Checks

Monitor deployment health:

```bash
# Run validation checks
python validate_deployment.py --region us-east-1

# Check CloudWatch alarms
aws cloudwatch describe-alarms --state-value ALARM

# Check RDS status
aws rds describe-db-instances --query 'DBInstances[?contains(DBInstanceIdentifier, `honeypot`)].DBInstanceStatus'
```

### Log Monitoring

Access system logs:

```bash
# View Lambda function logs
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/ai-honeypot"

# View RDS logs
aws rds describe-db-log-files --db-instance-identifier <db-identifier>

# View VPC Flow Logs
aws logs describe-log-groups --log-group-name-prefix "/aws/vpc/honeypot"
```

### Performance Monitoring

Monitor system performance:

```bash
# Check Lambda function metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=ai-honeypot-intelligence-processor \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average

# Check RDS metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name CPUUtilization \
  --dimensions Name=DBInstanceIdentifier,Value=<db-identifier> \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

## Troubleshooting

### Common Issues

#### 1. CDK Bootstrap Required

```bash
Error: Need to perform AWS CDK bootstrap
Solution: cdk bootstrap aws://$AWS_ACCOUNT_ID/$AWS_REGION
```

#### 2. Insufficient Permissions

```bash
Error: User is not authorized to perform action
Solution: Ensure IAM user has sufficient permissions for CDK deployment
```

#### 3. Resource Limits

```bash
Error: Limit exceeded for resource type
Solution: Request service quota increase or clean up unused resources
```

#### 4. Database Connection Issues

```bash
Error: Could not connect to database
Solution: 
- Check security groups allow connections
- Verify database is in available state
- Check credentials in Secrets Manager
```

### Debug Commands

```bash
# Check CDK diff
cdk diff --context environment=dev

# View CloudFormation events
aws cloudformation describe-stack-events --stack-name HoneypotNetworkStack

# Check Lambda function configuration
aws lambda get-function --function-name ai-honeypot-intelligence-processor

# Test database connectivity
python -c "
import psycopg2
conn = psycopg2.connect(
    host='$DB_ENDPOINT',
    database='honeypot_intelligence',
    user='honeypot_admin',
    password='$DB_PASSWORD'
)
print('Database connection successful')
"
```

## Cleanup and Destruction

### Complete Cleanup

Remove all resources:

```bash
python deploy_complete.py --action cleanup --environment dev --region us-east-1
```

### Manual Cleanup

Remove stacks in reverse order:

```bash
cdk destroy HoneypotIntegrationStack --force
cdk destroy HoneypotMonitoringStack --force
cdk destroy HoneypotDatabaseStack --force
cdk destroy HoneypotStorageStack --force
cdk destroy HoneypotSecurityStack --force
cdk destroy HoneypotNetworkStack --force
```

### Cleanup Verification

Verify all resources are removed:

```bash
# Check CloudFormation stacks
aws cloudformation list-stacks --stack-status-filter DELETE_COMPLETE

# Check S3 buckets
aws s3 ls | grep honeypot

# Check RDS instances
aws rds describe-db-instances --query 'DBInstances[?contains(DBInstanceIdentifier, `honeypot`)]'
```

## Security Considerations

### Network Security

- VPC with isolated subnets
- Security groups with minimal required access
- VPC Flow Logs enabled
- Network ACLs for additional protection

### Data Security

- Encryption at rest for all data stores
- Encryption in transit for all communications
- Secrets Manager for credential management
- IAM roles with least privilege access

### Monitoring Security

- CloudWatch alarms for security events
- SNS notifications for critical alerts
- Audit logging for all administrative actions
- Real-time monitoring of honeypot activities

## Cost Optimization

### Development Environment

- Use smaller instance types
- Disable Multi-AZ for RDS
- Shorter log retention periods
- Lifecycle policies for S3 storage

### Production Environment

- Reserved instances for predictable workloads
- Spot instances where appropriate
- Automated scaling policies
- Regular cost reviews and optimization

## Support and Maintenance

### Regular Tasks

1. **Weekly**: Review CloudWatch alarms and metrics
2. **Monthly**: Update Lambda function dependencies
3. **Quarterly**: Review and update security groups
4. **Annually**: Review and update retention policies

### Backup and Recovery

- RDS automated backups enabled
- S3 versioning and lifecycle policies
- Cross-region replication for critical data
- Disaster recovery procedures documented

### Updates and Patches

- Regular CDK and dependency updates
- Lambda runtime updates
- RDS engine updates during maintenance windows
- Security patch management

## Next Steps

After successful deployment:

1. **Deploy AgentCore Agents** (Task 12)
2. **Configure Honeypot Infrastructure**
3. **Set up External Integrations**
4. **Conduct End-to-End Testing**
5. **Implement Operational Procedures**

For detailed information on each component, refer to the individual stack documentation in the `cdk/stacks/` directory.