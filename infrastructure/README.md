# AI Honeypot AgentCore Infrastructure

This directory contains the AWS infrastructure as code (IaC) for the AI Honeypot system built on Amazon AgentCore Runtime.

## Architecture Overview

The infrastructure consists of the following components:

### Core Stacks

1. **NetworkStack** - VPC, subnets, and network isolation
2. **SecurityStack** - IAM roles, security groups, and KMS keys
3. **DatabaseStack** - RDS PostgreSQL for intelligence data storage
4. **StorageStack** - S3 buckets for session data and audit logs
5. **MonitoringStack** - CloudWatch dashboards, alarms, and logging
6. **IntegrationStack** - SNS, Lambda, and API Gateway for external integrations

### Key Features

- **Network Isolation**: Separate subnets for AgentCore agents and honeypot infrastructure
- **Encryption**: KMS encryption for all data at rest and in transit
- **Monitoring**: Comprehensive CloudWatch monitoring and alerting
- **Compliance**: Audit logging and data retention policies
- **Scalability**: Auto-scaling and load balancing for high availability
- **Security**: Least privilege IAM policies and security groups

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **AWS CDK** installed (`npm install -g aws-cdk`)
3. **Python 3.11+** with pip
4. **Boto3** for AWS SDK access

## Quick Start

### 1. Install Dependencies

```bash
cd infrastructure/cdk
pip install -r requirements.txt
```

### 2. Configure Environment

Set your AWS account and region:

```bash
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION=us-east-1
```

### 3. Deploy Infrastructure

For development environment:

```bash
python ../deploy.py --action deploy --environment dev --region us-east-1
```

For production environment:

```bash
python ../deploy.py --action deploy --environment prod --region us-east-1
```

### 4. Verify Deployment

Check stack status:

```bash
python ../deploy.py --action list --environment dev
```

View differences:

```bash
python ../deploy.py --action diff --environment dev
```

## Deployment Commands

### Deploy All Stacks

```bash
python deploy.py --action deploy --environment dev
```

### Deploy Specific Stacks

```bash
python deploy.py --action deploy --environment dev --stacks HoneypotNetworkStack HoneypotDatabaseStack
```

### Validate Stacks

```bash
python deploy.py --action validate --environment dev
```

### Destroy Infrastructure

```bash
python deploy.py --action destroy --environment dev
```

## Environment Configuration

The infrastructure supports multiple environments with different configurations:

### Development (dev)
- Single AZ deployment
- Smaller instance sizes
- 7-day backup retention
- Cost-optimized settings

### Staging (staging)
- Multi-AZ deployment
- Medium instance sizes
- 14-day backup retention
- Production-like settings

### Production (prod)
- Multi-AZ deployment
- Large instance sizes
- 30-day backup retention
- High availability and performance

## Security Considerations

### Network Security
- VPC with isolated subnets
- Network ACLs for additional security
- VPC Flow Logs for monitoring
- No direct internet access for honeypots

### Data Security
- KMS encryption for all data
- Secrets Manager for credentials
- S3 bucket policies for access control
- Database encryption at rest

### Access Control
- Least privilege IAM policies
- Role-based access control
- API key authentication
- Security group restrictions

## Monitoring and Alerting

### CloudWatch Dashboards
- Agent health and performance
- Database metrics
- Security events
- System activity

### Alarms
- High error rates
- Database performance issues
- Security violations
- Real data detection

### Log Groups
- AgentCore Runtime logs
- Agent-specific logs
- Security audit logs
- Infrastructure logs

## Cost Optimization

### Lifecycle Policies
- S3 storage class transitions
- Automated data archival
- Log retention policies

### Resource Optimization
- Right-sized instances
- Spot instances (where appropriate)
- Reserved instances for production

## Troubleshooting

### Common Issues

1. **CDK Bootstrap Required**
   ```bash
   cdk bootstrap aws://ACCOUNT-ID/REGION
   ```

2. **Permission Denied**
   - Ensure AWS credentials have sufficient permissions
   - Check IAM policies for CDK deployment

3. **Stack Dependencies**
   - Deploy stacks in order: Network → Security → Database → Storage → Monitoring → Integration

4. **Resource Limits**
   - Check AWS service quotas
   - Request limit increases if needed

### Debugging

Enable CDK debug output:
```bash
export CDK_DEBUG=true
python deploy.py --action deploy --environment dev
```

View CloudFormation events:
```bash
aws cloudformation describe-stack-events --stack-name HoneypotNetworkStack
```

## Maintenance

### Regular Tasks

1. **Update Dependencies**
   ```bash
   pip install -r requirements.txt --upgrade
   ```

2. **Review Security Groups**
   - Audit security group rules quarterly
   - Remove unused rules

3. **Monitor Costs**
   - Review AWS Cost Explorer monthly
   - Optimize resource usage

4. **Update Configurations**
   - Review and update config.yaml
   - Test changes in development first

### Backup and Recovery

1. **Database Backups**
   - Automated daily backups
   - Point-in-time recovery available
   - Cross-region backup replication

2. **Configuration Backup**
   - Store CDK code in version control
   - Document configuration changes
   - Maintain deployment runbooks

## Support

For issues or questions:

1. Check CloudWatch logs for errors
2. Review CDK documentation
3. Contact the Security Team
4. Create support tickets for AWS issues

## References

- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
- [Amazon AgentCore Runtime](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-runtime.html)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [Infrastructure as Code Best Practices](https://docs.aws.amazon.com/whitepapers/latest/introduction-devops-aws/infrastructure-as-code.html)