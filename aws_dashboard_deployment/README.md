# AI-Powered Honeypot Dashboard - AWS Deployment

This directory contains everything needed to deploy the AI-Powered Honeypot Dashboard to AWS Lambda with a public URL.

## 🚀 Quick Deployment

### Prerequisites

1. **AWS CLI** - [Install Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
2. **AWS SAM CLI** - [Install Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
3. **AWS Account** with appropriate permissions

### Setup AWS Credentials

```bash
# Configure AWS credentials
aws configure

# Verify credentials
aws sts get-caller-identity
```

### Deploy Dashboard

```bash
# Navigate to deployment directory
cd ai-honeypot-agentcore/aws_dashboard_deployment

# Run deployment script
./deploy.sh
```

The script will:
1. ✅ Check prerequisites
2. 🪣 Create S3 bucket for deployment
3. 🏗️ Build the SAM application
4. 🚀 Deploy to AWS Lambda + API Gateway
5. 📊 Provide public dashboard URL

## 📊 Dashboard Features

### Enhanced Intelligence Reports
- **Detailed Analysis**: Complete threat campaign analysis
- **MITRE ATT&CK Mapping**: Technique identification and classification
- **IOC Extraction**: Comprehensive indicators of compromise
- **Threat Actor Profiling**: Sophistication and attribution analysis
- **Attack Timeline**: Chronological attack progression

### Honeypot Infrastructure Details
- **Resource Information**: Instance IDs, IP addresses, ports
- **Real-time Status**: Active/standby status monitoring
- **Engagement Tracking**: Current attacker sessions
- **Resource Utilization**: Performance and capacity metrics

### Live Monitoring
- **Real-time Updates**: Auto-refresh every 10 seconds
- **System Health**: Agent status and performance
- **Threat Detection**: Live threat feed processing
- **Intelligence Generation**: Automated report creation

## 🌐 Accessing Your Dashboard

After deployment, you'll receive a public URL like:
```
https://abc123def456.execute-api.us-west-2.amazonaws.com/Prod/
```

### Dashboard Sections

1. **System Status** - Agent health and connectivity
2. **Live Metrics** - Real-time threat and engagement counts
3. **Honeypot Infrastructure** - Detailed resource information
4. **Recent Threats** - Latest detected threats with confidence scores
5. **Active Engagements** - Current attacker interactions
6. **Intelligence Reports** - Summary intelligence analysis
7. **Detailed Intelligence** - Comprehensive threat analysis

## 🔧 Management Commands

### View Logs
```bash
sam logs -n HoneypotDashboardFunction --stack-name honeypot-dashboard --tail
```

### Update Dashboard
```bash
# Make changes to app.py, then redeploy
./deploy.sh
```

### Delete Deployment
```bash
aws cloudformation delete-stack --stack-name honeypot-dashboard
```

## 🎭 Demo vs Production

### Current Demo Mode
- Shows simulated threat data
- Demonstrates system capabilities
- No real AgentCore Runtime connection
- Perfect for presentations and testing

### Production Integration
To connect to real AgentCore Runtime:

1. **Update API endpoints** in `app.py`
2. **Add authentication** for AgentCore APIs
3. **Configure VPC access** if needed
4. **Set environment variables** for production endpoints

Example production configuration:
```python
# In app.py, replace mock data with real API calls
AGENTCORE_ENDPOINT = os.environ.get('AGENTCORE_ENDPOINT')
API_KEY = os.environ.get('AGENTCORE_API_KEY')

# Real API call example
async def get_real_threats():
    response = requests.get(f"{AGENTCORE_ENDPOINT}/api/threats", 
                          headers={"Authorization": f"Bearer {API_KEY}"})
    return response.json()
```

## 💰 Cost Estimation

AWS Lambda pricing (approximate):
- **Requests**: $0.20 per 1M requests
- **Duration**: $0.0000166667 per GB-second
- **API Gateway**: $3.50 per million API calls

For a demo dashboard with moderate usage:
- **Monthly cost**: ~$1-5 USD
- **Free tier eligible** for new AWS accounts

## 🔒 Security Considerations

### Current Security
- ✅ HTTPS enabled by default
- ✅ CORS configured
- ✅ No sensitive data exposure
- ✅ Serverless isolation

### Production Security
For production deployment, consider:
- 🔐 API authentication/authorization
- 🌐 VPC integration for private resources
- 📊 CloudWatch monitoring and alerting
- 🛡️ WAF protection for API Gateway

## 🆘 Troubleshooting

### Common Issues

**Deployment fails with permissions error:**
```bash
# Ensure your AWS user has these permissions:
# - CloudFormation full access
# - Lambda full access
# - API Gateway full access
# - S3 full access
# - IAM role creation
```

**Dashboard shows "Loading..." forever:**
- Check browser console for errors
- Verify API Gateway endpoints are accessible
- Check Lambda function logs

**SAM CLI not found:**
```bash
# Install SAM CLI
pip install aws-sam-cli
# or
brew install aws-sam-cli
```

### Getting Help

1. Check CloudFormation stack events in AWS Console
2. View Lambda function logs in CloudWatch
3. Test API endpoints directly in browser
4. Verify AWS credentials and permissions

## 📞 Support

For issues with this deployment:
1. Check the troubleshooting section above
2. Review AWS CloudFormation stack events
3. Examine Lambda function logs in CloudWatch
4. Verify all prerequisites are installed correctly