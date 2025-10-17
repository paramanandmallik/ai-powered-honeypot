
# Manual Dashboard Update Instructions
Generated: 2025-10-17 23:16:09

## Problem
The current dashboard generates static/fake data internally and doesn't accept real data from AgentCore agents.

## Solution
Replace the dashboard Lambda function with a version that accepts real AgentCore data.

## Steps

### 1. Install AWS CLI (if not already installed)
```bash
# macOS
brew install awscli

# or using pip
pip install awscli
```

### 2. Configure AWS credentials
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and region
```

### 3. Find your Lambda function name
```bash
aws lambda list-functions --query 'Functions[].FunctionName' | grep -i dashboard
```

### 4. Update the Lambda function
```bash
# Create deployment package
python3 deploy_dashboard_direct.py --create-zip

# Update Lambda function (replace YOUR_FUNCTION_NAME with actual name)
aws lambda update-function-code \
    --function-name YOUR_FUNCTION_NAME \
    --zip-file fileb://dashboard_update.zip
```

### 5. Test the updated dashboard
```bash
# Send real data to the updated dashboard
python3 send_real_data_to_dashboard.py --single
```

## Expected Result
After updating, the dashboard will:
- ✅ Accept real data from AgentCore agents
- ✅ Show dynamic honeypot counts that change over time
- ✅ Display real-time metrics instead of static fake data

## Dashboard URL
https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod

## Troubleshooting
If the update fails:
1. Check AWS credentials: `aws sts get-caller-identity`
2. Verify Lambda function name: `aws lambda list-functions`
3. Check permissions: Ensure you have lambda:UpdateFunctionCode permission
