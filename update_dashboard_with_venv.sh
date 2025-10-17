#!/bin/bash
# Update Dashboard Lambda Function using venv AWS CLI
# This updates the dashboard to accept real AgentCore data

echo "🚀 Updating Honeypot Dashboard Lambda Function"
echo "=============================================="

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Check AWS CLI
echo "✅ AWS CLI version:"
aws --version

# Check if credentials are configured
echo "🔐 Checking AWS credentials..."
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS credentials not configured."
    echo ""
    echo "Please configure AWS credentials first:"
    echo "1. Get your AWS credentials from AWS Console"
    echo "2. Run: aws configure"
    echo "   - AWS Access Key ID: [Your Access Key]"
    echo "   - AWS Secret Access Key: [Your Secret Key]"
    echo "   - Default region name: us-east-1"
    echo "   - Default output format: json"
    echo ""
    echo "Or set environment variables:"
    echo "export AWS_ACCESS_KEY_ID=your_access_key"
    echo "export AWS_SECRET_ACCESS_KEY=your_secret_key"
    echo "export AWS_DEFAULT_REGION=us-east-1"
    exit 1
fi

echo "✅ AWS credentials configured"
aws sts get-caller-identity

# Create deployment package
echo "📦 Creating deployment package..."
python3 deploy_dashboard_direct.py --create-zip

if [ ! -f "dashboard_update.zip" ]; then
    echo "❌ Failed to create deployment package"
    exit 1
fi

echo "✅ Deployment package created"

# Update Lambda function
FUNCTION_NAME="honeypot-dashboard"
echo "📤 Updating Lambda function: $FUNCTION_NAME"

aws lambda update-function-code \
    --function-name "$FUNCTION_NAME" \
    --zip-file fileb://dashboard_update.zip

if [ $? -eq 0 ]; then
    echo "✅ Lambda function updated successfully!"
    echo ""
    echo "🎉 Dashboard now supports real AgentCore data!"
    echo "📊 Dashboard URL: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod"
    echo ""
    echo "🧪 Testing the update..."
    python3 send_real_data_to_dashboard.py --single
    echo ""
    echo "🔄 Refresh your browser to see dynamic honeypot counts!"
else
    echo "❌ Failed to update Lambda function"
    echo "💡 Check the error message above for details"
fi

# Clean up
rm -f dashboard_update.zip
echo "🧹 Cleanup complete"