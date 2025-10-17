#!/bin/bash
# AWS Lambda Update Script
# Updates the dashboard Lambda function with real data integration

echo "🚀 Updating AI-Powered Honeypot Dashboard Lambda Function"
echo "========================================================="

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI is not installed. Please install it first:"
    echo "   brew install awscli"
    echo "   # or"
    echo "   pip install awscli"
    exit 1
fi

# Check if user is authenticated with mainkeys profile
if ! aws sts get-caller-identity --profile mainkeys &> /dev/null; then
    echo "❌ AWS mainkeys profile not configured. Please run:"
    echo "   aws configure --profile mainkeys"
    exit 1
fi

echo "✅ AWS CLI is ready"

# Create the deployment package
echo "📦 Creating deployment package..."
python3 deploy_dashboard_direct.py --create-zip

if [ ! -f "dashboard_update.zip" ]; then
    echo "❌ Failed to create deployment package"
    exit 1
fi

echo "✅ Deployment package created"

# Try to find and update the Lambda function
FUNCTION_NAMES=(
    "ai-honeypot-dashboard"
    "honeypot-dashboard" 
    "dashboard-function"
    "ai-honeypot-system-dashboard"
)

FUNCTION_FOUND=false

for FUNCTION_NAME in "${FUNCTION_NAMES[@]}"; do
    echo "🔍 Checking for Lambda function: $FUNCTION_NAME"
    
    if aws lambda get-function --function-name "$FUNCTION_NAME" --profile mainkeys &> /dev/null; then
        echo "✅ Found Lambda function: $FUNCTION_NAME"
        echo "📤 Updating function code..."
        
        aws lambda update-function-code \
            --function-name "$FUNCTION_NAME" \
            --zip-file fileb://dashboard_update.zip
        
        if [ $? -eq 0 ]; then
            echo "✅ Lambda function updated successfully!"
            echo "🔄 Dashboard should now accept real data from AgentCore"
            echo ""
            echo "📊 Dashboard URL: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod"
            echo ""
            FUNCTION_FOUND=true
            break
        else
            echo "❌ Failed to update Lambda function: $FUNCTION_NAME"
        fi
    fi
done

if [ "$FUNCTION_FOUND" = false ]; then
    echo "❌ Could not find the dashboard Lambda function"
    echo "💡 Please check the AWS Console for the correct function name"
    echo ""
    echo "🔍 You can list all Lambda functions with:"
    echo "   aws lambda list-functions --query 'Functions[].FunctionName'"
    echo ""
    echo "📝 Then update manually with:"
    echo "   aws lambda update-function-code --function-name YOUR_FUNCTION_NAME --zip-file fileb://dashboard_update.zip"
fi

# Clean up
rm -f dashboard_update.zip
echo "🧹 Cleanup complete"
