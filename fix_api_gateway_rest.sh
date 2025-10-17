#!/bin/bash

# Comprehensive REST API Gateway Fix - Addresses 502 and 403 errors
echo "🔧 Starting comprehensive REST API Gateway fix..."

# Configuration
API_ID="srms4z2ke7"
REGION="us-east-1"
LAMBDA_FUNCTION="honeypot-dashboard-function"
PROFILE="mainkeys"

echo "📡 API Gateway ID: $API_ID"
echo "🌍 Region: $REGION"
echo "⚡ Lambda Function: $LAMBDA_FUNCTION"
echo "🔑 AWS Profile: $PROFILE"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo "🐍 Activating virtual environment..."
    source venv/bin/activate
fi

# Get account ID
echo "🏢 Getting account ID..."
ACCOUNT_ID=$(aws sts get-caller-identity --profile $PROFILE --query 'Account' --output text)
if [ $? -ne 0 ]; then
    echo "❌ Failed to get account ID. Check AWS credentials."
    exit 1
fi
echo "🏢 Account ID: $ACCOUNT_ID"

# Get Lambda function details
echo "🔍 Getting Lambda function details..."
LAMBDA_ARN=$(aws lambda get-function --function-name $LAMBDA_FUNCTION --region $REGION --profile $PROFILE --query 'Configuration.FunctionArn' --output text)
if [ $? -ne 0 ]; then
    echo "❌ Failed to get Lambda function. Check function name and permissions."
    exit 1
fi
echo "🔗 Lambda ARN: $LAMBDA_ARN"

# Check Lambda function handler
HANDLER=$(aws lambda get-function --function-name $LAMBDA_FUNCTION --region $REGION --profile $PROFILE --query 'Configuration.Handler' --output text)
echo "🎯 Lambda Handler: $HANDLER"

# Remove ALL existing permissions (ignore errors)
echo "🗑️ Removing ALL existing Lambda permissions..."
STATEMENT_IDS=("apigateway-invoke" "apigateway-invoke-prod" "apigateway-invoke-all" "apigateway-test" "api-gateway-invoke")

for STATEMENT_ID in "${STATEMENT_IDS[@]}"; do
    echo "  Removing statement: $STATEMENT_ID"
    aws lambda remove-permission \
        --function-name $LAMBDA_FUNCTION \
        --statement-id "$STATEMENT_ID" \
        --region $REGION \
        --profile $PROFILE 2>/dev/null || true
done

# Add comprehensive Lambda permissions for API Gateway
echo "🔐 Adding comprehensive Lambda permissions..."

# Permission for all paths and methods
aws lambda add-permission \
    --function-name $LAMBDA_FUNCTION \
    --statement-id apigateway-invoke-all \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT_ID:$API_ID/*/*" \
    --region $REGION \
    --profile $PROFILE

if [ $? -ne 0 ]; then
    echo "❌ Failed to add Lambda permission"
    exit 1
fi

echo "✅ Lambda permissions added successfully"

# Get REST API Gateway details
echo "🔍 Getting REST API Gateway details..."
API_INFO=$(aws apigateway get-rest-api --rest-api-id $API_ID --profile $PROFILE --region $REGION)
if [ $? -ne 0 ]; then
    echo "❌ Failed to get API Gateway details"
    exit 1
fi

echo "📋 API Gateway Info:"
echo "$API_INFO" | jq '{name: .name, id: .id, endpointConfiguration: .endpointConfiguration}'

# Get resources
echo "🔍 Getting API Gateway resources..."
RESOURCES=$(aws apigateway get-resources --rest-api-id $API_ID --profile $PROFILE --region $REGION)
ROOT_RESOURCE_ID=$(echo "$RESOURCES" | jq -r '.items[] | select(.path == "/") | .id')
echo "🏠 Root Resource ID: $ROOT_RESOURCE_ID"

# Check if proxy resource exists
PROXY_RESOURCE=$(echo "$RESOURCES" | jq -r '.items[] | select(.pathPart == "{proxy+}") | .id')
if [ -z "$PROXY_RESOURCE" ] || [ "$PROXY_RESOURCE" = "null" ]; then
    echo "➕ Creating proxy resource..."
    PROXY_RESPONSE=$(aws apigateway create-resource \
        --rest-api-id $API_ID \
        --parent-id $ROOT_RESOURCE_ID \
        --path-part "{proxy+}" \
        --profile $PROFILE \
        --region $REGION)
    PROXY_RESOURCE_ID=$(echo "$PROXY_RESPONSE" | jq -r '.id')
    echo "🆕 Created proxy resource: $PROXY_RESOURCE_ID"
else
    PROXY_RESOURCE_ID=$PROXY_RESOURCE
    echo "✅ Proxy resource exists: $PROXY_RESOURCE_ID"
fi

# Create/Update ANY method on root resource
echo "🔧 Setting up ANY method on root resource..."
aws apigateway put-method \
    --rest-api-id $API_ID \
    --resource-id $ROOT_RESOURCE_ID \
    --http-method ANY \
    --authorization-type NONE \
    --profile $PROFILE \
    --region $REGION 2>/dev/null || echo "Method may already exist"

# Set up integration for root resource
echo "🔗 Setting up integration for root resource..."
aws apigateway put-integration \
    --rest-api-id $API_ID \
    --resource-id $ROOT_RESOURCE_ID \
    --http-method ANY \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
    --profile $PROFILE \
    --region $REGION

# Create/Update ANY method on proxy resource
echo "🔧 Setting up ANY method on proxy resource..."
aws apigateway put-method \
    --rest-api-id $API_ID \
    --resource-id $PROXY_RESOURCE_ID \
    --http-method ANY \
    --authorization-type NONE \
    --profile $PROFILE \
    --region $REGION 2>/dev/null || echo "Method may already exist"

# Set up integration for proxy resource
echo "🔗 Setting up integration for proxy resource..."
aws apigateway put-integration \
    --rest-api-id $API_ID \
    --resource-id $PROXY_RESOURCE_ID \
    --http-method ANY \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
    --profile $PROFILE \
    --region $REGION

# Deploy API Gateway
echo "🚀 Deploying API Gateway..."
DEPLOYMENT_RESPONSE=$(aws apigateway create-deployment \
    --rest-api-id $API_ID \
    --stage-name prod \
    --description "Comprehensive fix deployment $(date)" \
    --profile $PROFILE \
    --region $REGION)

if [ $? -ne 0 ]; then
    echo "❌ Failed to deploy API Gateway"
    exit 1
fi

echo "✅ Deployment successful:"
echo "$DEPLOYMENT_RESPONSE" | jq '{id: .id, createdDate: .createdDate}'

# Test the Lambda function directly
echo "🧪 Testing Lambda function directly..."
TEST_EVENT='{"httpMethod":"GET","path":"/","headers":{},"queryStringParameters":null,"body":null,"requestContext":{"httpMethod":"GET","path":"/"}}'
aws lambda invoke \
    --function-name $LAMBDA_FUNCTION \
    --payload "$TEST_EVENT" \
    --region $REGION \
    --profile $PROFILE \
    /tmp/lambda-test-response.json

if [ $? -eq 0 ]; then
    echo "✅ Lambda function test successful:"
    cat /tmp/lambda-test-response.json | jq '.'
else
    echo "❌ Lambda function test failed"
fi

# Final status check
echo "🔍 Final API Gateway status check..."
aws apigateway get-rest-api --rest-api-id $API_ID --profile $PROFILE --region $REGION | jq '{name: .name, id: .id, createdDate: .createdDate}'

echo ""
echo "🎉 Comprehensive REST API Gateway fix completed!"
echo "🌐 Dashboard URL: https://$API_ID.execute-api.$REGION.amazonaws.com/prod/"
echo "🌐 Alternative URL: https://$API_ID.execute-api.$REGION.amazonaws.com/"
echo ""
echo "⏳ Wait 30-60 seconds for changes to propagate, then test both URLs"
echo "🔧 If issues persist, check CloudWatch logs for the Lambda function"