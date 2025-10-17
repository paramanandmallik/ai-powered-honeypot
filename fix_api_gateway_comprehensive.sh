#!/bin/bash

# Comprehensive API Gateway Fix - Addresses 502 and 403 errors
echo "🔧 Starting comprehensive API Gateway fix..."

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

# Get current policy and remove any API Gateway permissions
echo "🔍 Checking current Lambda policy..."
POLICY=$(aws lambda get-policy --function-name $LAMBDA_FUNCTION --region $REGION --profile $PROFILE --query 'Policy' --output text 2>/dev/null || echo "{}")
if [ "$POLICY" != "{}" ]; then
    echo "📋 Current policy exists, checking for API Gateway permissions..."
fi

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

# Permission specifically for prod stage
aws lambda add-permission \
    --function-name $LAMBDA_FUNCTION \
    --statement-id apigateway-invoke-prod \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT_ID:$API_ID/prod/*" \
    --region $REGION \
    --profile $PROFILE

echo "✅ Lambda permissions added successfully"

# Get API Gateway details
echo "🔍 Getting API Gateway details..."
API_INFO=$(aws apigatewayv2 get-api --api-id $API_ID --profile $PROFILE --region $REGION)
if [ $? -ne 0 ]; then
    echo "❌ Failed to get API Gateway details"
    exit 1
fi

echo "📋 API Gateway Info:"
echo "$API_INFO" | jq '.Name, .ProtocolType, .RouteSelectionExpression'

# Get existing integrations
echo "🔍 Getting existing integrations..."
INTEGRATIONS=$(aws apigatewayv2 get-integrations --api-id $API_ID --profile $PROFILE --region $REGION)
INTEGRATION_ID=$(echo "$INTEGRATIONS" | jq -r '.Items[0].IntegrationId // empty')

if [ -z "$INTEGRATION_ID" ] || [ "$INTEGRATION_ID" = "null" ]; then
    echo "⚠️ No existing integration found, creating new one..."
    
    # Create new integration
    INTEGRATION_RESPONSE=$(aws apigatewayv2 create-integration \
        --api-id $API_ID \
        --integration-type AWS_PROXY \
        --integration-uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
        --payload-format-version "2.0" \
        --region $REGION \
        --profile $PROFILE)
    
    INTEGRATION_ID=$(echo "$INTEGRATION_RESPONSE" | jq -r '.IntegrationId')
    echo "🆕 Created new integration: $INTEGRATION_ID"
else
    echo "🔄 Updating existing integration: $INTEGRATION_ID"
    
    # Update existing integration
    aws apigatewayv2 update-integration \
        --api-id $API_ID \
        --integration-id $INTEGRATION_ID \
        --integration-uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
        --region $REGION \
        --profile $PROFILE
fi

if [ $? -ne 0 ]; then
    echo "❌ Failed to create/update integration"
    exit 1
fi

# Get existing routes
echo "🛣️ Checking routes..."
ROUTES=$(aws apigatewayv2 get-routes --api-id $API_ID --profile $PROFILE --region $REGION)
echo "📋 Current routes:"
echo "$ROUTES" | jq '.Items[] | {RouteKey, Target}'

# Ensure we have the necessary routes
ROUTE_KEYS=("ANY /" "ANY /prod" "ANY /prod/{proxy+}" "ANY /{proxy+}")

for ROUTE_KEY in "${ROUTE_KEYS[@]}"; do
    echo "🔍 Checking route: $ROUTE_KEY"
    
    EXISTING_ROUTE=$(echo "$ROUTES" | jq -r --arg key "$ROUTE_KEY" '.Items[] | select(.RouteKey == $key) | .RouteId')
    
    if [ -z "$EXISTING_ROUTE" ] || [ "$EXISTING_ROUTE" = "null" ]; then
        echo "➕ Creating route: $ROUTE_KEY"
        aws apigatewayv2 create-route \
            --api-id $API_ID \
            --route-key "$ROUTE_KEY" \
            --target "integrations/$INTEGRATION_ID" \
            --region $REGION \
            --profile $PROFILE
    else
        echo "🔄 Updating route: $ROUTE_KEY"
        aws apigatewayv2 update-route \
            --api-id $API_ID \
            --route-id "$EXISTING_ROUTE" \
            --target "integrations/$INTEGRATION_ID" \
            --region $REGION \
            --profile $PROFILE
    fi
done

# Check if prod stage exists
echo "🎭 Checking stages..."
STAGES=$(aws apigatewayv2 get-stages --api-id $API_ID --profile $PROFILE --region $REGION)
PROD_STAGE=$(echo "$STAGES" | jq -r '.Items[] | select(.StageName == "prod") | .StageName')

if [ -z "$PROD_STAGE" ] || [ "$PROD_STAGE" = "null" ]; then
    echo "➕ Creating prod stage..."
    aws apigatewayv2 create-stage \
        --api-id $API_ID \
        --stage-name prod \
        --auto-deploy \
        --region $REGION \
        --profile $PROFILE
else
    echo "✅ Prod stage exists"
fi

# Deploy API Gateway
echo "🚀 Deploying API Gateway..."
DEPLOYMENT_RESPONSE=$(aws apigatewayv2 create-deployment \
    --api-id $API_ID \
    --stage-name prod \
    --description "Comprehensive fix deployment $(date)" \
    --region $REGION \
    --profile $PROFILE)

if [ $? -ne 0 ]; then
    echo "❌ Failed to deploy API Gateway"
    exit 1
fi

echo "✅ Deployment successful:"
echo "$DEPLOYMENT_RESPONSE" | jq '.DeploymentId, .DeploymentStatus'

# Test the Lambda function directly
echo "🧪 Testing Lambda function directly..."
TEST_EVENT='{"httpMethod":"GET","path":"/","headers":{},"queryStringParameters":null,"body":null}'
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
aws apigatewayv2 get-api --api-id $API_ID --profile $PROFILE --region $REGION | jq '{Name, ApiEndpoint, ProtocolType}'

echo ""
echo "🎉 Comprehensive API Gateway fix completed!"
echo "🌐 Dashboard URL: https://$API_ID.execute-api.$REGION.amazonaws.com/prod/"
echo "🌐 Alternative URL: https://$API_ID.execute-api.$REGION.amazonaws.com/"
echo ""
echo "⏳ Wait 30-60 seconds for changes to propagate, then test both URLs"
echo "🔧 If issues persist, check CloudWatch logs for the Lambda function"