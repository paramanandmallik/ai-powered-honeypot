#!/bin/bash

# Fix API Gateway routes for honeypot dashboard
# Add missing API endpoints

API_ID="srms4z2ke7"
REGION="us-east-1"
PROFILE="mainkeys"
LAMBDA_ARN="arn:aws:lambda:us-east-1:962265335633:function:honeypot-dashboard-function"

echo "🔧 Adding missing API Gateway routes..."

# Get the /api resource ID
API_RESOURCE_ID=$(aws apigateway get-resources --rest-api-id $API_ID --region $REGION --profile $PROFILE --query 'items[?path==`/api`].id' --output text)
echo "API resource ID: $API_RESOURCE_ID"

# Function to create API endpoint
create_api_endpoint() {
    local endpoint_name=$1
    local method=$2
    
    echo "Creating /api/$endpoint_name endpoint..."
    
    # Create resource
    RESOURCE_ID=$(aws apigateway create-resource \
        --rest-api-id $API_ID \
        --parent-id $API_RESOURCE_ID \
        --path-part $endpoint_name \
        --region $REGION \
        --profile $PROFILE \
        --query 'id' --output text)
    
    if [ $? -eq 0 ]; then
        echo "✅ Created resource /api/$endpoint_name with ID: $RESOURCE_ID"
        
        # Create method
        aws apigateway put-method \
            --rest-api-id $API_ID \
            --resource-id $RESOURCE_ID \
            --http-method $method \
            --authorization-type NONE \
            --region $REGION \
            --profile $PROFILE
        
        # Set up integration
        aws apigateway put-integration \
            --rest-api-id $API_ID \
            --resource-id $RESOURCE_ID \
            --http-method $method \
            --type AWS_PROXY \
            --integration-http-method POST \
            --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
            --region $REGION \
            --profile $PROFILE
        
        echo "✅ Configured $method method for /api/$endpoint_name"
    else
        echo "❌ Failed to create resource /api/$endpoint_name"
    fi
}

# Create missing API endpoints
create_api_endpoint "status" "GET"
create_api_endpoint "threats" "GET"
create_api_endpoint "engagements" "GET"
create_api_endpoint "intelligence" "GET"
create_api_endpoint "detailed-intelligence" "GET"

# Deploy the API
echo "🚀 Deploying API changes..."
aws apigateway create-deployment \
    --rest-api-id $API_ID \
    --stage-name prod \
    --region $REGION \
    --profile $PROFILE

echo "✅ API Gateway routes updated successfully!"
echo "🌐 Dashboard URL: https://$API_ID.execute-api.$REGION.amazonaws.com/prod/"