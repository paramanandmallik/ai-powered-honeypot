#!/bin/bash

# Fix API Gateway configuration
echo "🔧 Fixing API Gateway configuration..."

# Get API Gateway ID
API_ID="srms4z2ke7"
REGION="us-east-1"
LAMBDA_FUNCTION="honeypot-dashboard-function"

echo "📡 API Gateway ID: $API_ID"
echo "🌍 Region: $REGION"
echo "⚡ Lambda Function: $LAMBDA_FUNCTION"

# Get Lambda function ARN
LAMBDA_ARN=$(aws lambda get-function --function-name $LAMBDA_FUNCTION --region $REGION --profile mainkeys --query 'Configuration.FunctionArn' --output text)
echo "🔗 Lambda ARN: $LAMBDA_ARN"

# Add Lambda permission for API Gateway
echo "🔐 Adding Lambda permission for API Gateway..."
aws lambda add-permission \
    --function-name $LAMBDA_FUNCTION \
    --statement-id apigateway-invoke \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:$REGION:*:$API_ID/*/*" \
    --region $REGION \
    --profile mainkeys

# Update API Gateway integration
echo "🔄 Updating API Gateway integration..."
aws apigatewayv2 update-integration \
    --api-id $API_ID \
    --integration-id $(aws apigatewayv2 get-integrations --api-id $API_ID --profile mainkeys --query 'Items[0].IntegrationId' --output text) \
    --integration-uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
    --region $REGION \
    --profile mainkeys

# Deploy API Gateway
echo "🚀 Deploying API Gateway..."
aws apigatewayv2 create-deployment \
    --api-id $API_ID \
    --stage-name prod \
    --region $REGION \
    --profile mainkeys

echo "✅ API Gateway configuration fixed!"
echo "🌐 Test URL: https://$API_ID.execute-api.$REGION.amazonaws.com/prod/"