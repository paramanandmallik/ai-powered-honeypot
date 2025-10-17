#!/bin/bash
# Deploy the fixed Lambda function using AWS CLI

echo "🚀 Deploying fixed Lambda function..."

# Create zip file
zip -r lambda_function.zip fix_lambda_handler.py

# Update Lambda function
aws lambda update-function-code \
    --function-name honeypot-dashboard-function \
    --zip-file fileb://lambda_function.zip \
    --region us-east-1

if [ $? -eq 0 ]; then
    echo "✅ Lambda function updated successfully!"
    
    # Test the function
    echo "🧪 Testing Lambda function..."
    aws lambda invoke \
        --function-name honeypot-dashboard-function \
        --payload '{"httpMethod":"GET","path":"/"}' \
        --region us-east-1 \
        response.json
    
    echo "📄 Response:"
    cat response.json
    echo ""
    
    echo "✅ Dashboard should be working now!"
    echo "🌐 Visit: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod/"
else
    echo "❌ Failed to update Lambda function"
fi

# Clean up
rm -f lambda_function.zip response.json