#!/bin/bash

# AI-Powered Honeypot Dashboard - AWS Deployment Script
# This script deploys the dashboard to AWS Lambda with API Gateway

set -e

echo "🎭 Deploying AI-Powered Honeypot Dashboard to AWS..."
echo "=================================================="

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI is not installed. Please install it first."
    echo "   Visit: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
fi

# Check if SAM CLI is installed
if ! command -v sam &> /dev/null; then
    echo "❌ AWS SAM CLI is not installed. Please install it first."
    echo "   Visit: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html"
    exit 1
fi

# Check AWS credentials
echo "🔐 Checking AWS credentials..."
if ! aws sts get-caller-identity --profile mainkeys &> /dev/null; then
    echo "❌ AWS credentials not configured. Please run 'aws configure' first."
    exit 1
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --profile mainkeys --output text)
AWS_REGION=$(aws configure get region)
echo "✅ AWS Account: $AWS_ACCOUNT_ID"
echo "✅ AWS Region: $AWS_REGION"

# Set deployment parameters
STACK_NAME="honeypot-dashboard"
S3_BUCKET="honeypot-dashboard-deployment-$AWS_ACCOUNT_ID-$AWS_REGION"

echo ""
echo "📦 Deployment Configuration:"
echo "   Stack Name: $STACK_NAME"
echo "   S3 Bucket: $S3_BUCKET"
echo "   Region: $AWS_REGION"
echo ""

# Create S3 bucket for deployment artifacts if it doesn't exist
echo "🪣 Creating S3 bucket for deployment artifacts..."
if ! aws s3 ls "s3://$S3_BUCKET" 2>&1 | grep -q 'NoSuchBucket'; then
    echo "   Bucket already exists: $S3_BUCKET"
else
    if [ "$AWS_REGION" = "us-east-1" ]; then
        aws s3 mb "s3://$S3_BUCKET"
    else
        aws s3 mb "s3://$S3_BUCKET" --region "$AWS_REGION"
    fi
    echo "   ✅ Created bucket: $S3_BUCKET"
fi

# Build and deploy with SAM
echo ""
echo "🏗️  Building SAM application..."
sam build

echo ""
echo "🚀 Deploying to AWS..."
sam deploy \
    --stack-name "$STACK_NAME" \
    --s3-bucket "$S3_BUCKET" \
    --capabilities CAPABILITY_IAM \
    --region "$AWS_REGION" \
    --confirm-changeset \
    --no-fail-on-empty-changeset

# Get the deployed URL
echo ""
echo "📋 Getting deployment information..."
DASHBOARD_URL=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`HoneypotDashboardUrl`].OutputValue' \
    --output text)

echo ""
echo "🎉 Deployment Complete!"
echo "=================================================="
echo "📊 Dashboard URL: $DASHBOARD_URL"
echo "🌐 You can now access your AI-Powered Honeypot Dashboard at the URL above"
echo ""
echo "📝 Next Steps:"
echo "   1. Open the dashboard URL in your browser"
echo "   2. The dashboard will show simulated data for demonstration"
echo "   3. In production, connect it to your real AgentCore Runtime"
echo ""
echo "🔧 Management Commands:"
echo "   View logs: sam logs -n HoneypotDashboardFunction --stack-name $STACK_NAME --tail"
echo "   Update:    Re-run this script to deploy updates"
echo "   Delete:    aws cloudformation delete-stack --stack-name $STACK_NAME"
echo ""

# Save deployment info
cat > deployment-info.txt << EOF
AI-Powered Honeypot Dashboard - Deployment Information
=====================================================

Deployment Date: $(date)
AWS Account: $AWS_ACCOUNT_ID
AWS Region: $AWS_REGION
Stack Name: $STACK_NAME
S3 Bucket: $S3_BUCKET

Dashboard URL: $DASHBOARD_URL

Management Commands:
- View logs: sam logs -n HoneypotDashboardFunction --stack-name $STACK_NAME --tail
- Update: Re-run deploy.sh
- Delete: aws cloudformation delete-stack --stack-name $STACK_NAME
EOF

echo "💾 Deployment information saved to: deployment-info.txt"
