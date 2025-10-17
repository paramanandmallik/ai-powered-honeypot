#!/bin/bash

# AWS CloudFormation Deployment Script for AI-Powered Honeypot Dashboard
# Simple wrapper for the Python deployment script

echo "🚀 AI-Powered Honeypot Dashboard - CloudFormation Deployment"
echo "============================================================"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if AWS CLI is available
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI is required but not installed"
    echo "Please install AWS CLI: https://aws.amazon.com/cli/"
    exit 1
fi

# Check if boto3 is available
if ! python3 -c "import boto3" 2>/dev/null; then
    echo "📦 Installing boto3..."
    pip3 install boto3
fi

# Run the deployment
echo "🏗️ Starting CloudFormation deployment..."
python3 deploy_cloudformation.py

echo ""
echo "🎯 Deployment script completed!"