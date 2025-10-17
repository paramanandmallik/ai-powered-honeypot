#!/usr/bin/env python3
"""
Direct Dashboard Deployment
Updates the AWS Lambda function directly without SAM CLI
"""

import json
import zipfile
import base64
import urllib.request
import urllib.parse
import os
import sys
from datetime import datetime

def create_lambda_zip():
    """Create a zip file for Lambda deployment"""
    print("📦 Creating Lambda deployment package...")
    
    # Read the modified dashboard code
    with open('dashboard_with_real_data.py', 'r') as f:
        dashboard_code = f.read()
    
    # Create a temporary lambda_function.py (AWS Lambda expects this name)
    with open('lambda_function.py', 'w') as f:
        f.write(dashboard_code)
    
    # Create zip file
    with zipfile.ZipFile('dashboard_update.zip', 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write('lambda_function.py')
    
    # Clean up temporary file
    os.remove('lambda_function.py')
    
    print("✅ Lambda package created: dashboard_update.zip")
    return 'dashboard_update.zip'

def get_lambda_function_name():
    """Try to determine the Lambda function name"""
    # Common patterns for the dashboard Lambda function
    possible_names = [
        "ai-honeypot-dashboard",
        "honeypot-dashboard", 
        "dashboard-function",
        "ai-honeypot-system-dashboard"
    ]
    
    print("🔍 Possible Lambda function names:")
    for i, name in enumerate(possible_names, 1):
        print(f"   {i}. {name}")
    
    return possible_names

def create_aws_cli_update_script():
    """Create a script to update Lambda using AWS CLI"""
    script_content = '''#!/bin/bash
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

# Check if user is authenticated
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS credentials not configured. Please run:"
    echo "   aws configure"
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
    
    if aws lambda get-function --function-name "$FUNCTION_NAME" &> /dev/null; then
        echo "✅ Found Lambda function: $FUNCTION_NAME"
        echo "📤 Updating function code..."
        
        aws lambda update-function-code \\
            --function-name "$FUNCTION_NAME" \\
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
'''
    
    with open('update_dashboard_lambda.sh', 'w') as f:
        f.write(script_content)
    
    os.chmod('update_dashboard_lambda.sh', 0o755)
    print("✅ Created update script: update_dashboard_lambda.sh")

def create_manual_instructions():
    """Create manual deployment instructions"""
    instructions = f"""
# Manual Dashboard Update Instructions
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

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
aws lambda update-function-code \\
    --function-name YOUR_FUNCTION_NAME \\
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
"""
    
    with open('DASHBOARD_UPDATE_INSTRUCTIONS.md', 'w') as f:
        f.write(instructions)
    
    print("✅ Created manual instructions: DASHBOARD_UPDATE_INSTRUCTIONS.md")

def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] == '--create-zip':
        # Just create the zip file
        create_lambda_zip()
        return
    
    print("🚀 Dashboard Direct Deployment Setup")
    print("=" * 50)
    
    # Check if required files exist
    if not os.path.exists('dashboard_with_real_data.py'):
        print("❌ dashboard_with_real_data.py not found")
        print("   Please ensure the file exists in the current directory")
        return
    
    # Create deployment package
    zip_file = create_lambda_zip()
    
    # Create AWS CLI update script
    create_aws_cli_update_script()
    
    # Create manual instructions
    create_manual_instructions()
    
    print("\n🎯 Next Steps:")
    print("1. Install AWS CLI if not already installed:")
    print("   brew install awscli")
    print("")
    print("2. Run the automated update script:")
    print("   ./update_dashboard_lambda.sh")
    print("")
    print("3. Or follow manual instructions in:")
    print("   DASHBOARD_UPDATE_INSTRUCTIONS.md")
    print("")
    print("4. After update, test with:")
    print("   python3 send_real_data_to_dashboard.py --single")

if __name__ == "__main__":
    main()