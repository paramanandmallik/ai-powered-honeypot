#!/usr/bin/env python3
"""
Fix Dashboard API 404 Error
This script tests and fixes the API Gateway routing issue for the dashboard
"""

import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

# Dashboard configuration
DASHBOARD_URL = "https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod"

def test_lambda_function_directly():
    """Test the Lambda function directly using AWS CLI"""
    print("🔧 Testing Lambda function directly...")
    
    # Create test payload
    test_payload = {
        "httpMethod": "POST",
        "path": "/api/update",
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "timestamp": datetime.now().isoformat(),
            "source": "test",
            "active_honeypots": 5,
            "total_attacks": 3,
            "total_engagements": 2,
            "honeypots": [
                {
                    "id": "test_hp_1",
                    "type": "web_application",
                    "status": "active",
                    "source_ip": "192.168.1.100"
                }
            ]
        })
    }
    
    # Save payload to file
    with open("lambda_test_payload.json", "w") as f:
        json.dump(test_payload, f, indent=2)
    
    print("✅ Test payload created: lambda_test_payload.json")
    print("🚀 Run this command to test Lambda directly:")
    print("   aws lambda invoke --function-name ai-honeypot-system-dashboard --payload file://lambda_test_payload.json --profile mainkeys lambda_response.json")
    
    return test_payload

def test_api_endpoints():
    """Test different API endpoints to see which ones work"""
    print("\n🔍 Testing API Gateway endpoints...")
    
    endpoints_to_test = [
        "/",
        "/api/status", 
        "/api/update",
        "/api/metrics",
        "/api/honeypots",
        "/api/threats",
        "/api/engagements"
    ]
    
    working_endpoints = []
    failing_endpoints = []
    
    for endpoint in endpoints_to_test:
        try:
            url = f"{DASHBOARD_URL}{endpoint}"
            print(f"Testing: {url}")
            
            if endpoint == "/api/update":
                # POST request with data
                headers = {'Content-Type': 'application/json'}
                data = json.dumps({"test": "data"}).encode('utf-8')
                req = urllib.request.Request(url, data=data, headers=headers)
                req.get_method = lambda: 'POST'
            else:
                # GET request
                req = urllib.request.Request(url)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                status = response.status
                if status == 200:
                    print(f"  ✅ {endpoint} - HTTP {status}")
                    working_endpoints.append(endpoint)
                else:
                    print(f"  ⚠️  {endpoint} - HTTP {status}")
                    
        except urllib.error.HTTPError as e:
            print(f"  ❌ {endpoint} - HTTP {e.code}")
            failing_endpoints.append((endpoint, e.code))
        except Exception as e:
            print(f"  ❌ {endpoint} - Error: {e}")
            failing_endpoints.append((endpoint, str(e)))
    
    print(f"\n📊 Results:")
    print(f"  Working endpoints: {working_endpoints}")
    print(f"  Failing endpoints: {[ep[0] for ep in failing_endpoints]}")
    
    return working_endpoints, failing_endpoints

def create_api_gateway_fix_script():
    """Create a script to fix API Gateway configuration"""
    fix_script = '''#!/bin/bash
# Fix API Gateway Configuration for Dashboard
# This script adds the missing /api/update route to API Gateway

echo "🔧 Fixing API Gateway configuration..."

# Get the API Gateway ID
API_ID=$(aws apigateway get-rest-apis --profile mainkeys --query 'items[?name==`ai-honeypot-system-dashboard`].id' --output text)

if [ -z "$API_ID" ]; then
    echo "❌ Could not find API Gateway for dashboard"
    exit 1
fi

echo "✅ Found API Gateway ID: $API_ID"

# Get the root resource ID
ROOT_RESOURCE_ID=$(aws apigateway get-resources --rest-api-id $API_ID --profile mainkeys --query 'items[?path==`/`].id' --output text)

echo "✅ Root resource ID: $ROOT_RESOURCE_ID"

# Check if /api resource exists
API_RESOURCE_ID=$(aws apigateway get-resources --rest-api-id $API_ID --profile mainkeys --query 'items[?pathPart==`api`].id' --output text)

if [ -z "$API_RESOURCE_ID" ]; then
    echo "🚀 Creating /api resource..."
    API_RESOURCE_ID=$(aws apigateway create-resource --rest-api-id $API_ID --parent-id $ROOT_RESOURCE_ID --path-part api --profile mainkeys --query 'id' --output text)
    echo "✅ Created /api resource: $API_RESOURCE_ID"
else
    echo "✅ /api resource exists: $API_RESOURCE_ID"
fi

# Check if /api/update resource exists
UPDATE_RESOURCE_ID=$(aws apigateway get-resources --rest-api-id $API_ID --profile mainkeys --query 'items[?pathPart==`update`].id' --output text)

if [ -z "$UPDATE_RESOURCE_ID" ]; then
    echo "🚀 Creating /api/update resource..."
    UPDATE_RESOURCE_ID=$(aws apigateway create-resource --rest-api-id $API_ID --parent-id $API_RESOURCE_ID --path-part update --profile mainkeys --query 'id' --output text)
    echo "✅ Created /api/update resource: $UPDATE_RESOURCE_ID"
else
    echo "✅ /api/update resource exists: $UPDATE_RESOURCE_ID"
fi

# Add POST method to /api/update
echo "🚀 Adding POST method to /api/update..."
aws apigateway put-method --rest-api-id $API_ID --resource-id $UPDATE_RESOURCE_ID --http-method POST --authorization-type NONE --profile mainkeys

# Get Lambda function ARN
LAMBDA_ARN=$(aws lambda get-function --function-name ai-honeypot-system-dashboard --profile mainkeys --query 'Configuration.FunctionArn' --output text)
echo "✅ Lambda ARN: $LAMBDA_ARN"

# Set up Lambda integration
echo "🚀 Setting up Lambda integration..."
aws apigateway put-integration --rest-api-id $API_ID --resource-id $UPDATE_RESOURCE_ID --http-method POST --type AWS_PROXY --integration-http-method POST --uri "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" --profile mainkeys

# Add Lambda permission for API Gateway
echo "🚀 Adding Lambda permission for API Gateway..."
aws lambda add-permission --function-name ai-honeypot-system-dashboard --statement-id apigateway-invoke-update --action lambda:InvokeFunction --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:us-east-1:*:$API_ID/*/POST/api/update" --profile mainkeys

# Deploy the API
echo "🚀 Deploying API changes..."
aws apigateway create-deployment --rest-api-id $API_ID --stage-name prod --profile mainkeys

echo "✅ API Gateway configuration fixed!"
echo "🔗 Test URL: https://$API_ID.execute-api.us-east-1.amazonaws.com/prod/api/update"
'''
    
    with open("fix_api_gateway.sh", "w") as f:
        f.write(fix_script)
    
    print("✅ Created API Gateway fix script: fix_api_gateway.sh")
    print("🚀 Run: chmod +x fix_api_gateway.sh && ./fix_api_gateway.sh")

def create_simple_dashboard_test():
    """Create a simple test to verify dashboard works after fix"""
    test_script = '''#!/usr/bin/env python3
"""
Test Dashboard API After Fix
"""

import json
import urllib.request
from datetime import datetime

DASHBOARD_URL = "https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod"

def test_dashboard_api():
    """Test the fixed dashboard API"""
    print("🧪 Testing fixed dashboard API...")
    
    # Test data
    test_data = {
        "timestamp": datetime.now().isoformat(),
        "source": "test_fix",
        "active_honeypots": 3,
        "total_attacks": 2,
        "total_engagements": 1,
        "honeypots": [
            {
                "id": "test_hp_fixed",
                "type": "web_application", 
                "status": "active",
                "source_ip": "192.168.1.200"
            }
        ],
        "threats": [
            {
                "id": "test_threat",
                "type": "SQL Injection",
                "source_ip": "192.168.1.200",
                "confidence": 0.95
            }
        ]
    }
    
    try:
        url = f"{DASHBOARD_URL}/api/update"
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'DashboardTester/1.0'
        }
        
        request_data = json.dumps(test_data).encode('utf-8')
        req = urllib.request.Request(url, data=request_data, headers=headers)
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                response_data = response.read().decode()
                print("✅ Dashboard API is working!")
                print(f"   Response: {response_data}")
                return True
            else:
                print(f"⚠️  Dashboard returned HTTP {response.status}")
                
    except Exception as e:
        print(f"❌ Dashboard test failed: {e}")
        
    return False

if __name__ == "__main__":
    test_dashboard_api()
'''
    
    with open("test_dashboard_fix.py", "w") as f:
        f.write(test_script)
    
    print("✅ Created dashboard test script: test_dashboard_fix.py")

def main():
    """Main function to diagnose and fix the 404 issue"""
    print("🔧 Dashboard API 404 Fix Tool")
    print("=" * 50)
    
    # Test Lambda function directly
    test_lambda_function_directly()
    
    # Test API Gateway endpoints
    working, failing = test_api_endpoints()
    
    # Create fix scripts
    create_api_gateway_fix_script()
    create_simple_dashboard_test()
    
    print(f"\n🎯 Next Steps:")
    print(f"1. Test Lambda directly: aws lambda invoke --function-name ai-honeypot-system-dashboard --payload file://lambda_test_payload.json --profile mainkeys lambda_response.json")
    print(f"2. Fix API Gateway: chmod +x fix_api_gateway.sh && ./fix_api_gateway.sh")
    print(f"3. Test the fix: python3 test_dashboard_fix.py")
    print(f"4. Run detection demo again: python3 run_detection_agent_demo.py")

if __name__ == "__main__":
    main()