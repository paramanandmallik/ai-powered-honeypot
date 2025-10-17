#!/usr/bin/env python3
"""
Deploy the working Lambda function to AWS
"""

import boto3
import zipfile
import os
import json

def deploy_lambda():
    """Deploy the working lambda function"""
    
    # Create a zip file with the lambda function
    with zipfile.ZipFile('lambda_function.zip', 'w') as zip_file:
        zip_file.write('lambda_function.py')
    
    # Initialize AWS Lambda client
    session = boto3.Session(profile_name='mainkeys')
    lambda_client = session.client('lambda', region_name='us-east-1')
    
    try:
        # Read the zip file
        with open('lambda_function.zip', 'rb') as zip_file:
            zip_content = zip_file.read()
        
        # Update the Lambda function
        response = lambda_client.update_function_code(
            FunctionName='honeypot-dashboard-function',
            ZipFile=zip_content
        )
        
        print("✅ Lambda function updated successfully!")
        print(f"Function ARN: {response['FunctionArn']}")
        print(f"Last Modified: {response['LastModified']}")
        
        # Clean up
        os.remove('lambda_function.zip')
        
        return True
        
    except Exception as e:
        print(f"❌ Error updating Lambda function: {e}")
        # Clean up on error
        if os.path.exists('lambda_function.zip'):
            os.remove('lambda_function.zip')
        return False

def test_lambda():
    """Test the deployed lambda function"""
    session = boto3.Session(profile_name='mainkeys')
    lambda_client = session.client('lambda', region_name='us-east-1')
    
    try:
        # Test with a GET request
        test_event = {
            'httpMethod': 'GET',
            'path': '/'
        }
        
        response = lambda_client.invoke(
            FunctionName='honeypot-dashboard-function',
            Payload=json.dumps(test_event)
        )
        
        result = json.loads(response['Payload'].read())
        
        if result.get('statusCode') == 200:
            print("✅ Lambda function test successful!")
            return True
        else:
            print(f"❌ Lambda function test failed: {result}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing Lambda function: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Deploying working Lambda function...")
    
    if deploy_lambda():
        print("\n🧪 Testing deployed function...")
        test_lambda()
        print("\n✅ Deployment complete! Dashboard should be working now.")
        print("🌐 Visit your API Gateway URL to see the dashboard")
    else:
        print("❌ Deployment failed!")