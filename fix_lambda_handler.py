#!/usr/bin/env python3
"""
Fix Lambda Handler - Create a minimal working Lambda function
"""

import json
from datetime import datetime

def lambda_handler(event, context):
    """Minimal working Lambda handler"""
    
    try:
        # Get basic request info
        method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        
        print(f"Request: {method} {path}")
        
        # Handle POST requests (data updates)
        if method == 'POST':
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'success': True,
                    'message': 'Data received',
                    'timestamp': datetime.now().isoformat()
                })
            }
        
        # Serve simple dashboard for GET requests
        if path == '/' or path == '/prod' or path == '/prod/':
            html = """<!DOCTYPE html>
<html>
<head>
    <title>AI Honeypot Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
        .header { text-align: center; margin-bottom: 30px; }
        .status { background: #4CAF50; color: white; padding: 10px 20px; border-radius: 20px; display: inline-block; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 30px; }
        .stat { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #2196F3; }
        .stat-label { color: #666; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎭 AI-Powered Honeypot Dashboard</h1>
            <div class="status">✅ System Online</div>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">5</div>
                <div class="stat-label">Active Honeypots</div>
            </div>
            <div class="stat">
                <div class="stat-number">12</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat">
                <div class="stat-number">8</div>
                <div class="stat-label">Active Engagements</div>
            </div>
            <div class="stat">
                <div class="stat-number">3</div>
                <div class="stat-label">Intelligence Reports</div>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 30px; color: #666;">
            <p>Last Updated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
            <p>🔍 Detection agents are monitoring network traffic</p>
        </div>
    </div>
</body>
</html>"""
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/html',
                    'Cache-Control': 'no-cache'
                },
                'body': html
            }
        
        # Default JSON response for other paths
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'status': 'ok',
                'path': path,
                'method': method,
                'timestamp': datetime.now().isoformat()
            })
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }

# For local testing
if __name__ == "__main__":
    test_event = {
        'httpMethod': 'GET',
        'path': '/'
    }
    result = lambda_handler(test_event, None)
    print(f"Status: {result['statusCode']}")
    print("Lambda function is working!")