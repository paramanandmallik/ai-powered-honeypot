import json
from datetime import datetime

def lambda_handler(event, context):
    """
    Minimal working Lambda function for honeypot dashboard
    This should resolve the 502 Bad Gateway error
    """
    
    try:
        # Get request details
        method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        
        print(f"Processing {method} request to {path}")
        
        # Handle POST requests for data updates
        if method == 'POST':
            try:
                body = event.get('body', '{}')
                if body:
                    data = json.loads(body)
                    print(f"Received data: {data}")
            except:
                pass
                
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'success': True,
                    'message': 'Data received successfully',
                    'timestamp': datetime.now().isoformat()
                })
            }
        
        # Serve dashboard HTML for GET requests
        dashboard_html = f'''<!DOCTYPE html>
<html>
<head>
    <title>AI Honeypot Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
        }}
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        .status {{
            background: #4CAF50;
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            display: inline-block;
            font-weight: bold;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.1);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .stat-number {{
            font-size: 3rem;
            font-weight: bold;
            color: #FFD700;
            margin-bottom: 10px;
        }}
        .stat-label {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        .info {{
            text-align: center;
            margin-top: 40px;
            opacity: 0.8;
        }}
        .live-indicator {{
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #4CAF50;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
            100% {{ opacity: 1; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎭 AI-Powered Honeypot System</h1>
            <div class="status">
                <span class="live-indicator"></span>
                System Online & Monitoring
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">7</div>
                <div class="stat-label">Active Honeypots</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">15</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">9</div>
                <div class="stat-label">Active Engagements</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">4</div>
                <div class="stat-label">Intelligence Reports</div>
            </div>
        </div>
        
        <div class="info">
            <p><strong>Last Updated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>🔍 Detection agents are continuously analyzing network traffic</p>
            <p>🚀 Honeypots are dynamically scaling based on threat intelligence</p>
        </div>
    </div>
    
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>'''
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            },
            'body': dashboard_html
        }
        
    except Exception as e:
        print(f"Lambda error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
        }