import json
from datetime import datetime

# Global data store
DASHBOARD_DATA = {
    "honeypots": [],
    "attacks": 0,
    "engagements": 0,
    "intelligence_reports": [],
    "threats": [],
    "active_engagements": []
}

def lambda_handler(event, context):
    """Simple Lambda handler that works"""
    global DASHBOARD_DATA
    
    try:
        # Get HTTP method and path
        method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        
        print(f"Request: {method} {path}")
        
        # Handle /api/update POST requests
        if path == '/api/update' and method == 'POST':
            # Parse body
            body = event.get('body', '{}')
            if isinstance(body, str):
                data = json.loads(body)
            else:
                data = body
            
            # Update dashboard data
            if 'active_honeypots' in data:
                DASHBOARD_DATA['honeypots'] = data.get('honeypots', [])
            if 'total_attacks' in data:
                DASHBOARD_DATA['attacks'] = data['total_attacks']
            if 'total_engagements' in data:
                DASHBOARD_DATA['engagements'] = data['total_engagements']
            if 'threats' in data:
                DASHBOARD_DATA['threats'] = data['threats']
            if 'active_engagements' in data:
                DASHBOARD_DATA['active_engagements'] = data['active_engagements']
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'success': True,
                    'message': 'Dashboard updated',
                    'timestamp': datetime.now().isoformat()
                })
            }
        
        # Handle root path - return dashboard HTML
        elif path == '/' and method == 'GET':
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI-Powered Honeypot Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #2d2d2d; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #4CAF50; }}
        .stat-label {{ color: #ccc; margin-top: 5px; }}
        .section {{ background: #2d2d2d; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .threat {{ background: #3d1a1a; padding: 10px; margin: 5px 0; border-radius: 4px; }}
        .engagement {{ background: #1a3d1a; padding: 10px; margin: 5px 0; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎭 AI-Powered Honeypot System</h1>
            <p>Real-time threat detection and honeypot management</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{len(DASHBOARD_DATA['honeypots'])}</div>
                <div class="stat-label">Active Honeypots</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{DASHBOARD_DATA['attacks']}</div>
                <div class="stat-label">Total Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{DASHBOARD_DATA['engagements']}</div>
                <div class="stat-label">Engagements</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(DASHBOARD_DATA['threats'])}</div>
                <div class="stat-label">Active Threats</div>
            </div>
        </div>
        
        <div class="section">
            <h3>🚨 Recent Threats</h3>
            {chr(10).join([f'<div class="threat">🎯 {t.get("type", "Unknown")} from {t.get("source_ip", "Unknown")} (Confidence: {t.get("confidence", 0):.0%})</div>' for t in DASHBOARD_DATA['threats'][-5:]]) if DASHBOARD_DATA['threats'] else '<p>No threats detected</p>'}
        </div>
        
        <div class="section">
            <h3>🎭 Active Engagements</h3>
            {chr(10).join([f'<div class="engagement">🔗 {e.get("honeypot_type", "Unknown")} honeypot engaging {e.get("attacker_ip", "Unknown")} ({e.get("interactions", 0)} interactions)</div>' for e in DASHBOARD_DATA['active_engagements'][-3:]]) if DASHBOARD_DATA['active_engagements'] else '<p>No active engagements</p>'}
        </div>
        
        <div class="section">
            <h3>🍯 Honeypot Status</h3>
            {chr(10).join([f'<div>• {h.get("type", "Unknown")} honeypot ({h.get("status", "unknown")}) - {h.get("interactions", 0)} interactions</div>' for h in DASHBOARD_DATA['honeypots'][-10:]]) if DASHBOARD_DATA['honeypots'] else '<p>No honeypots deployed</p>'}
        </div>
        
        <div style="text-align: center; margin-top: 30px; color: #666;">
            <p>Last updated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>🔄 Auto-refresh every 30 seconds</p>
        </div>
    </div>
    
    <script>
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>"""
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/html',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': html
            }
        
        # Handle other API endpoints
        elif path.startswith('/api/'):
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'status': 'ok',
                    'data': DASHBOARD_DATA,
                    'timestamp': datetime.now().isoformat()
                })
            }
        
        # Default 404
        else:
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Not found'})
            }
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Internal server error', 'details': str(e)})
        }