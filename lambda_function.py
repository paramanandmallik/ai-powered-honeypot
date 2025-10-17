import json
import random
from datetime import datetime, timedelta

def lambda_handler(event, context):
    """
    Comprehensive AI-Powered Honeypot Dashboard with full functionality
    """
    
    try:
        # Get request details
        method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        
        print(f"Processing {method} request to {path}")
        
        # Handle API endpoints
        if path == '/api/status' and method == 'GET':
            return serve_status_api()
        elif path == '/api/threats' and method == 'GET':
            return serve_threats_api()
        elif path == '/api/engagements' and method == 'GET':
            return serve_engagements_api()
        elif path == '/api/intelligence' and method == 'GET':
            return serve_intelligence_api()
        elif path == '/api/detailed-intelligence' and method == 'GET':
            return serve_detailed_intelligence_api()
        
        # Handle POST requests for data updates
        elif method == 'POST':
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
        
        # Serve comprehensive dashboard HTML for GET requests
        dashboard_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Powered Honeypot System Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0,0,0,0.2);
            padding: 1rem 2rem;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 300;
        }
        
        .subtitle {
            color: rgba(255,255,255,0.8);
            margin-top: 0.5rem;
        }
        
        .container {
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card h3 {
            margin-bottom: 1rem;
            color: #fff;
            font-size: 1.2rem;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-healthy { background: #4CAF50; }
        .status-warning { background: #FF9800; }
        .status-critical { background: #F44336; }
        
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .metric:last-child {
            border-bottom: none;
        }
        
        .metric-value {
            font-weight: bold;
            font-size: 1.1rem;
        }
        
        .threat-item, .engagement-item {
            background: rgba(0,0,0,0.2);
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 8px;
            border-left: 4px solid #FF5722;
        }
        
        .engagement-item {
            border-left-color: #2196F3;
        }
        
        .intelligence-item {
            background: rgba(0,0,0,0.2);
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
        }
        
        .timestamp {
            color: rgba(255,255,255,0.7);
            font-size: 0.9rem;
        }
        
        .confidence-bar {
            background: rgba(255,255,255,0.2);
            height: 6px;
            border-radius: 3px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #FF5722, #4CAF50);
            transition: width 0.3s ease;
        }
        
        .refresh-btn {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: #4CAF50;
            color: white;
            border: none;
            padding: 1rem;
            border-radius: 50%;
            cursor: pointer;
            font-size: 1.2rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            transition: all 0.3s ease;
        }
        
        .refresh-btn:hover {
            background: #45a049;
            transform: scale(1.1);
        }
        
        .auto-refresh {
            color: rgba(255,255,255,0.7);
            font-size: 0.9rem;
            margin-top: 1rem;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .loading {
            animation: pulse 1.5s infinite;
        }
        
        .architecture-diagram {
            background: rgba(0,0,0,0.3);
            padding: 2rem;
            border-radius: 12px;
            margin: 2rem 0;
            text-align: center;
        }
        
        .architecture-diagram h3 {
            margin-bottom: 1.5rem;
            color: #4CAF50;
        }
        
        .diagram-flow {
            display: flex;
            justify-content: center;
            align-items: center;
            flex-wrap: wrap;
            gap: 1.5rem;
            margin: 1rem 0;
        }
        
        .diagram-node {
            background: rgba(76, 175, 80, 0.2);
            padding: 1.5rem 1rem;
            border-radius: 12px;
            border: 2px solid #4CAF50;
            min-width: 140px;
            text-align: center;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }
        
        .diagram-node:hover {
            transform: scale(1.05);
        }
        
        .diagram-node div:first-child {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .diagram-node div:last-child {
            font-size: 0.9rem;
            font-weight: bold;
        }
        
        .diagram-arrow {
            font-size: 2.5rem;
            color: #4CAF50;
            font-weight: bold;
        }
        
        @media (max-width: 768px) {
            .diagram-flow {
                flex-direction: column;
            }
            .diagram-arrow {
                transform: rotate(90deg);
            }
        }
        
        .mitre-technique {
            background: rgba(255,152,0,0.2);
            padding: 0.3rem 0.6rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 0.2rem;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎭 AI-Powered Honeypot System</h1>
        <div class="subtitle">Real-time Threat Detection & Intelligence Dashboard</div>
    </div>
    
    <div class="container">
        <div class="grid">
            <!-- System Status -->
            <div class="card">
                <h3>🚀 System Status</h3>
                <div id="system-status">
                    <div class="metric">
                        <span><span class="status-indicator status-healthy"></span>Detection Agent</span>
                        <span class="metric-value">Online</span>
                    </div>
                    <div class="metric">
                        <span><span class="status-indicator status-healthy"></span>Coordinator Agent</span>
                        <span class="metric-value">Online</span>
                    </div>
                    <div class="metric">
                        <span><span class="status-indicator status-healthy"></span>Interaction Agent</span>
                        <span class="metric-value">Online</span>
                    </div>
                    <div class="metric">
                        <span><span class="status-indicator status-healthy"></span>Intelligence Agent</span>
                        <span class="metric-value">Online</span>
                    </div>
                </div>
            </div>
            
            <!-- Live Metrics -->
            <div class="card">
                <h3>📊 Live Metrics</h3>
                <div id="live-metrics">
                    <div class="metric">
                        <span>Threats Detected (24h)</span>
                        <span class="metric-value" id="threats-count">5</span>
                    </div>
                    <div class="metric">
                        <span>Active Engagements</span>
                        <span class="metric-value" id="engagements-count">3</span>
                    </div>
                    <div class="metric">
                        <span>Intelligence Reports</span>
                        <span class="metric-value" id="reports-count">2</span>
                    </div>
                    <div class="metric">
                        <span>System Uptime</span>
                        <span class="metric-value">99.9%</span>
                    </div>
                </div>
            </div>
            
            <!-- Honeypot Status -->
            <div class="card">
                <h3>🎪 Honeypot Infrastructure</h3>
                <div id="honeypot-status">
                    <div class="metric">
                        <span><span class="status-indicator status-healthy"></span>Web Admin Portal</span>
                        <span class="metric-value">Active</span>
                    </div>
                    <div class="metric">
                        <span><span class="status-indicator status-healthy"></span>SSH Honeypot</span>
                        <span class="metric-value">Active</span>
                    </div>
                    <div class="metric">
                        <span><span class="status-indicator status-healthy"></span>Database Honeypot</span>
                        <span class="metric-value">Active</span>
                    </div>
                    <div class="metric">
                        <span><span class="status-indicator status-warning"></span>File Share</span>
                        <span class="metric-value">Standby</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="grid">
            <!-- Recent Threats -->
            <div class="card">
                <h3>🚨 Recent Threats</h3>
                <div id="recent-threats">
                    <div class="threat-item">
                        <div><strong>SQL Injection</strong></div>
                        <div>Source: 192.168.1.100</div>
                        <div>Confidence: 89.2%</div>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: 89%"></div>
                        </div>
                        <div class="timestamp">14:32:15</div>
                    </div>
                    <div class="threat-item">
                        <div><strong>Brute Force</strong></div>
                        <div>Source: 10.0.0.50</div>
                        <div>Confidence: 94.7%</div>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: 95%"></div>
                        </div>
                        <div class="timestamp">14:28:42</div>
                    </div>
                </div>
            </div>
            
            <!-- Active Engagements -->
            <div class="card">
                <h3>🎭 Active Engagements</h3>
                <div id="active-engagements">
                    <div class="engagement-item">
                        <div><strong>web_admin</strong> - active</div>
                        <div>Attacker: 192.168.1.100</div>
                        <div>Duration: 145s</div>
                        <div class="timestamp">14:30:22</div>
                    </div>
                    <div class="engagement-item">
                        <div><strong>ssh</strong> - active</div>
                        <div>Attacker: 172.16.0.25</div>
                        <div>Duration: 67s</div>
                        <div class="timestamp">14:31:55</div>
                    </div>
                </div>
            </div>
            
            <!-- Intelligence Reports -->
            <div class="card">
                <h3>🧠 Latest Intelligence</h3>
                <div id="intelligence-reports">
                    <div class="intelligence-item">
                        <div><strong>Multi-Vector Web Attack Campaign</strong></div>
                        <div>MITRE: <span class="mitre-technique">T1190</span> <span class="mitre-technique">T1059</span></div>
                        <div>IOCs: 8</div>
                        <div class="timestamp">14:25:30</div>
                    </div>
                    <div class="intelligence-item">
                        <div><strong>SSH Brute Force Campaign</strong></div>
                        <div>MITRE: <span class="mitre-technique">T1110</span> <span class="mitre-technique">T1021</span></div>
                        <div>IOCs: 5</div>
                        <div class="timestamp">14:20:15</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Architecture Overview -->
        <div class="architecture-diagram">
            <h3>🏗️ System Architecture Overview</h3>
            <div style="text-align: center; margin: 2rem 0;">
                <img src="https://d3nswgo2anpzyz.cloudfront.net/architecture-diagram.png" 
                     alt="AI Honeypot System Architecture" 
                     style="max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);"
                     onerror="this.style.display='none'; document.getElementById('fallback-diagram').style.display='block';">
            </div>
            <!-- Fallback diagram if image fails to load -->
            <div id="fallback-diagram" style="display: none;">
                <div class="diagram-flow">
                    <div class="diagram-node">
                        <div>🌐</div>
                        <div>Internet</div>
                    </div>
                    <div class="diagram-arrow">→</div>
                    <div class="diagram-node">
                        <div>🛡️</div>
                        <div>Detection Agent</div>
                    </div>
                    <div class="diagram-arrow">→</div>
                    <div class="diagram-node">
                        <div>🎪</div>
                        <div>Honeypots</div>
                    </div>
                    <div class="diagram-arrow">→</div>
                    <div class="diagram-node">
                        <div>🤖</div>
                        <div>AI Agents</div>
                    </div>
                    <div class="diagram-arrow">→</div>
                    <div class="diagram-node">
                        <div>🧠</div>
                        <div>Intelligence</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="auto-refresh">
            🔄 Auto-refreshing every 5 seconds | Last updated: <span id="last-update">Never</span>
        </div>
    </div>
    
    <button class="refresh-btn" onclick="refreshData()" title="Refresh Data">🔄</button>
    
    <script>
        let refreshInterval;
        
        function updateTimestamp() {
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
        }
        
        async function fetchData(endpoint) {
            try {
                const response = await fetch(endpoint);
                return await response.json();
            } catch (error) {
                console.error('Error fetching data:', error);
                return null;
            }
        }
        
        async function refreshData() {
            console.log('Refreshing dashboard data...');
            
            try {
                // Update threats
                const threats = await fetchData('/prod/api/threats');
                if (threats && threats.length > 0) {
                    document.getElementById('threats-count').textContent = threats.length;
                    
                    const threatsHtml = threats.map(threat => `
                        <div class="threat-item">
                            <div><strong>${threat.type}</strong></div>
                            <div>Source: ${threat.source_ip}</div>
                            <div>Confidence: ${(threat.confidence * 100).toFixed(1)}%</div>
                            <div class="confidence-bar">
                                <div class="confidence-fill" style="width: ${threat.confidence * 100}%"></div>
                            </div>
                            <div class="timestamp">${threat.timestamp}</div>
                        </div>
                    `).join('');
                    
                    document.getElementById('recent-threats').innerHTML = threatsHtml;
                }
                
                // Update engagements
                const engagements = await fetchData('/prod/api/engagements');
                if (engagements && engagements.length > 0) {
                    document.getElementById('engagements-count').textContent = engagements.length;
                    
                    const engagementsHtml = engagements.map(engagement => `
                        <div class="engagement-item">
                            <div><strong>${engagement.honeypot_type}</strong> - ${engagement.status}</div>
                            <div>Attacker: ${engagement.attacker_ip}</div>
                            <div>Duration: ${engagement.duration}s</div>
                            <div class="timestamp">${engagement.start_time}</div>
                        </div>
                    `).join('');
                    
                    document.getElementById('active-engagements').innerHTML = engagementsHtml;
                }
                
                // Update intelligence
                const intelligence = await fetchData('/prod/api/intelligence');
                if (intelligence && intelligence.length > 0) {
                    document.getElementById('reports-count').textContent = intelligence.length;
                    
                    const intelligenceHtml = intelligence.map(report => `
                        <div class="intelligence-item">
                            <div><strong>${report.attack_type}</strong></div>
                            <div>MITRE: ${report.mitre_techniques.map(t => `<span class="mitre-technique">${t}</span>`).join(' ')}</div>
                            <div>IOCs: ${report.iocs_count}</div>
                            <div class="timestamp">${report.generated_at}</div>
                        </div>
                    `).join('');
                    
                    document.getElementById('intelligence-reports').innerHTML = intelligenceHtml;
                }
                
                updateTimestamp();
                console.log('Dashboard data refreshed successfully');
                
            } catch (error) {
                console.error('Error refreshing dashboard data:', error);
            }
        }
        
        function startAutoRefresh() {
            refreshData(); // Initial load
            refreshInterval = setInterval(refreshData, 5000); // Refresh every 5 seconds
        }
        
        // Start auto-refresh when page loads
        window.addEventListener('load', startAutoRefresh);
        
        // Handle page visibility changes
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                clearInterval(refreshInterval);
            } else {
                startAutoRefresh();
            }
        });
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

def serve_status_api():
    """Serve system status API"""
    status = {
        "timestamp": datetime.now().isoformat(),
        "system_status": "healthy",
        "agents": {
            "detection_agent": {"status": "online", "instances": 2},
            "coordinator_agent": {"status": "online", "instances": 1},
            "interaction_agent": {"status": "online", "instances": 3},
            "intelligence_agent": {"status": "online", "instances": 2}
        },
        "honeypots": {
            "web_admin": {"status": "active", "engagements": random.randint(0, 3)},
            "ssh": {"status": "active", "engagements": random.randint(0, 2)},
            "database": {"status": "active", "engagements": random.randint(0, 1)},
            "file_share": {"status": "standby", "engagements": 0}
        }
    }
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(status)
    }

def serve_threats_api():
    """Serve recent threats API"""
    threats = []
    
    threat_types = ["SQL Injection", "XSS Attack", "Brute Force", "Directory Traversal", "Command Injection"]
    source_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10"]
    
    # Generate some recent threats
    for i in range(random.randint(3, 8)):
        threat_time = datetime.now() - timedelta(minutes=random.randint(1, 120))
        threats.append({
            "id": f"threat_{i+1}",
            "type": random.choice(threat_types),
            "source_ip": random.choice(source_ips),
            "confidence": random.uniform(0.7, 0.95),
            "timestamp": threat_time.strftime("%H:%M:%S"),
            "status": "detected"
        })
    
    # Sort by most recent first
    threats.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(threats[:5])  # Return last 5 threats
    }

def serve_engagements_api():
    """Serve active engagements API"""
    engagements = []
    
    honeypot_types = ["web_admin", "ssh", "database"]
    attacker_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25"]
    
    # Generate some active engagements
    for i in range(random.randint(1, 4)):
        start_time = datetime.now() - timedelta(minutes=random.randint(1, 30))
        engagements.append({
            "id": f"engagement_{i+1}",
            "honeypot_type": random.choice(honeypot_types),
            "attacker_ip": random.choice(attacker_ips),
            "status": "active",
            "start_time": start_time.strftime("%H:%M:%S"),
            "duration": random.randint(30, 300),
            "interactions": random.randint(5, 25)
        })
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(engagements)
    }

def serve_intelligence_api():
    """Serve intelligence reports API"""
    reports = []
    
    attack_types = [
        "Multi-Vector Web Attack Campaign",
        "SSH Brute Force Campaign", 
        "Database Exploitation Attempt",
        "Reconnaissance and Enumeration"
    ]
    
    mitre_techniques = [
        ["T1190", "T1059"],
        ["T1110", "T1021"],
        ["T1190", "T1083"],
        ["T1046", "T1018"]
    ]
    
    # Generate some intelligence reports
    for i in range(random.randint(2, 5)):
        generated_time = datetime.now() - timedelta(hours=random.randint(1, 24))
        attack_type = random.choice(attack_types)
        techniques = random.choice(mitre_techniques)
        
        reports.append({
            "id": f"report_{i+1}",
            "attack_type": attack_type,
            "mitre_techniques": techniques,
            "iocs_count": random.randint(3, 12),
            "confidence": random.uniform(0.8, 0.95),
            "generated_at": generated_time.strftime("%H:%M:%S"),
            "threat_level": "high" if random.random() > 0.5 else "medium"
        })
    
    # Sort by most recent first
    reports.sort(key=lambda x: x["generated_at"], reverse=True)
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(reports[:3])  # Return last 3 reports
    }

def serve_detailed_intelligence_api():
    """Serve detailed intelligence reports API"""
    
    detailed_reports = [
        {
            "id": "intel_001",
            "campaign_name": "Multi-Vector Web Application Attack Campaign",
            "confidence": 0.89,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mitre_techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
                {"id": "T1059.007", "name": "JavaScript"},
                {"id": "T1110.001", "name": "Password Guessing"},
                {"id": "T1083", "name": "File and Directory Discovery"}
            ],
            "iocs": [
                {"type": "IP Address", "value": "192.168.1.100"},
                {"type": "SQL Payload", "value": "' OR '1'='1 --"},
                {"type": "XSS Payload", "value": "<script>alert('XSS')</script>"},
                {"type": "Credential", "value": "admin:password123"},
                {"type": "Path Traversal", "value": "../../../etc/passwd"}
            ],
            "threat_actor": {
                "sophistication": "Low-Medium",
                "motivation": "Opportunistic/Financial",
                "tools": "Automated scanners, Manual testing",
                "attribution": "Unknown (likely script kiddie)"
            },
            "timeline": [
                {"time": "14:30:15", "description": "Initial reconnaissance - port scanning detected"},
                {"time": "14:31:22", "description": "SQL injection attempts on login form"},
                {"time": "14:32:45", "description": "XSS payload injection in search parameter"},
                {"time": "14:34:12", "description": "Brute force attack on admin credentials"},
                {"time": "14:35:30", "description": "Directory traversal attempts"},
                {"time": "14:36:45", "description": "Session terminated - intelligence extracted"}
            ],
            "summary": "Coordinated multi-vector attack targeting web application vulnerabilities. Attacker demonstrated knowledge of common web attack techniques but used basic payloads suggesting automated tooling or low skill level. No advanced persistence mechanisms observed."
        }
    ]
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(detailed_reports)
    }