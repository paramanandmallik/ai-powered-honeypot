#!/usr/bin/env python3
"""
AI-Powered Honeypot System Dashboard
Real-time monitoring and management interface
"""

import json
import time
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import random

class HoneypotDashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/api/status':
            self.serve_status_api()
        elif self.path == '/api/threats':
            self.serve_threats_api()
        elif self.path == '/api/engagements':
            self.serve_engagements_api()
        elif self.path == '/api/intelligence':
            self.serve_intelligence_api()
        elif self.path == '/api/detailed-intelligence':
            self.serve_detailed_intelligence_api()
        elif self.path.startswith('/static/'):
            self.serve_static()
        else:
            self.send_error(404)
    
    def serve_dashboard(self):
        """Serve the main dashboard HTML"""
        html = """
<!DOCTYPE html>
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
                        <span class="metric-value" id="threats-count">0</span>
                    </div>
                    <div class="metric">
                        <span>Active Engagements</span>
                        <span class="metric-value" id="engagements-count">0</span>
                    </div>
                    <div class="metric">
                        <span>Intelligence Reports</span>
                        <span class="metric-value" id="reports-count">0</span>
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
                    <div class="loading">Loading threat data...</div>
                </div>
            </div>
            
            <!-- Active Engagements -->
            <div class="card">
                <h3>🎭 Active Engagements</h3>
                <div id="active-engagements">
                    <div class="loading">Loading engagement data...</div>
                </div>
            </div>
            
            <!-- Intelligence Reports -->
            <div class="card">
                <h3>🧠 Latest Intelligence</h3>
                <div id="intelligence-reports">
                    <div class="loading">Loading intelligence data...</div>
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
            // Update threats
            const threats = await fetchData('/api/threats');
            if (threats) {
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
                
                document.getElementById('recent-threats').innerHTML = threatsHtml || '<div>No recent threats</div>';
            }
            
            // Update engagements
            const engagements = await fetchData('/api/engagements');
            if (engagements) {
                document.getElementById('engagements-count').textContent = engagements.length;
                
                const engagementsHtml = engagements.map(engagement => `
                    <div class="engagement-item">
                        <div><strong>${engagement.honeypot_type}</strong> - ${engagement.status}</div>
                        <div>Attacker: ${engagement.attacker_ip}</div>
                        <div>Duration: ${engagement.duration}s</div>
                        <div class="timestamp">${engagement.start_time}</div>
                    </div>
                `).join('');
                
                document.getElementById('active-engagements').innerHTML = engagementsHtml || '<div>No active engagements</div>';
            }
            
            // Update intelligence
            const intelligence = await fetchData('/api/intelligence');
            if (intelligence) {
                document.getElementById('reports-count').textContent = intelligence.length;
                
                const intelligenceHtml = intelligence.map(report => `
                    <div class="intelligence-item">
                        <div><strong>${report.attack_type}</strong></div>
                        <div>MITRE: ${report.mitre_techniques.join(', ')}</div>
                        <div>IOCs: ${report.iocs_count}</div>
                        <div class="timestamp">${report.generated_at}</div>
                    </div>
                `).join('');
                
                document.getElementById('intelligence-reports').innerHTML = intelligenceHtml || '<div>No intelligence reports</div>';
            }
            
            updateTimestamp();
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
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_status_api(self):
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
        
        self.send_json_response(status)
    
    def serve_threats_api(self):
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
        
        self.send_json_response(threats[:5])  # Return last 5 threats
    
    def serve_engagements_api(self):
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
        
        self.send_json_response(engagements)
    
    def serve_intelligence_api(self):
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
        
        self.send_json_response(reports[:3])  # Return last 3 reports
    
    def serve_detailed_intelligence_api(self):
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
            },
            {
                "id": "intel_002", 
                "campaign_name": "SSH Infrastructure Reconnaissance",
                "confidence": 0.82,
                "generated_at": (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
                "mitre_techniques": [
                    {"id": "T1110.001", "name": "Password Guessing"},
                    {"id": "T1021.004", "name": "SSH"},
                    {"id": "T1057", "name": "Process Discovery"},
                    {"id": "T1018", "name": "Remote System Discovery"}
                ],
                "iocs": [
                    {"type": "IP Address", "value": "10.0.0.50"},
                    {"type": "Username", "value": "root"},
                    {"type": "Username", "value": "admin"},
                    {"type": "Command", "value": "whoami"},
                    {"type": "Command", "value": "cat /etc/passwd"}
                ],
                "threat_actor": {
                    "sophistication": "Medium",
                    "motivation": "Reconnaissance/Lateral Movement",
                    "tools": "SSH clients, Basic Linux commands",
                    "attribution": "Possible APT reconnaissance phase"
                },
                "timeline": [
                    {"time": "12:15:30", "description": "SSH connection attempts from external IP"},
                    {"time": "12:16:45", "description": "Credential brute force - common passwords"},
                    {"time": "12:18:12", "description": "Successful login with weak credentials"},
                    {"time": "12:18:30", "description": "System enumeration commands executed"},
                    {"time": "12:19:45", "description": "Network discovery attempts"},
                    {"time": "12:21:00", "description": "Connection terminated"}
                ],
                "summary": "Systematic SSH-based reconnaissance indicating potential APT activity. Attacker showed methodical approach to system enumeration after gaining access. Behavior suggests intelligence gathering for future lateral movement operations."
            }
        ]
        
        self.send_json_response(detailed_reports)
    
    def serve_static(self):
        """Serve static files (CSS, JS, etc.)"""
        self.send_error(404)  # For now, no static files
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def log_message(self, format, *args):
        """Override to reduce log noise"""
        pass

def run_dashboard(port=8090):
    """Run the dashboard server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, HoneypotDashboardHandler)
    
    print(f"🎭 AI-Powered Honeypot Dashboard Starting...")
    print(f"🌐 Dashboard URL: http://localhost:{port}")
    print(f"📊 Real-time monitoring and intelligence dashboard")
    print(f"🔄 Auto-refreshing every 5 seconds")
    print(f"⏹️  Press Ctrl+C to stop")
    print()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
        httpd.shutdown()

if __name__ == "__main__":
    run_dashboard()